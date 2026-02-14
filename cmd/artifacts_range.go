package main

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	// initialTailSize is the initial number of bytes to prefetch from the end of the archive.
	initialTailSize = 1 << 20 // 1MB

	// eocdSignature is the End of Central Directory signature.
	eocdSignature = 0x06054b50
	// eocd64LocSignature is the ZIP64 End of Central Directory Locator signature.
	eocd64LocSignature = 0x07064b50
	// eocd64Signature is the ZIP64 End of Central Directory signature.
	eocd64Signature = 0x06064b50
)

// httpReaderAt implements io.ReaderAt over HTTP Range requests.
// It prefetches the tail of the file and pre-loads the entire Central Directory,
// so zip.NewReader never needs additional HTTP requests.
type httpReaderAt struct {
	url    string
	client *http.Client
	token  string
	size   int64
	mu     sync.Mutex
	// bufs holds pre-fetched byte ranges sorted by offset.
	// Typically: [central directory gap, tail] or just [tail] if CD fits in tail.
	bufs []segment
}

// segment represents a cached byte range.
type segment struct {
	offset int64
	data   []byte
}

// ReadAt satisfies io.ReaderAt.
func (r *httpReaderAt) ReadAt(p []byte, off int64) (int, error) {
	end := off + int64(len(p))

	r.mu.Lock()
	for _, seg := range r.bufs {
		segEnd := seg.offset + int64(len(seg.data))
		if off >= seg.offset && end <= segEnd {
			n := copy(p, seg.data[off-seg.offset:])
			r.mu.Unlock()
			if n < len(p) {
				return n, io.EOF
			}
			return n, nil
		}
	}
	r.mu.Unlock()

	// Fallback: fetch the missing range (should rarely happen after prefetch)
	log.Printf("Range: unexpected ReadAt miss at offset %d, length %d — fetching from server\n", off, len(p))
	data, err := r.fetchRange(off, end-1)
	if err != nil {
		return 0, err
	}

	r.mu.Lock()
	r.bufs = append(r.bufs, segment{offset: off, data: data})
	r.mu.Unlock()

	n := copy(p, data)
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// fetchRange downloads a byte range from the server.
func (r *httpReaderAt) fetchRange(start, end int64) ([]byte, error) {
	req, err := http.NewRequest("GET", r.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", r.token)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("range fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("range fetch: unexpected status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// findEOCD locates the End of Central Directory record in the buffer and returns
// the CD offset and CD size. Supports both standard and ZIP64 formats.
func findEOCD(buf []byte, bufOffset int64) (cdOffset int64, cdSize int64, err error) {
	// Search backwards for EOCD signature (last 22 bytes minimum, up to 64KB + 22 for comment)
	for i := len(buf) - 22; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:]) == eocdSignature {
			cdSize32 := binary.LittleEndian.Uint32(buf[i+12:])
			cdOffset32 := binary.LittleEndian.Uint32(buf[i+16:])

			// Check for ZIP64
			if cdOffset32 == 0xFFFFFFFF || cdSize32 == 0xFFFFFFFF {
				// Look for ZIP64 EOCD Locator (20 bytes before EOCD)
				if i >= 20 && binary.LittleEndian.Uint32(buf[i-20:]) == eocd64LocSignature {
					eocd64Off := int64(binary.LittleEndian.Uint64(buf[i-20+8:]))
					// Check if ZIP64 EOCD is in our buffer
					relOff := eocd64Off - bufOffset
					if relOff >= 0 && relOff+56 <= int64(len(buf)) {
						if binary.LittleEndian.Uint32(buf[relOff:]) == eocd64Signature {
							cdSize = int64(binary.LittleEndian.Uint64(buf[relOff+40:]))
							cdOffset = int64(binary.LittleEndian.Uint64(buf[relOff+48:]))
							return cdOffset, cdSize, nil
						}
					}
				}
			}

			return int64(cdOffset32), int64(cdSize32), nil
		}
	}
	return 0, 0, fmt.Errorf("EOCD signature not found")
}

// listArtifactsViaRange attempts to list artifacts by downloading only the ZIP Central Directory
// using HTTP Range requests instead of the full archive.
func listArtifactsViaRange(client *http.Client, gitlabURL, token string, projectID, jobID int) ([]string, map[string]FileInfo, error) {
	startTime := time.Now()
	apiURL := fmt.Sprintf("%s/api/v4/projects/%d/jobs/%d/artifacts", gitlabURL, projectID, jobID)

	// Use a dedicated client without the logging transport
	rangeClient := &http.Client{
		Timeout: client.Timeout,
		Transport: &http.Transport{
			DisableCompression:  true,
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	// HEAD request to get file size and check Range support
	headReq, err := http.NewRequest("HEAD", apiURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("range: error creating HEAD request: %w", err)
	}
	headReq.Header.Set("PRIVATE-TOKEN", token)

	headResp, err := rangeClient.Do(headReq)
	if err != nil {
		return nil, nil, fmt.Errorf("range: HEAD request failed: %w", err)
	}
	headResp.Body.Close()

	if headResp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("range: HEAD returned status %d", headResp.StatusCode)
	}

	fileSize := headResp.ContentLength
	if fileSize <= 0 {
		return nil, nil, fmt.Errorf("range: unknown file size (Content-Length: %d)", fileSize)
	}

	acceptRanges := headResp.Header.Get("Accept-Ranges")
	if acceptRanges != "" && acceptRanges != "bytes" {
		return nil, nil, fmt.Errorf("range: server does not support byte ranges (Accept-Ranges: %s)", acceptRanges)
	}

	// Step 1: Fetch the tail of the archive to find EOCD
	tailSize := int64(initialTailSize)
	if fileSize < tailSize {
		tailSize = fileSize
	}
	tailStart := fileSize - tailSize

	log.Printf("Range: fetching last %d bytes of %d byte archive for project %d, job %d\n",
		tailSize, fileSize, projectID, jobID)

	tailBuf, err := fetchHTTPRange(rangeClient, apiURL, token, tailStart, fileSize-1)
	if err != nil {
		return nil, nil, err
	}

	// Step 2: Parse EOCD to find Central Directory location
	cdOffset, cdSize, err := findEOCD(tailBuf, tailStart)
	if err != nil {
		return nil, nil, fmt.Errorf("range: %w", err)
	}

	readerAt := &httpReaderAt{
		url:    apiURL,
		client: rangeClient,
		token:  token,
		size:   fileSize,
		bufs:   []segment{{offset: tailStart, data: tailBuf}},
	}

	// Step 3: If Central Directory extends beyond the tail buffer, prefetch the gap
	if cdOffset < tailStart {
		gapEnd := tailStart - 1
		gapSize := gapEnd - cdOffset + 1
		log.Printf("Range: Central Directory (%d bytes) extends beyond tail, fetching gap [%d-%d] (%d bytes)\n",
			cdSize, cdOffset, gapEnd, gapSize)

		gapBuf, err := fetchHTTPRange(rangeClient, apiURL, token, cdOffset, gapEnd)
		if err != nil {
			return nil, nil, fmt.Errorf("range: failed to fetch CD gap: %w", err)
		}

		readerAt.mu.Lock()
		readerAt.bufs = append([]segment{{offset: cdOffset, data: gapBuf}}, readerAt.bufs...)
		readerAt.mu.Unlock()
	}

	// Step 4: zip.NewReader now has all data it needs in memory
	zipReader, err := zip.NewReader(readerAt, fileSize)
	if err != nil {
		return nil, nil, fmt.Errorf("range: error parsing ZIP Central Directory: %w", err)
	}

	var fileList []string
	fileInfoMap := make(map[string]FileInfo)

	for _, file := range zipReader.File {
		fileList = append(fileList, file.Name)
		fileInfoMap[file.Name] = FileInfo{
			Size:           file.UncompressedSize64,
			CompressedSize: file.CompressedSize64,
			ModTime:        file.Modified,
		}
	}

	totalFetched := tailSize
	if cdOffset < tailStart {
		totalFetched += tailStart - cdOffset
	}

	log.Printf("Range: found %d files (fetched %d bytes instead of %d, saved %.1f%%) in %v for project %d, job %d\n",
		len(fileList), totalFetched, fileSize,
		100-float64(totalFetched)*100/float64(fileSize),
		time.Since(startTime), projectID, jobID)

	return fileList, fileInfoMap, nil
}

// fetchHTTPRange downloads a byte range and validates the response is 206.
func fetchHTTPRange(client *http.Client, url, token string, start, end int64) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("range: error creating request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("range: fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil, fmt.Errorf("range: server returned 200 instead of 206, Range requests not supported")
	}
	if resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("range: unexpected status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
