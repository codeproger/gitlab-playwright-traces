package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"gitlab-artifacts-retriever/app/gitlab-artifacts-retriever/templates"
	"html/template"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Структуры для нового расширенного формата
type Commit struct {
	ID          string `json:"id"`
	ShortID     string `json:"short_id"`
	Title       string `json:"title"`
	AuthorName  string `json:"author_name"`
	AuthorEmail string `json:"author_email"`
	WebURL      string `json:"web_url"`
}

type Pipeline struct {
	ID     int    `json:"id"`
	Status string `json:"status"`
	Ref    string `json:"ref"`
	SHA    string `json:"sha"`
	WebURL string `json:"web_url"`
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	WebURL   string `json:"web_url"`
}

type ArtifactFile struct {
	Filename string `json:"filename"`
	Size     int    `json:"size"`
}

type ExtendedArtifact struct {
	FileType   string `json:"file_type"`
	Size       int    `json:"size"`
	Filename   string `json:"filename"`
	FileFormat string `json:"file_format"`
}

type JobDetails struct {
	ID            int                `json:"id"`
	Status        string             `json:"status"`
	Stage         string             `json:"stage"`
	Name          string             `json:"name"`
	Ref           string             `json:"ref"`
	Tag           bool               `json:"tag"`
	User          User               `json:"user"`
	Commit        Commit             `json:"commit"`
	Pipeline      Pipeline           `json:"pipeline"`
	WebURL        string             `json:"web_url"`
	ArtifactsFile ArtifactFile       `json:"artifacts_file"`
	Artifacts     []ExtendedArtifact `json:"artifacts"`
	FailureReason string             `json:"failure_reason"`
	ProjectID     int                `json:"project_id"`
}

// FileInfo holds information about a file in the artifacts.zip
type FileInfo struct {
	Size           uint64
	CompressedSize uint64
	ModTime        time.Time
}

// FileOutput represents the structure for output in JSON
type FileOutput struct {
	Path           string    `json:"path"`
	Size           uint64    `json:"size"`
	CompressedSize uint64    `json:"compressed_size"`
	ModTime        time.Time `json:"mod_time"`
	URL            string    `json:"url"`
	DownloadURL    string    `json:"download_url"`
	PlaywrightURL  string    `json:"playwright_url"`
}

// LoggingTransport is a custom http.RoundTripper for logging requests/responses
type LoggingTransport struct {
	Transport http.RoundTripper
	LogLevel  int // 0=minimal, 1=headers, 2=full content
}

func (t *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Log request
	fmt.Printf("--- REQUEST %s %s ---\n", req.Method, req.URL)
	if t.LogLevel >= 1 {
		requestDump, _ := httputil.DumpRequestOut(req, t.LogLevel >= 2)
		fmt.Printf("%s\n", requestDump)
	}

	// Execute request
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return resp, err
	}

	// Log response
	fmt.Printf("--- RESPONSE Status: %d ---\n", resp.StatusCode)

	// Log response in error cases or if higher log level
	if resp.StatusCode >= 400 || t.LogLevel >= 1 {
		responseDump, _ := httputil.DumpResponse(resp, t.LogLevel >= 2)
		// Create a copy of the body for logging
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// Restore the body for further use
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// For error responses, print the full content
		if resp.StatusCode >= 400 {
			fmt.Printf("Error response body: %s\n", string(bodyBytes))
		} else if t.LogLevel >= 1 {
			fmt.Printf("%s\n", responseDump)
		}
	}

	return resp, err
}

// Add these new types after the existing type definitions
type FileListResponse struct {
	Files []FileOutput `json:"files"`
}

type HealthResponse struct {
	Status string `json:"status"`
}

// Add this new type for path parameters
type RouteParams struct {
	ProjectID  string
	PipelineID string
}

// Add this helper function to parse URL path parameters
func getRouteParams(path string) (*RouteParams, error) {
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid path format, expected /view/{projectId}/{pipelineId}")
	}

	return &RouteParams{
		ProjectID:  parts[2],
		PipelineID: parts[3],
	}, nil
}

// CacheEntry represents a cached file list with metadata
type CacheEntry struct {
	Files      []string
	FileInfo   map[string]FileInfo
	Expiration time.Time
}

// FileCache holds cached file lists
type FileCache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
}

// NewFileCache creates a new file cache
func NewFileCache() *FileCache {
	return &FileCache{
		entries: make(map[string]*CacheEntry),
	}
}

// Get retrieves a cached file list if it exists and is not expired
func (c *FileCache) Get(projectID, jobID int) ([]string, map[string]FileInfo, bool) {
	key := fmt.Sprintf("%d:%d", projectID, jobID)
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, nil, false
	}

	if time.Now().After(entry.Expiration) {
		// Need to upgrade to write lock to delete the entry
		c.mu.RUnlock()
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, nil, false
	}

	// Check if there are any trace files in the cached data
	hasTraces := false
	for _, file := range entry.Files {
		if strings.HasPrefix(file, "output/trace") && strings.HasSuffix(file, ".zip") {
			hasTraces = true
			break
		}
	}
	if !hasTraces {
		return nil, nil, false
	}

	return entry.Files, entry.FileInfo, true
}

// Set stores a file list in the cache
func (c *FileCache) Set(projectID, jobID int, files []string, fileInfo map[string]FileInfo) {
	key := fmt.Sprintf("%d:%d", projectID, jobID)
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &CacheEntry{
		Files:      files,
		FileInfo:   fileInfo,
		Expiration: time.Now().Add(5 * time.Minute), // Cache TTL of 5 minutes
	}
}

// Global cache instance
var fileCache = NewFileCache()

// Add new type for progress updates
type ProgressUpdate struct {
	Progress float64 `json:"progress"`
	Status   string  `json:"status"`
}

// Add new function to load templates
func loadTemplates() (*template.Template, error) {
	tmpl := template.New("")

	// Get the directory of the current source file
	_, filename, _, _ := runtime.Caller(0)
	templateDir := filepath.Join(filepath.Dir(filename), "templates")

	// Load all template files
	err := filepath.Walk(templateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".html") {
			content, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}
			_, err = tmpl.Parse(string(content))
			return err
		}
		return nil
	})

	return tmpl, err
}

func main() {
	var gitlabToken string
	var gitlabURL string
	var logLevel int
	var httpPort int
	// Add this to your environment configuration at the top of main()
	var playwrightURL string

	// Parse command-line arguments
	flag.StringVar(&gitlabToken, "token", "", "GitLab API token")
	flag.StringVar(&gitlabURL, "url", "https://gitlab.com", "GitLab instance URL")
	flag.IntVar(&logLevel, "log", 0, "Log level (0=minimal, 1=headers, 2=full)")
	flag.IntVar(&httpPort, "http-port", 8080, "HTTP server port")
	flag.StringVar(&playwrightURL, "playwright-url", "http://localhost:8081", "Playwright trace viewer URL")
	flag.Parse()

	// Check for required parameters
	if gitlabToken == "" {
		// Try to get token from environment variable
		gitlabToken = os.Getenv("GITLAB_TOKEN")
		if gitlabToken == "" {
			fmt.Println("Error: GitLab API token is required (use --token flag or GITLAB_TOKEN environment variable)")
			flag.Usage()
			os.Exit(1)
		}
	}

	// Create HTTP client with logging
	client := &http.Client{
		Transport: &LoggingTransport{
			Transport: http.DefaultTransport,
			LogLevel:  logLevel,
		},
		Timeout: 30 * time.Second,
	}

	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a channel to receive shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Create error channel for server
	errChan := make(chan error, 1)

	// Create server
	mux, err := setupRoutes(client, gitlabURL, gitlabToken, playwrightURL)
	if err != nil {
		fmt.Printf("Error setting up routes: %v\n", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", httpPort),
		Handler: mux,
	}

	// Start HTTP server in a goroutine
	go func() {
		fmt.Printf("Starting HTTP server on port %d...\n", httpPort)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for signals in a loop
	for {
		select {
		case <-ctx.Done():
			// Context was cancelled, clean up and exit
			fmt.Println("Context cancelled, shutting down...")
			server.Shutdown(context.Background())
			return

		case <-sigChan:
			fmt.Println("\nShutdown signal received...")
			// Continue running unless it's a second signal
			signal.Reset(os.Interrupt, syscall.SIGTERM)
			fmt.Println("Send signal again to force stop")

			// Set up a new signal handler for force stop
			go func() {
				<-sigChan
				fmt.Println("\nForce stopping server...")
				server.Close()
				cancel()
			}()

		case err := <-errChan:
			if err != nil {
				fmt.Printf("Server error: %v\n", err)
				server.Close()
				cancel()
				os.Exit(1)
			}
		}
	}
}

// Update setupRoutes to use templates
func setupRoutes(client *http.Client, gitlabURL, token, playwrightURL string) (*http.ServeMux, error) {
	mux := http.NewServeMux()

	// Load templates
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, fmt.Errorf("error loading templates: %v", err)
	}

	// Serve traces page
	mux.HandleFunc("/traces", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Get the directory of the current source file
			_, filename, _, _ := runtime.Caller(0)
			templatePath := filepath.Join(filepath.Dir(filename), "templates", "traces.html")

			html, err := ioutil.ReadFile(templatePath)
			if err != nil {
				fmt.Printf("Error reading template: %v\n", err)
				http.Error(w, "Error reading template", http.StatusInternalServerError)
				return
			}

			// Get URL parameters
			projectID := r.URL.Query().Get("projectId")
			pipelineID := r.URL.Query().Get("pipelineId")

			// Replace placeholder values in the HTML
			htmlStr := string(html)
			if projectID != "" {
				htmlStr = strings.ReplaceAll(htmlStr, `value=""`, fmt.Sprintf(`value="%s"`, projectID))
			}
			if pipelineID != "" {
				htmlStr = strings.ReplaceAll(htmlStr, `value=""`, fmt.Sprintf(`value="%s"`, pipelineID))
			}

			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(htmlStr))
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	// Setup view endpoint
	mux.HandleFunc("/view/", func(w http.ResponseWriter, r *http.Request) {
		// Only allow GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse route parameters
		params, err := getRouteParams(r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Convert string IDs to integers
		projectID, err := strconv.Atoi(params.ProjectID)
		if err != nil {
			http.Error(w, "Invalid project ID", http.StatusBadRequest)
			return
		}

		jobID, err := strconv.Atoi(params.PipelineID)
		if err != nil {
			http.Error(w, "Invalid pipeline ID", http.StatusBadRequest)
			return
		}

		// Get artifacts
		artifactFiles, fileInfoMap, err := downloadAndListArtifacts(client, gitlabURL, token, projectID, jobID, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error getting artifacts: %v", err), http.StatusInternalServerError)
			return
		}

		// Filter and sort files
		var filteredFiles []string
		for _, file := range artifactFiles {
			if strings.HasPrefix(file, "output/trace") && strings.HasSuffix(file, ".zip") {
				filteredFiles = append(filteredFiles, file)
			}
		}
		sort.Strings(filteredFiles)

		// Prepare output
		var output []FileOutput
		for _, file := range filteredFiles {
			info := fileInfoMap[file]
			fileURL := getFileArtifactURL(gitlabURL, projectID, jobID, file)

			// Get the current server's host from the request
			host := r.Host
			if host == "" {
				host = "localhost:8080" // fallback if host is not available
			}

			// Construct full URLs using the current server's host
			downloadURL := fmt.Sprintf("http://%s/proxy?url=%s", host, url.QueryEscape(fileURL))
			playwrightURL := fmt.Sprintf("http://%s/pw?trace=%s", host, url.QueryEscape(downloadURL))

			output = append(output, FileOutput{
				Path:           file,
				Size:           info.Size,
				CompressedSize: info.CompressedSize,
				ModTime:        info.ModTime,
				URL:            fileURL,
				DownloadURL:    downloadURL,
				PlaywrightURL:  playwrightURL,
			})
		}

		// Send response
		response := FileListResponse{Files: output}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Setup file endpoint
	mux.HandleFunc("/file/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		params, err := getRouteParams(r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		projectID, err := strconv.Atoi(params.ProjectID)
		if err != nil {
			http.Error(w, "Invalid project ID", http.StatusBadRequest)
			return
		}

		jobID, err := strconv.Atoi(params.PipelineID)
		if err != nil {
			http.Error(w, "Invalid pipeline ID", http.StatusBadRequest)
			return
		}

		handleFileDownload(w, r, client, gitlabURL, token, projectID, jobID)
	})

	// Setup health endpoints
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, r *http.Request) {
		response := HealthResponse{Status: "ok"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		// Simple connection test to GitLab API
		req, err := http.NewRequest("GET", gitlabURL+"/api/v4/version", nil)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			response := HealthResponse{Status: fmt.Sprintf("error creating request: %v", err)}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		req.Header.Set("PRIVATE-TOKEN", token)
		resp, err := client.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			response := HealthResponse{Status: fmt.Sprintf("error connecting to GitLab: %v", err)}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			w.WriteHeader(http.StatusServiceUnavailable)
			response := HealthResponse{Status: fmt.Sprintf("GitLab API returned status: %d", resp.StatusCode)}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		response := HealthResponse{Status: "ok"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// Add new playwright redirect endpoint
	mux.HandleFunc("/pw", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get trace parameter
		traceURL := r.URL.Query().Get("trace")
		if traceURL == "" {
			http.Error(w, "trace parameter is required", http.StatusBadRequest)
			return
		}

		// Construct the playwright viewer URL
		viewerURL := fmt.Sprintf("%s/?trace=%s", playwrightURL, url.QueryEscape(traceURL))

		// Redirect to the playwright viewer
		http.Redirect(w, r, viewerURL, http.StatusTemporaryRedirect)
	})

	// Add proxy endpoint for CORS-enabled file access
	mux.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
		// Handle OPTIONS request for CORS preflight
		if r.Method == http.MethodOptions {
			// Set CORS headers
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusOK)
			return
		}

		// Only allow GET requests
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get the GitLab file URL from query parameter
		fileURL := r.URL.Query().Get("url")
		if fileURL == "" {
			http.Error(w, "url parameter is required", http.StatusBadRequest)
			return
		}

		// Create request to GitLab
		req, err := http.NewRequest("GET", fileURL, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error creating request: %v", err), http.StatusInternalServerError)
			return
		}

		// Forward the GitLab token if present
		if token != "" {
			req.Header.Set("PRIVATE-TOKEN", token)
		}

		// Forward the request to GitLab
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error downloading file: %v", err), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Check response status
		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("GitLab returned status: %d", resp.StatusCode), resp.StatusCode)
			return
		}

		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Copy content type from GitLab response
		if contentType := resp.Header.Get("Content-Type"); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}

		// Extract filename from URL or Content-Disposition header
		filename := ""
		if contentDisposition := resp.Header.Get("Content-Disposition"); contentDisposition != "" {
			// Try to extract filename from Content-Disposition header
			if strings.Contains(contentDisposition, "filename=") {
				filename = strings.Split(contentDisposition, "filename=")[1]
				filename = strings.Trim(filename, "\"")
			}
		}

		// If no filename in Content-Disposition, try to extract from URL
		if filename == "" {
			urlParts := strings.Split(fileURL, "/")
			filename = urlParts[len(urlParts)-1]
		}

		// Set Content-Disposition header with the filename
		if filename != "" {
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
		}

		// Stream the file content
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error streaming file: %v", err), http.StatusInternalServerError)
			return
		}
	})

	// Update the /files/ endpoint to use templates
	mux.HandleFunc("/files/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get parameters from query string
		projectID := r.URL.Query().Get("projectId")
		pipelineID := r.URL.Query().Get("pipelineId")

		if projectID == "" || pipelineID == "" {
			http.Error(w, "projectId and pipelineId are required", http.StatusBadRequest)
			return
		}

		// Convert string IDs to integers
		projectIDInt, err := strconv.Atoi(projectID)
		if err != nil {
			http.Error(w, "Invalid project ID", http.StatusBadRequest)
			return
		}

		jobID, err := strconv.Atoi(pipelineID)
		if err != nil {
			http.Error(w, "Invalid pipeline ID", http.StatusBadRequest)
			return
		}

		// Get artifacts
		artifactFiles, fileInfoMap, err := downloadAndListArtifacts(client, gitlabURL, token, projectIDInt, jobID, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error getting artifacts: %v", err), http.StatusInternalServerError)
			return
		}

		// Filter and sort files
		var filteredFiles []string
		for _, file := range artifactFiles {
			if strings.HasPrefix(file, "output/trace") && strings.HasSuffix(file, ".zip") {
				filteredFiles = append(filteredFiles, file)
			}
		}
		sort.Strings(filteredFiles)

		// Prepare template data
		var templateData templates.FileListData
		for _, file := range filteredFiles {
			info := fileInfoMap[file]
			fileURL := getFileArtifactURL(gitlabURL, projectIDInt, jobID, file)

			// Get the current server's host from the request
			host := r.Host
			if host == "" {
				host = "localhost:8080" // fallback if host is not available
			}

			// Construct full URLs using the current server's host
			downloadURL := fmt.Sprintf("http://%s/proxy?url=%s", host, url.QueryEscape(fileURL))
			playwrightURL := fmt.Sprintf("http://%s/pw?trace=%s", host, url.QueryEscape(downloadURL))

			templateData.Files = append(templateData.Files, templates.FileData{
				Name:          filepath.Base(file),
				Path:          file,
				Size:          formatFileSize(info.Size),
				DownloadURL:   downloadURL,
				PlaywrightURL: playwrightURL,
			})
		}

		// Execute template
		w.Header().Set("Content-Type", "text/html")
		if err := tmpl.ExecuteTemplate(w, "file_list", templateData); err != nil {
			http.Error(w, fmt.Sprintf("Error executing template: %v", err), http.StatusInternalServerError)
			return
		}
	})

	// Add progress endpoint
	mux.HandleFunc("/progress", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		// Get project and job IDs from query parameters
		projectID := r.URL.Query().Get("projectId")
		pipelineID := r.URL.Query().Get("pipelineId")

		if projectID == "" || pipelineID == "" {
			fmt.Fprintf(w, "data: %s\n\n", `{"progress": 0, "status": "Missing parameters"}`)
			flusher.Flush()
			return
		}

		// Convert string IDs to integers
		projectIDInt, err := strconv.Atoi(projectID)
		if err != nil {
			fmt.Fprintf(w, "data: %s\n\n", `{"progress": 0, "status": "Invalid project ID"}`)
			flusher.Flush()
			return
		}

		jobID, err := strconv.Atoi(pipelineID)
		if err != nil {
			fmt.Fprintf(w, "data: %s\n\n", `{"progress": 0, "status": "Invalid pipeline ID"}`)
			flusher.Flush()
			return
		}

		// Create a channel for progress updates
		progressChan := make(chan ProgressUpdate, 100)
		defer close(progressChan)

		// Start download in a goroutine
		go func() {
			_, _, err := downloadAndListArtifacts(client, gitlabURL, token, projectIDInt, jobID, progressChan)
			if err != nil {
				progressChan <- ProgressUpdate{Progress: 0, Status: fmt.Sprintf("Error: %v", err)}
				return
			}
		}()

		// Send progress updates to client
		for update := range progressChan {
			data, _ := json.Marshal(update)
			fmt.Fprintf(w, "data: %s\n\n", string(data))
			flusher.Flush()
		}
	})

	return mux, nil
}

// Update startHTTPServer to use the new setup
func startHTTPServer(port int, client *http.Client, gitlabURL, token, playwrightURL string) error {
	mux, err := setupRoutes(client, gitlabURL, token, playwrightURL)
	if err != nil {
		return err
	}
	return http.ListenAndServe(fmt.Sprintf(":%d", port), mux)
}

func getJobExtendedDetails(client *http.Client, gitlabURL, token string, projectID, jobID int) (*JobDetails, error) {
	apiURL := fmt.Sprintf("%s/api/v4/projects/%d/jobs/%d", gitlabURL, projectID, jobID)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jobDetails JobDetails
	if err := json.Unmarshal(body, &jobDetails); err != nil {
		return nil, err
	}

	// Set the ProjectID from the URL
	jobDetails.ProjectID = projectID

	return &jobDetails, nil
}

func printJobDetails(job *JobDetails) {
	fmt.Println("\n=== Job Details ===")
	fmt.Printf("ID: %d\n", job.ID)
	fmt.Printf("Name: %s\n", job.Name)
	fmt.Printf("Status: %s\n", job.Status)
	fmt.Printf("Stage: %s\n", job.Stage)
	fmt.Printf("Ref: %s\n", job.Ref)
	fmt.Printf("Web URL: %s\n", job.WebURL)

	if job.Commit.ID != "" {
		fmt.Println("\n--- Commit Info ---")
		fmt.Printf("Commit: %s (%s)\n", job.Commit.ID, job.Commit.ShortID)
		fmt.Printf("Title: %s\n", job.Commit.Title)
		fmt.Printf("Author: %s <%s>\n", job.Commit.AuthorName, job.Commit.AuthorEmail)
		fmt.Printf("Commit URL: %s\n", job.Commit.WebURL)
	}

	if job.Pipeline.ID != 0 {
		fmt.Println("\n--- Pipeline Info ---")
		fmt.Printf("Pipeline ID: %d\n", job.Pipeline.ID)
		fmt.Printf("Status: %s\n", job.Pipeline.Status)
		fmt.Printf("Ref: %s\n", job.Pipeline.Ref)
		fmt.Printf("Pipeline URL: %s\n", job.Pipeline.WebURL)
	}

	if job.ArtifactsFile.Filename != "" {
		fmt.Println("\n--- Artifacts Archive ---")
		fmt.Printf("Filename: %s\n", job.ArtifactsFile.Filename)
		fmt.Printf("Size: %d bytes\n", job.ArtifactsFile.Size)
	}

	if job.FailureReason != "" {
		fmt.Println("\n--- Failure Info ---")
		fmt.Printf("Failure Reason: %s\n", job.FailureReason)
	}
}

func getArtifactURL(gitlabURL string, projectID, jobID int, artifactPath string) string {
	// Construct the artifact URL based on GitLab conventions
	// The format is: <gitlab_url>/api/v4/projects/<project_id>/jobs/<job_id>/artifacts/<artifact_path>
	encodedPath := url.PathEscape(artifactPath)
	if encodedPath != "" {
		return fmt.Sprintf("%s/api/v4/projects/%d/jobs/%d/artifacts/%s", gitlabURL, projectID, jobID, encodedPath)
	}
	return fmt.Sprintf("%s/api/v4/projects/%d/jobs/%d/artifacts", gitlabURL, projectID, jobID)
}

func getFileArtifactURL(gitlabURL string, projectID, jobID int, filePath string) string {
	// Construct the artifact URL for a file inside the artifacts archive
	encodedPath := url.PathEscape(filePath)
	return fmt.Sprintf("%s/api/v4/projects/%d/jobs/%d/artifacts/%s", gitlabURL, projectID, jobID, encodedPath)
}

// Update downloadAndListArtifacts to accept a progress channel
func downloadAndListArtifacts(client *http.Client, gitlabURL, token string, projectID, jobID int, progressChan chan<- ProgressUpdate) ([]string, map[string]FileInfo, error) {
	// Try to get from cache first
	if files, fileInfo, ok := fileCache.Get(projectID, jobID); ok {
		// Check if there are any trace files in the cached data
		hasTraces := false
		for _, file := range files {
			if strings.HasPrefix(file, "output/trace") && strings.HasSuffix(file, ".zip") {
				hasTraces = true
				break
			}
		}
		if !hasTraces {
			return nil, nil, fmt.Errorf("no trace files found in artifacts")
		}
		if progressChan != nil {
			progressChan <- ProgressUpdate{Progress: 100, Status: "Using cached data"}
		}
		return files, fileInfo, nil
	}

	if progressChan != nil {
		progressChan <- ProgressUpdate{Progress: 0, Status: "Starting download..."}
	}

	// Create a temporary file for storing the zip archive
	tmpFile, err := ioutil.TempFile("", "artifacts-*.zip")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(tmpFile.Name()) // Clean up when we're done
	defer tmpFile.Close()

	// If not in cache, download and process
	apiURL := fmt.Sprintf("%s/api/v4/projects/%d/jobs/%d/artifacts", gitlabURL, projectID, jobID)

	// Set up a longer timeout client for downloading large files
	downloadClient := &http.Client{
		Timeout: 30 * time.Minute, // Much longer timeout for large downloads
		Transport: &http.Transport{
			DisableCompression:  true, // Avoid overhead of decompression for zip files
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	// Determine file size first via HEAD request for progress tracking
	headReq, err := http.NewRequest("HEAD", apiURL, nil)
	if err != nil {
		return nil, nil, err
	}
	headReq.Header.Set("PRIVATE-TOKEN", token)

	headResp, err := downloadClient.Do(headReq)
	if err != nil {
		return nil, nil, err
	}
	headResp.Body.Close()

	fileSize := headResp.ContentLength
	if progressChan != nil {
		progressChan <- ProgressUpdate{Progress: 5, Status: fmt.Sprintf("File size: %.2f MB", float64(fileSize)/(1024*1024))}
	}

	// Download with Range support for potential resuming
	maxRetries := 3
	var totalWritten int64 = 0

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			if progressChan != nil {
				progressChan <- ProgressUpdate{Progress: float64(totalWritten) * 100 / float64(fileSize),
					Status: fmt.Sprintf("Retry attempt %d/%d after timeout...", attempt+1, maxRetries)}
			}
			time.Sleep(2 * time.Second) // Brief pause before retry
		}

		// Create request with Range header if resuming
		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, nil, err
		}

		req.Header.Set("PRIVATE-TOKEN", token)

		// If we have partial content, set Range header
		if totalWritten > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", totalWritten))
			if progressChan != nil {
				progressChan <- ProgressUpdate{Progress: float64(totalWritten) * 100 / float64(fileSize),
					Status: fmt.Sprintf("Resuming download from %.2f MB", float64(totalWritten)/(1024*1024))}
			}
		}

		// Use context with timeout for better control
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		req = req.WithContext(ctx)
		resp, err := downloadClient.Do(req)

		if err != nil {
			if strings.Contains(err.Error(), "context deadline exceeded") ||
				strings.Contains(err.Error(), "timeout") {
				if progressChan != nil {
					progressChan <- ProgressUpdate{Progress: float64(totalWritten) * 100 / float64(fileSize),
						Status: "Download timed out, will retry"}
				}
				continue
			}
			return nil, nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			// Read only part of error response
			bodyBytes := make([]byte, 1024)
			n, _ := resp.Body.Read(bodyBytes)
			return nil, nil, fmt.Errorf("artifacts download failed with status: %d, body: %s",
				resp.StatusCode, string(bodyBytes[:n]))
		}

		// Calculate start position based on status code
		startPos := totalWritten
		if resp.StatusCode == http.StatusOK {
			// Server didn't honor Range request, need to restart
			if totalWritten > 0 {
				tmpFile.Truncate(0)
				tmpFile.Seek(0, 0)
				totalWritten = 0
			}
		}

		// Copy data with progress reporting
		buffer := make([]byte, 1024*1024) // 1MB buffer
		for {
			nr, er := resp.Body.Read(buffer)
			if nr > 0 {
				nw, ew := tmpFile.WriteAt(buffer[0:nr], startPos)
				if nw < 0 || nw != nr {
					return nil, nil, fmt.Errorf("error writing to temp file")
				}
				if ew != nil {
					return nil, nil, ew
				}
				startPos += int64(nw)
				totalWritten += int64(nw)

				// Send progress updates every ~5MB
				if progressChan != nil && totalWritten%5242880 < 1024*1024 {
					progress := float64(totalWritten) * 100 / float64(fileSize)
					progressChan <- ProgressUpdate{
						Progress: progress,
						Status: fmt.Sprintf("Downloading: %.2f%% (%.2f/%.2f MB)",
							progress,
							float64(totalWritten)/(1024*1024),
							float64(fileSize)/(1024*1024)),
					}
				}
			}
			if er != nil {
				if er == io.EOF {
					// Normal end of file
					break
				}
				// Check if it's a timeout
				if strings.Contains(er.Error(), "context deadline exceeded") ||
					strings.Contains(er.Error(), "timeout") {
					if progressChan != nil {
						progressChan <- ProgressUpdate{Progress: float64(totalWritten) * 100 / float64(fileSize),
							Status: fmt.Sprintf("Read timed out after downloading %.2f MB, will resume",
								float64(totalWritten)/(1024*1024))}
					}
					break // Exit this attempt, start the next one with Range header
				}
				return nil, nil, er
			}
		}

		// If we've downloaded everything or almost everything, break out of retry loop
		if totalWritten >= fileSize || (fileSize > 0 && float64(totalWritten)/float64(fileSize) > 0.99) {
			if progressChan != nil {
				progressChan <- ProgressUpdate{Progress: 100,
					Status: fmt.Sprintf("Download complete: %.2f MB", float64(totalWritten)/(1024*1024))}
			}
			break
		}
	}

	// Flush and rewind file
	tmpFile.Sync()
	tmpFile.Seek(0, 0)

	if progressChan != nil {
		progressChan <- ProgressUpdate{Progress: 100, Status: "Processing artifacts ZIP file..."}
	}

	// Process the ZIP file
	zipReader, err := zip.NewReader(tmpFile, totalWritten)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening zip file: %v", err)
	}

	// Extract file list and information
	var fileList []string
	fileInfoMap := make(map[string]FileInfo)
	hasTraces := false

	for _, file := range zipReader.File {
		fileList = append(fileList, file.Name)
		fileInfoMap[file.Name] = FileInfo{
			Size:           file.UncompressedSize64,
			CompressedSize: file.CompressedSize64,
			ModTime:        file.Modified,
		}

		// Check for trace files while iterating
		if strings.HasPrefix(file.Name, "output/trace") && strings.HasSuffix(file.Name, ".zip") {
			hasTraces = true
		}
	}

	if !hasTraces {
		return nil, nil, fmt.Errorf("no trace files found in artifacts")
	}

	// Store in cache
	fileCache.Set(projectID, jobID, fileList, fileInfoMap)

	if progressChan != nil {
		progressChan <- ProgressUpdate{Progress: 100, Status: "Processing complete"}
	}

	return fileList, fileInfoMap, nil
}

func handleFileDownload(w http.ResponseWriter, r *http.Request, client *http.Client, gitlabURL, token string, projectID, jobID int) {
	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "path parameter is required", http.StatusBadRequest)
		return
	}

	// Construct the artifact URL
	artifactURL := getFileArtifactURL(gitlabURL, projectID, jobID, filePath)

	// Create request to GitLab
	req, err := http.NewRequest("GET", artifactURL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating request: %v", err), http.StatusInternalServerError)
		return
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	// Forward the request to GitLab
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error downloading file: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("GitLab returned status: %d", resp.StatusCode), resp.StatusCode)
		return
	}

	// Copy headers from GitLab response
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Stream the file content
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error streaming file: %v", err), http.StatusInternalServerError)
		return
	}
}

// Helper function to format file size
func formatFileSize(bytes uint64) string {
	if bytes == 0 {
		return "0 Bytes"
	}

	const k = 1024
	sizes := []string{"Bytes", "KB", "MB", "GB"}
	i := int(math.Floor(math.Log(float64(bytes)) / math.Log(float64(k))))

	return fmt.Sprintf("%.2f %s", float64(bytes)/math.Pow(float64(k), float64(i)), sizes[i])
}
