package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	// treeAPIMinMajor and treeAPIMinMinor define the minimum GitLab version
	// that supports the /artifacts/tree endpoint.
	treeAPIMinMajor = 18
	treeAPIMinMinor = 8
)

// treeAPIDisabled is set to true if the GitLab version does not support the tree endpoint.
var treeAPIDisabled atomic.Bool

// gitlabVersionResponse represents the response from /api/v4/version.
type gitlabVersionResponse struct {
	Version string `json:"version"`
}

// checkGitLabVersion queries /api/v4/version and disables the Tree API
// if the GitLab version is below 18.8.
func checkGitLabVersion(client *http.Client, gitlabURL, token string) {
	req, err := http.NewRequest("GET", gitlabURL+"/api/v4/version", nil)
	if err != nil {
		log.Printf("Tree API: failed to create version request: %v, disabling\n", err)
		treeAPIDisabled.Store(true)
		return
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Tree API: failed to query GitLab version: %v, disabling\n", err)
		treeAPIDisabled.Store(true)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Tree API: /api/v4/version returned status %d, disabling\n", resp.StatusCode)
		treeAPIDisabled.Store(true)
		return
	}

	var ver gitlabVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&ver); err != nil {
		log.Printf("Tree API: failed to decode version response: %v, disabling\n", err)
		treeAPIDisabled.Store(true)
		return
	}

	major, minor, err := parseGitLabVersion(ver.Version)
	if err != nil {
		log.Printf("Tree API: failed to parse version %q: %v, disabling\n", ver.Version, err)
		treeAPIDisabled.Store(true)
		return
	}

	if major < treeAPIMinMajor || (major == treeAPIMinMajor && minor < treeAPIMinMinor) {
		log.Printf("Tree API: GitLab %s (need >= %d.%d), disabling\n", ver.Version, treeAPIMinMajor, treeAPIMinMinor)
		treeAPIDisabled.Store(true)
	} else {
		treeAPIDisabled.Store(false)
		log.Printf("Tree API: GitLab %s, endpoint available\n", ver.Version)
	}
}

// parseGitLabVersion extracts major and minor from a version string like "16.11.10".
func parseGitLabVersion(version string) (major, minor int, err error) {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("unexpected version format: %s", version)
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major version: %w", err)
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor version: %w", err)
	}
	return major, minor, nil
}

// treeEntry represents a single entry from the GitLab artifacts tree API.
type treeEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"` // "file" or "directory"
	Size uint64 `json:"size"`
	Mode string `json:"mode"`
}

// listArtifactsViaTree lists artifacts using the GitLab /artifacts/tree endpoint (GitLab 18.8+).
func listArtifactsViaTree(client *http.Client, gitlabURL, token string, projectID, jobID int) ([]string, map[string]FileInfo, error) {
	if treeAPIDisabled.Load() {
		return nil, nil, fmt.Errorf("tree: skipped (unavailable on this GitLab instance)")
	}

	var allEntries []treeEntry
	page := 1
	perPage := 100

	for {
		apiURL := fmt.Sprintf("%s/api/v4/projects/%d/jobs/%d/artifacts/tree?recursive=true&per_page=%d&page=%d",
			gitlabURL, projectID, jobID, perPage, page)

		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("tree: error creating request: %w", err)
		}
		req.Header.Set("PRIVATE-TOKEN", token)

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("tree: request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("tree: unexpected status %d", resp.StatusCode)
		}

		var entries []treeEntry
		if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
			return nil, nil, fmt.Errorf("tree: error decoding response: %w", err)
		}

		allEntries = append(allEntries, entries...)

		// Check pagination
		nextPage := resp.Header.Get("X-Next-Page")
		if nextPage == "" {
			break
		}
		page, err = strconv.Atoi(nextPage)
		if err != nil {
			break
		}
	}

	// Build file list and info map
	var fileList []string
	fileInfoMap := make(map[string]FileInfo)

	for _, entry := range allEntries {
		if entry.Type != "file" {
			continue
		}
		fileList = append(fileList, entry.Path)
		fileInfoMap[entry.Path] = FileInfo{
			Size: entry.Size,
		}
	}

	log.Printf("Tree API: found %d files for project %d, job %d\n", len(fileList), projectID, jobID)
	return fileList, fileInfoMap, nil
}
