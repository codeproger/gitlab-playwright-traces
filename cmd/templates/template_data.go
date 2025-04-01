package templates

// FileListData represents the data structure for the file list template
type FileListData struct {
	Files []FileData
}

// FileData represents a single file in the list
type FileData struct {
	Name          string
	Path          string
	Size          string
	DownloadURL   string
	PlaywrightURL string
}
