package github

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// buildZip creates an in-memory zip archive with the given files.
func buildZip(files map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestUnzipLogs_ValidZip(t *testing.T) {
	files := map[string]string{
		"1_Set up job.txt":  "Setting up the job\nStep 1 complete",
		"2_Run action.txt":  "Running action\nAll done",
		"summary.md":        "This is a markdown file", // should be ignored
	}
	data, err := buildZip(files)
	if err != nil {
		t.Fatalf("buildZip: %v", err)
	}

	logFiles, err := unzipLogs(data)
	if err != nil {
		t.Fatalf("unzipLogs returned error: %v", err)
	}

	// Only .txt files should be extracted
	if len(logFiles) != 2 {
		t.Fatalf("expected 2 log files, got %d", len(logFiles))
	}

	// Verify content is preserved
	contentMap := make(map[string]string)
	for _, lf := range logFiles {
		contentMap[lf.Name] = lf.Content
	}
	if contentMap["1_Set up job.txt"] != files["1_Set up job.txt"] {
		t.Errorf("content mismatch for 1_Set up job.txt")
	}
	if contentMap["2_Run action.txt"] != files["2_Run action.txt"] {
		t.Errorf("content mismatch for 2_Run action.txt")
	}
}

func TestUnzipLogs_EmptyZip(t *testing.T) {
	data, err := buildZip(map[string]string{})
	if err != nil {
		t.Fatalf("buildZip: %v", err)
	}

	logFiles, err := unzipLogs(data)
	if err != nil {
		t.Fatalf("unzipLogs returned error for empty zip: %v", err)
	}
	if len(logFiles) != 0 {
		t.Errorf("expected 0 log files, got %d", len(logFiles))
	}
}

func TestUnzipLogs_FileSizeCap(t *testing.T) {
	// Create a file larger than maxFileBytes (1 MB)
	bigContent := strings.Repeat("x", maxFileBytes+1024)
	files := map[string]string{
		"big.txt": bigContent,
	}
	data, err := buildZip(files)
	if err != nil {
		t.Fatalf("buildZip: %v", err)
	}

	logFiles, err := unzipLogs(data)
	if err != nil {
		t.Fatalf("unzipLogs returned error: %v", err)
	}
	if len(logFiles) != 1 {
		t.Fatalf("expected 1 log file, got %d", len(logFiles))
	}

	// Content should be truncated to maxFileBytes
	if len(logFiles[0].Content) > maxFileBytes {
		t.Errorf("expected content capped at %d bytes, got %d bytes", maxFileBytes, len(logFiles[0].Content))
	}
}
