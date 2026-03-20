package github

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

const (
	maxBodyBytes = 50 * 1024 * 1024 // 50 MB cap on zip download
	maxFileBytes = 1 * 1024 * 1024  // 1 MB cap per log file
)

// LogFile holds the name and text content of a single file extracted from the run logs zip.
type LogFile struct {
	Name    string
	Content string
}

// DownloadRunLogs fetches the workflow run logs zip and extracts all .txt files.
// Returns an empty slice (no error) if logs are unavailable (404).
func (c *Client) DownloadRunLogs(ctx context.Context, owner, repo string, runID int64) ([]LogFile, error) {
	var redirectURL string

	err := c.withRateLimitRetry(ctx, func() error {
		url, resp, err := c.GH.Actions.GetWorkflowRunLogs(ctx, owner, repo, runID, 3)
		if err != nil {
			// 404 means logs have been purged — warn and skip
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				slog.Warn("logs not found (purged?)", "repo", owner+"/"+repo, "run_id", runID)
				redirectURL = ""
				return nil
			}
			return fmt.Errorf("getting log URL for run %d: %w", runID, err)
		}
		if url != nil {
			redirectURL = url.String()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if redirectURL == "" {
		return nil, nil
	}

	// Download the zip using the plain HTTP client (no Authorization header)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, redirectURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating log download request: %w", err)
	}

	resp, err := c.PlainHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading run logs zip for run %d: %w", runID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d downloading run logs for run %d", resp.StatusCode, runID)
	}

	// Read the body with a size cap
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading run logs zip for run %d: %w", runID, err)
	}

	return unzipLogs(body)
}

// unzipLogs extracts all .txt files from a zip archive in memory.
// Each file's content is capped at maxFileBytes.
func unzipLogs(data []byte) ([]LogFile, error) {
	if len(data) == 0 {
		return nil, nil
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("opening log zip: %w", err)
	}

	var logFiles []LogFile
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".txt") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			slog.Warn("failed to open zip entry", "name", f.Name, "error", err)
			continue
		}

		content, err := io.ReadAll(io.LimitReader(rc, maxFileBytes))
		rc.Close()
		if err != nil {
			slog.Warn("failed to read zip entry", "name", f.Name, "error", err)
			continue
		}

		logFiles = append(logFiles, LogFile{
			Name:    f.Name,
			Content: string(content),
		})
	}

	return logFiles, nil
}
