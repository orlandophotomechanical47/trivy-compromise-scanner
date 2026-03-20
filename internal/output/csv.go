package output

import (
	"encoding/csv"
	"fmt"
	"io"
)

// CSVFormatter writes a ScanResult as CSV rows.
type CSVFormatter struct {
	w io.Writer
}

// Write encodes the ScanResult findings as CSV to the underlying writer.
func (f *CSVFormatter) Write(result ScanResult) error {
	cw := csv.NewWriter(f.w)

	// Write header row
	header := []string{
		"org",
		"repo",
		"workflow_name",
		"run_id",
		"run_url",
		"triggered_at",
		"matches",
	}
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("writing CSV header: %w", err)
	}

	// Write one row per finding
	for _, finding := range result.Findings {
		row := []string{
			finding.Org,
			finding.Repo,
			finding.WorkflowName,
			fmt.Sprintf("%d", finding.RunID),
			finding.RunURL,
			finding.TriggeredAt,
			finding.MatchSummary,
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("writing CSV row: %w", err)
		}
	}

	cw.Flush()
	return cw.Error()
}
