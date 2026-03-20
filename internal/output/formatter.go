package output

import (
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/step-security/trivy-compromise-scanner/internal/scanner"
)

// ScanResult is the top-level envelope for scan output.
type ScanResult struct {
	ScannedAt     time.Time         `json:"scanned_at"`
	TotalRepos    int               `json:"total_repos"`
	TotalRuns     int               `json:"total_runs_scanned"`
	TotalFindings int               `json:"total_findings"`
	Findings      []scanner.Finding `json:"findings"`
}

// Formatter writes scan results to an underlying writer.
type Formatter interface {
	Write(result ScanResult) error
}

// NewFormatter returns the appropriate Formatter for the given format string.
func NewFormatter(format string, w io.Writer) (Formatter, error) {
	switch format {
	case "json":
		return &JSONFormatter{w: w}, nil
	case "csv":
		return &CSVFormatter{w: w}, nil
	default:
		return nil, fmt.Errorf("unknown format %q; must be json or csv", format)
	}
}

// PrintSummaryTable writes a human-readable summary table to stdout via tabwriter.
func PrintSummaryTable(w io.Writer, result ScanResult) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SUMMARY")
	fmt.Fprintf(tw, "Scanned at:\t%s\n", result.ScannedAt.Format(time.RFC3339))
	fmt.Fprintf(tw, "Repos scanned:\t%d\n", result.TotalRepos)
	fmt.Fprintf(tw, "Runs scanned:\t%d\n", result.TotalRuns)
	fmt.Fprintf(tw, "Findings:\t%d\n", result.TotalFindings)
	fmt.Fprintln(tw)

	if len(result.Findings) > 0 {
		fmt.Fprintln(tw, "FINDINGS")
		fmt.Fprintln(tw, "REPO\tRUN ID\tWORKFLOW\tTRIGGERED AT\tMATCHES")
		for _, f := range result.Findings {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\n",
				f.Repo,
				f.RunID,
				f.WorkflowName,
				f.TriggeredAt,
				f.MatchSummary,
			)
		}
	}
	tw.Flush()
}
