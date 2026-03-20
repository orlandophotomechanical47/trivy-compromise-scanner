package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	ghclient "github.com/step-security/trivy-compromise-scanner/internal/github"
	"github.com/step-security/trivy-compromise-scanner/internal/output"
	"github.com/step-security/trivy-compromise-scanner/internal/scanner"
)

const (
	defaultSince = "2026-03-19T17:00:00Z"
	defaultUntil = "2026-03-20T06:00:00Z"
)

var rootCmd = &cobra.Command{
	Use:   "trivy-scanner",
	Short: "Scan GitHub Actions workflow run logs for aquasecurity/trivy supply chain compromise",
	Long: `trivy-scanner audits GitHub Actions workflow run logs to determine if workflows
executed compromised aquasecurity/trivy action references during the supply chain
compromise window (2026-03-19 to 2026-03-20).`,
	RunE: runScan,
}

// flag values
var (
	flagToken   string
	flagOrgs    []string
	flagRepos   []string
	flagSince   string
	flagUntil   string
	flagOutput  string
	flagFormat  string
	flagWorkers int
	flagDryRun  bool
	flagVerbose bool
)

func init() {
	rootCmd.Flags().StringVarP(&flagToken, "token", "t", "", "GitHub PAT (or set GITHUB_TOKEN env var)")
	rootCmd.Flags().StringArrayVar(&flagOrgs, "org", nil, "Organization name(s); repeatable or comma-separated")
	rootCmd.Flags().StringArrayVarP(&flagRepos, "repo", "r", nil, "owner/repo; repeatable or comma-separated")
	rootCmd.Flags().StringVar(&flagSince, "since", defaultSince, "Window start (RFC3339)")
	rootCmd.Flags().StringVar(&flagUntil, "until", defaultUntil, "Window end (RFC3339)")
	rootCmd.Flags().StringVar(&flagOutput, "output", "", "Output file path (default: stdout)")
	rootCmd.Flags().StringVarP(&flagFormat, "format", "f", "json", "Output format: json or csv")
	rootCmd.Flags().IntVarP(&flagWorkers, "workers", "w", 5, "Number of concurrent run scanners (default 5)")
	rootCmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "Validate PAT permissions and exit without scanning")
	rootCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable debug logging")
}

// Execute is the entry point called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// Configure logging
	logLevel := slog.LevelInfo
	if flagVerbose {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	// Resolve token: flag > env var
	token := flagToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("GitHub token is required: use --token or GITHUB_TOKEN env var")
	}

	// Expand comma-separated orgs and repos
	orgs := expandList(flagOrgs)
	repos := expandList(flagRepos)

	if len(orgs) == 0 && len(repos) == 0 {
		return fmt.Errorf("at least one of --org or --repo is required")
	}

	// Validate time window
	if _, err := time.Parse(time.RFC3339, flagSince); err != nil {
		return fmt.Errorf("invalid --since value %q: %w", flagSince, err)
	}
	if _, err := time.Parse(time.RFC3339, flagUntil); err != nil {
		return fmt.Errorf("invalid --until value %q: %w", flagUntil, err)
	}

	cfg := &scanner.Config{
		Token:      token,
		OutputFile: flagOutput,
		Format:     flagFormat,
		Orgs:       orgs,
		Repos:      repos,
		Since:      flagSince,
		Until:      flagUntil,
		Workers:    flagWorkers,
		Verbose:    flagVerbose,
		DryRun:     flagDryRun,
	}

	ctx := context.Background()
	client := ghclient.NewClient(token)

	// Always validate permissions before scanning
	needsOrg := len(orgs) > 0
	if err := client.CheckPermissions(ctx, needsOrg); err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}

	if flagDryRun {
		fmt.Println("Dry-run complete: token permissions are valid.")
		return nil
	}

	patterns := scanner.CompiledPatterns()
	slog.Info("compiled patterns", "count", len(patterns))
	if len(patterns) == 0 {
		slog.Warn("no compromised patterns configured; scan will produce no findings")
	}

	s := &scanner.Scanner{
		Config:   cfg,
		GH:       client,
		Patterns: patterns,
	}

	findings, totalRepos, totalRuns, err := s.Run(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	result := output.ScanResult{
		ScannedAt:     time.Now().UTC(),
		TotalRepos:    totalRepos,
		TotalRuns:     totalRuns,
		TotalFindings: len(findings),
		Findings:      findings,
	}

	// Always print summary table to stderr so it appears even when output goes to a file
	output.PrintSummaryTable(os.Stdout, result)

	// Write full results
	outWriter := os.Stdout
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("creating output file %q: %w", flagOutput, err)
		}
		defer f.Close()
		outWriter = f
	}

	formatter, err := output.NewFormatter(flagFormat, outWriter)
	if err != nil {
		return err
	}

	return formatter.Write(result)
}

// expandList takes a slice of flag values (which may contain comma-separated items)
// and returns a deduplicated flat list.
func expandList(values []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, ok := seen[part]; !ok {
				seen[part] = struct{}{}
				result = append(result, part)
			}
		}
	}
	return result
}
