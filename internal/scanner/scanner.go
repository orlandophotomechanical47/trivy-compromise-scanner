package scanner

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	ghclient "github.com/step-security/trivy-compromise-scanner/internal/github"
)

// ActionRef represents a parsed action reference found in a log file.
type ActionRef struct {
	Action string // e.g. "owner/action-name"
	Ref    string // e.g. commit SHA, branch, or tag
	Line   string // the original log line containing the reference
}

// ExtractActionRefs parses all owner/action@ref usages from log file content.
// It handles both "uses: owner/action@ref" and "##[group]Run owner/action@ref" formats.
func ExtractActionRefs(content string) []ActionRef {
	var refs []ActionRef
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		ref, ok := parseActionRef(line)
		if ok {
			refs = append(refs, ActionRef{
				Action: ref.Action,
				Ref:    ref.Ref,
				Line:   line,
			})
		}
	}
	return refs
}

// parseActionRef attempts to extract an action reference from a single log line.
func parseActionRef(line string) (ActionRef, bool) {
	// Strip leading timestamp (e.g. "2026-03-19T18:31:05.1234567Z ")
	stripped := stripTimestamp(line)

	// Look for "uses: owner/action@ref" pattern
	if idx := strings.Index(stripped, "uses:"); idx != -1 {
		rest := strings.TrimSpace(stripped[idx+5:])
		return extractRef(rest, line)
	}

	// Look for "##[group]Run owner/action@ref" pattern
	if idx := strings.Index(stripped, "##[group]Run "); idx != -1 {
		rest := strings.TrimSpace(stripped[idx+13:])
		return extractRef(rest, line)
	}

	// Look for bare "owner/action@ref" pattern within the line
	// This catches variations like leading spaces or other prefixes
	if idx := strings.Index(stripped, "@"); idx != -1 {
		// Find the start of the action ref (must have a slash before @)
		slashIdx := strings.LastIndex(stripped[:idx], "/")
		if slashIdx != -1 {
			// Walk back to find the start of "owner"
			start := slashIdx
			for start > 0 && isActionChar(stripped[start-1]) {
				start--
			}
			if start < slashIdx {
				candidate := stripped[start:]
				// Find the end of the ref
				end := len(candidate)
				for i, ch := range candidate {
					if !isActionChar(byte(ch)) && ch != '@' && ch != '/' && ch != '-' && ch != '_' && ch != '.' {
						end = i
						break
					}
				}
				return extractRef(strings.TrimSpace(candidate[:end]), line)
			}
		}
	}

	return ActionRef{}, false
}

// extractRef parses "owner/action@ref" from a string token and the surrounding line.
func extractRef(token string, originalLine string) (ActionRef, bool) {
	// Trim trailing punctuation or whitespace
	token = strings.TrimRight(token, " \t\r\n,;'\"")

	atIdx := strings.Index(token, "@")
	if atIdx < 0 {
		return ActionRef{}, false
	}

	slashIdx := strings.Index(token[:atIdx], "/")
	if slashIdx < 0 {
		return ActionRef{}, false
	}

	// Validate: owner and action name must be non-empty
	owner := token[:slashIdx]
	// action name is between slash and @; may contain more slashes for nested paths
	actionName := token[slashIdx+1 : atIdx]
	ref := token[atIdx+1:]

	// Strip any trailing non-ref characters from ref
	if spaceIdx := strings.IndexAny(ref, " \t"); spaceIdx != -1 {
		ref = ref[:spaceIdx]
	}

	if owner == "" || actionName == "" || ref == "" {
		return ActionRef{}, false
	}

	return ActionRef{
		Action: owner + "/" + actionName,
		Ref:    ref,
		Line:   originalLine,
	}, true
}

// stripTimestamp removes a leading RFC3339 timestamp from a log line if present.
func stripTimestamp(line string) string {
	// GitHub Actions log timestamps look like: "2026-03-19T18:31:05.1234567Z "
	if len(line) < 28 {
		return line
	}
	if line[4] == '-' && line[7] == '-' && line[10] == 'T' {
		spaceIdx := strings.Index(line, " ")
		if spaceIdx > 0 && spaceIdx < 35 {
			return strings.TrimSpace(line[spaceIdx+1:])
		}
	}
	return line
}

// isActionChar returns true if c is a valid character in an action owner/name.
func isActionChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
}

// MatchPatterns applies compiled patterns against log files and returns all matches.
func MatchPatterns(patterns []ActionPattern, logFiles []ghclient.LogFile) []Match {
	var matches []Match
	for _, lf := range logFiles {
		lines := strings.Split(lf.Content, "\n")
		for i, line := range lines {
			for _, p := range patterns {
				if p.Regex.MatchString(line) {
					snippet := buildSnippet(lines, i, 200)
					matches = append(matches, Match{
						Pattern: p.Action + "@" + p.SHA,
						File:    lf.Name,
						Snippet: snippet,
					})
				}
			}
		}
	}
	return matches
}

// buildSnippet returns a context window around line i, capped at maxLen characters.
func buildSnippet(lines []string, idx, maxLen int) string {
	start := idx - 1
	if start < 0 {
		start = 0
	}
	end := idx + 2
	if end > len(lines) {
		end = len(lines)
	}
	snippet := strings.Join(lines[start:end], "\n")
	if len(snippet) > maxLen {
		snippet = snippet[:maxLen]
	}
	return snippet
}

// Match is a single pattern hit within a log file.
type Match struct {
	Pattern string `json:"pattern"`
	File    string `json:"file"`
	Snippet string `json:"snippet"`
}

// Finding is a workflow run confirmed to contain one or more compromised patterns.
type Finding struct {
	Org          string  `json:"org"           csv:"org"`
	Repo         string  `json:"repo"          csv:"repo"`
	WorkflowName string  `json:"workflow_name" csv:"workflow_name"`
	RunID        int64   `json:"run_id"        csv:"run_id"`
	RunURL       string  `json:"run_url"       csv:"run_url"`
	TriggeredAt  string  `json:"triggered_at"  csv:"triggered_at"`
	Matches      []Match `json:"matches"       csv:"-"`
	MatchSummary string  `json:"-"             csv:"matches"`
}

// repoTarget is used in phase 1 to enumerate run lists.
type repoTarget struct {
	Org  string
	Repo string // "owner/repo"
}

// runTarget is the unit of work for phase 2 workers.
type runTarget struct {
	Org      string
	Repo     string // "owner/repo"
	Owner    string
	RepoName string
	RunID    int64
	RunName  string
	RunURL   string
	RunTime  string
}

// Scanner orchestrates scanning across repos with a worker pool.
type Scanner struct {
	Config   *Config
	GH       *ghclient.Client
	Patterns []ActionPattern
}

// Config holds resolved runtime settings for the scanner.
type Config struct {
	Token      string
	OutputFile string
	Format     string
	Orgs       []string
	Repos      []string
	Since      string
	Until      string
	Workers    int
	Verbose    bool
	DryRun     bool
}

// Run executes the full scan and returns all findings plus metadata.
//
// Two-phase pipeline:
//  1. Phase 1 — a bounded pool fetches run lists for every repo and fans
//     individual runs into runCh. Workers = min(Config.Workers, repos).
//  2. Phase 2 — Config.Workers goroutines drain runCh, downloading logs
//     and matching patterns in parallel regardless of repo count.
func (s *Scanner) Run(ctx context.Context) ([]Finding, int, int, error) {
	jobs, totalRepos, err := s.buildJobList(ctx)
	if err != nil {
		return nil, 0, 0, err
	}

	prog := newProgressReporter(totalRepos, s.Config.Workers, os.Stderr)
	prog.start()
	defer prog.stop()

	// Surface rate-limit events in the progress display.
	s.GH.OnRateLimit = func(ev ghclient.RateLimitEvent) {
		if ev.Sleeping {
			wait := time.Until(ev.ResetAt).Round(time.Second)
			prog.SetRateLimitWarning(fmt.Sprintf(
				"rate limit hit — pausing %s (resets at %s UTC)",
				wait, ev.ResetAt.UTC().Format("15:04:05"),
			))
		} else {
			prog.ClearRateLimitWarning()
		}
	}

	// ── Phase 1: enumerate runs ───────────────────────────────────────────────
	runCh := make(chan runTarget, 200)

	repoCh := make(chan repoTarget, len(jobs))
	for _, j := range jobs {
		repoCh <- j
	}
	close(repoCh)

	fetchWorkers := s.Config.Workers
	if fetchWorkers > len(jobs) && len(jobs) > 0 {
		fetchWorkers = len(jobs)
	}
	if fetchWorkers == 0 {
		fetchWorkers = 1
	}

	var fetchWg sync.WaitGroup
	for i := 0; i < fetchWorkers; i++ {
		fetchWg.Add(1)
		go func() {
			defer fetchWg.Done()
			for job := range repoCh {
				parts := strings.SplitN(job.Repo, "/", 2)
				if len(parts) != 2 {
					continue
				}
				owner, repoName := parts[0], parts[1]
				runs, err := s.GH.ListRunsInWindow(ctx, owner, repoName, s.Config.Since, s.Config.Until)
				if err != nil {
					slog.Warn("failed to list runs", "repo", job.Repo, "error", err)
					continue
				}
				prog.addKnownRuns(len(runs))
				for _, run := range runs {
					runCh <- runTarget{
						Org:      job.Org,
						Repo:     job.Repo,
						Owner:    owner,
						RepoName: repoName,
						RunID:    run.GetID(),
						RunName:  run.GetName(),
						RunURL:   run.GetHTMLURL(),
						RunTime:  run.GetCreatedAt().String(),
					}
				}
			}
		}()
	}

	go func() {
		fetchWg.Wait()
		close(runCh)
	}()

	// ── Phase 2: process runs ─────────────────────────────────────────────────
	type workerResult struct {
		findings  []Finding
		runsCount int
	}
	resultCh := make(chan workerResult, s.Config.Workers)

	var wg sync.WaitGroup
	for i := 0; i < s.Config.Workers; i++ {
		wg.Add(1)
		wp := prog.workerProgress(i)
		go func() {
			defer wg.Done()
			var localFindings []Finding
			var localRuns int
			for rt := range runCh {
				if ctx.Err() != nil {
					break
				}
				finding, err := s.processRun(ctx, rt, wp)
				localRuns++
				if err != nil {
					slog.Warn("run scan failed", "repo", rt.Repo, "run_id", rt.RunID, "error", err)
					continue
				}
				if finding != nil {
					localFindings = append(localFindings, *finding)
				}
			}
			resultCh <- workerResult{findings: localFindings, runsCount: localRuns}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var allFindings []Finding
	totalRuns := 0
	for r := range resultCh {
		allFindings = append(allFindings, r.findings...)
		totalRuns += r.runsCount
	}

	return allFindings, totalRepos, totalRuns, nil
}

// processRun downloads and scans logs for a single workflow run.
func (s *Scanner) processRun(ctx context.Context, rt runTarget, wp *WorkerProgress) (*Finding, error) {
	wp.startDownloading(rt.Repo, rt.RunName, rt.RunID)

	logFiles, err := s.GH.DownloadRunLogs(ctx, rt.Owner, rt.RepoName, rt.RunID)
	if err != nil {
		wp.runDone(0)
		return nil, err
	}

	wp.startMatching()
	matches := MatchPatterns(s.Patterns, logFiles)
	wp.runDone(len(matches))

	if len(matches) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var summaryParts []string
	for _, m := range matches {
		if _, ok := seen[m.Pattern]; !ok {
			summaryParts = append(summaryParts, m.Pattern)
			seen[m.Pattern] = struct{}{}
		}
	}

	return &Finding{
		Org:          rt.Org,
		Repo:         rt.Repo,
		WorkflowName: rt.RunName,
		RunID:        rt.RunID,
		RunURL:       rt.RunURL,
		TriggeredAt:  rt.RunTime,
		Matches:      matches,
		MatchSummary: strings.Join(summaryParts, "; "),
	}, nil
}

// buildJobList expands org names into repos and merges with explicit --repo targets.
func (s *Scanner) buildJobList(ctx context.Context) ([]repoTarget, int, error) {
	seen := make(map[string]struct{})
	var jobs []repoTarget

	for _, org := range s.Config.Orgs {
		repos, err := s.GH.ListOrgRepos(ctx, org)
		if err != nil {
			return nil, 0, err
		}
		for _, r := range repos {
			if _, ok := seen[r]; !ok {
				seen[r] = struct{}{}
				jobs = append(jobs, repoTarget{Org: org, Repo: r})
			}
		}
	}

	for _, r := range s.Config.Repos {
		if _, ok := seen[r]; !ok {
			seen[r] = struct{}{}
			// For explicit repos, derive org from owner portion
			parts := strings.SplitN(r, "/", 2)
			org := ""
			if len(parts) == 2 {
				org = parts[0]
			}
			jobs = append(jobs, repoTarget{Org: org, Repo: r})
		}
	}

	return jobs, len(jobs), nil
}
