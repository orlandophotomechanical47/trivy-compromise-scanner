package scanner

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	globalBarWidth  = 30
	refreshInterval = 100 * time.Millisecond
)

var spinFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

type slotPhase uint8

const (
	phaseIdle        slotPhase = iota
	phaseDownloading           // fetching log zip
	phaseMatching              // scanning log content
	phaseDone
)

// workerSlot holds the display state for one worker goroutine.
type workerSlot struct {
	repo     string
	workflow string
	runID    int64
	phase    slotPhase
	findings int
}

// WorkerProgress is handed to each run-processing worker goroutine.
type WorkerProgress struct {
	id int
	pr *progressReporter
}

func (wp *WorkerProgress) startDownloading(repo, workflow string, runID int64) {
	wp.pr.mu.Lock()
	wp.pr.slots[wp.id] = workerSlot{
		repo: repo, workflow: workflow, runID: runID, phase: phaseDownloading,
	}
	wp.pr.mu.Unlock()
}

func (wp *WorkerProgress) startMatching() {
	wp.pr.mu.Lock()
	wp.pr.slots[wp.id].phase = phaseMatching
	wp.pr.mu.Unlock()
}

func (wp *WorkerProgress) runDone(findings int) {
	wp.pr.mu.Lock()
	wp.pr.slots[wp.id].findings += findings
	wp.pr.slots[wp.id].phase = phaseDone
	wp.pr.mu.Unlock()
	atomic.AddInt32(&wp.pr.doneRuns, 1)
	atomic.AddInt32(&wp.pr.totalFindings, int32(findings))
}

// addKnownRuns is called by the run-fetching phase as each repo's run list arrives.
func (p *progressReporter) addKnownRuns(n int) {
	atomic.AddInt32(&p.knownRuns, int32(n))
}

// SetRateLimitWarning surfaces a rate-limit event in the progress display.
func (p *progressReporter) SetRateLimitWarning(msg string) {
	p.rateLimitMsg.Store(msg)
}

// ClearRateLimitWarning removes the rate-limit warning once the pause is over.
func (p *progressReporter) ClearRateLimitWarning() {
	p.rateLimitMsg.Store("")
}

// progressReporter manages the multi-line terminal display.
type progressReporter struct {
	totalRepos int
	numWorkers int

	knownRuns     int32 // atomic — grows as repo run lists are fetched
	doneRuns      int32 // atomic — grows as runs are fully processed
	totalFindings int32 // atomic

	rateLimitMsg atomic.Value // string — non-empty while rate-limited

	mu    sync.Mutex
	slots []workerSlot

	w          io.Writer
	stopCh     chan struct{}
	doneCh     chan struct{}
	frameIdx   int
	linesDrawn int // lines written in last render (for cursor repositioning)
}

func newProgressReporter(totalRepos, numWorkers int, w io.Writer) *progressReporter {
	p := &progressReporter{
		totalRepos: totalRepos,
		numWorkers: numWorkers,
		slots:      make([]workerSlot, numWorkers),
		w:          w,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
	p.rateLimitMsg.Store("")
	return p
}

func (p *progressReporter) workerProgress(id int) *WorkerProgress {
	return &WorkerProgress{id: id, pr: p}
}

func (p *progressReporter) start() {
	go func() {
		defer close(p.doneCh)
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.frameIdx++
				p.render()
			case <-p.stopCh:
				p.render()
				p.clearBlock()
				return
			}
		}
	}()
}

func (p *progressReporter) stop() {
	close(p.stopCh)
	<-p.doneCh
}

// moveToTop repositions the cursor to the first line of the progress block.
// Must be called when cursor is sitting one line BELOW the last drawn line
// (i.e. right after a render that ended with \n).
func (p *progressReporter) moveToTop() {
	if p.linesDrawn == 0 {
		return
	}
	// Each render writes linesDrawn lines each ending with \n, leaving the
	// cursor at the start of line linesDrawn+1.  Moving up linesDrawn lines
	// returns to line 1.
	fmt.Fprintf(p.w, "\033[%dA\r", p.linesDrawn)
}

func (p *progressReporter) clearBlock() {
	if p.linesDrawn == 0 {
		return
	}
	// Move to the first line of the block.
	p.moveToTop()
	// Erase every line top-to-bottom.
	for i := 0; i < p.linesDrawn; i++ {
		fmt.Fprint(p.w, "\033[K") // erase to end of line
		if i < p.linesDrawn-1 {
			fmt.Fprintln(p.w) // advance to next line
		}
	}
	// Cursor is now at the last line; go back to line 1.
	if p.linesDrawn > 1 {
		fmt.Fprintf(p.w, "\033[%dA\r", p.linesDrawn-1)
	} else {
		fmt.Fprint(p.w, "\r")
	}
}

func (p *progressReporter) render() {
	p.mu.Lock()
	slots := make([]workerSlot, len(p.slots))
	copy(slots, p.slots)
	p.mu.Unlock()

	known := atomic.LoadInt32(&p.knownRuns)
	done := atomic.LoadInt32(&p.doneRuns)
	findings := atomic.LoadInt32(&p.totalFindings)
	spin := string(spinFrames[p.frameIdx%len(spinFrames)])
	rlMsg, _ := p.rateLimitMsg.Load().(string)

	var sb strings.Builder
	lines := 0

	// pad to 100 chars and clear to EOL to erase any leftover text
	line := func(format string, args ...any) {
		fmt.Fprintf(&sb, "%-100s\033[K\n", fmt.Sprintf(format, args...))
		lines++
	}

	// ── Header ────────────────────────────────────────────────────────────────
	line("  Scanning %d repo(s)   %d workers", p.totalRepos, p.numWorkers)
	line("")

	// ── Rate-limit warning (only when active) ─────────────────────────────────
	if rlMsg != "" {
		line("  \033[33m⚠  %s\033[0m", rlMsg)
		line("")
	}

	// ── Global progress bar ───────────────────────────────────────────────────
	if known == 0 {
		bar := strings.Repeat("░", globalBarWidth)
		line("  [%s]  discovering runs...", bar)
	} else {
		bar := renderBar(int(done), int(known), globalBarWidth)
		findStr := "no findings"
		if findings > 0 {
			findStr = fmt.Sprintf("\033[33m%d finding(s)\033[0m", findings)
		}
		line("  %s  %d/%d runs   %s", bar, done, known, findStr)
	}
	line("")

	// ── Per-worker rows ───────────────────────────────────────────────────────
	for _, slot := range slots {
		line("  %s", renderSlot(slot, spin))
	}

	// Move back to the top of the block and flush.
	p.moveToTop()
	fmt.Fprint(p.w, sb.String())
	p.linesDrawn = lines
}

func renderSlot(slot workerSlot, spin string) string {
	repo := label(slot.repo, 36)
	wf := label(slot.workflow, 24)

	switch slot.phase {
	case phaseIdle:
		return fmt.Sprintf("·  %-36s  %-24s  idle", "", "")
	case phaseDownloading:
		return fmt.Sprintf("%s  %-36s  %-24s  downloading logs...", spin, repo, wf)
	case phaseMatching:
		return fmt.Sprintf("%s  %-36s  %-24s  matching patterns...", spin, repo, wf)
	case phaseDone:
		suffix := ""
		if slot.findings > 0 {
			suffix = fmt.Sprintf("  \033[33m⚠ %d finding(s)\033[0m", slot.findings)
		}
		return fmt.Sprintf("\033[32m✓\033[0m  %-36s  %-24s  done%s", repo, wf, suffix)
	}
	return ""
}

func renderBar(done, total, width int) string {
	if total == 0 {
		return "[" + strings.Repeat("░", width) + "]"
	}
	filled := done * width / total
	if filled >= width {
		return "\033[32m[" + strings.Repeat("=", width) + "]\033[0m"
	}
	return "[" + strings.Repeat("=", filled) + ">" + strings.Repeat(" ", width-filled-1) + "]"
}

func label(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return "…" + s[len(s)-(maxLen-1):]
}
