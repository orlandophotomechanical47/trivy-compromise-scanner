package scanner

import (
	"strings"
	"testing"

	ghclient "github.com/step-security/trivy-compromise-scanner/internal/github"
)

// --- ExtractActionRefs tests ---

func TestExtractActionRefs_BasicUsage(t *testing.T) {
	content := `2026-03-19T18:31:05.123Z   uses: aquasecurity/trivy-action@abc1234def5678901234567890123456789012345`
	refs := ExtractActionRefs(content)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0].Action != "aquasecurity/trivy-action" {
		t.Errorf("expected action %q, got %q", "aquasecurity/trivy-action", refs[0].Action)
	}
	if refs[0].Ref != "abc1234def5678901234567890123456789012345" {
		t.Errorf("expected ref %q, got %q", "abc1234def5678901234567890123456789012345", refs[0].Ref)
	}
}

func TestExtractActionRefs_GroupRunFormat(t *testing.T) {
	content := `2026-03-19T18:31:05.123Z ##[group]Run aquasecurity/trivy-action@abc1234def5678901234567890123456789012345`
	refs := ExtractActionRefs(content)
	if len(refs) == 0 {
		t.Fatal("expected at least 1 ref, got 0")
	}
	found := false
	for _, r := range refs {
		if r.Action == "aquasecurity/trivy-action" &&
			r.Ref == "abc1234def5678901234567890123456789012345" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find aquasecurity/trivy-action@abc1234..., refs: %+v", refs)
	}
}

func TestExtractActionRefs_ShortSHA(t *testing.T) {
	content := `2026-03-19T18:31:05.123Z   uses: actions/checkout@v4`
	refs := ExtractActionRefs(content)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %d", len(refs))
	}
	if refs[0].Action != "actions/checkout" {
		t.Errorf("expected action %q, got %q", "actions/checkout", refs[0].Action)
	}
	if refs[0].Ref != "v4" {
		t.Errorf("expected ref %q, got %q", "v4", refs[0].Ref)
	}
}

func TestExtractActionRefs_MultipleActions(t *testing.T) {
	content := strings.Join([]string{
		`2026-03-19T18:31:00.000Z   uses: actions/checkout@v4`,
		`2026-03-19T18:31:01.000Z   uses: actions/setup-go@v5`,
		`2026-03-19T18:31:02.000Z   uses: aquasecurity/trivy-action@abc1234def5678901234567890123456789012345`,
	}, "\n")
	refs := ExtractActionRefs(content)
	if len(refs) != 3 {
		t.Fatalf("expected 3 refs, got %d: %+v", len(refs), refs)
	}
}

func TestExtractActionRefs_NoActions(t *testing.T) {
	content := `2026-03-19T18:31:05.123Z This is a regular log line with no action references.`
	refs := ExtractActionRefs(content)
	if len(refs) != 0 {
		t.Errorf("expected 0 refs, got %d: %+v", len(refs), refs)
	}
}

// --- MatchPatterns tests ---

func makePattern(action, sha string) ActionPattern {
	p := ActionPattern{Action: action, SHA: sha}
	patterns := []ActionPattern{}
	// Build a temporary CompromisedActions map and compile it
	oldActions := CompromisedActions
	CompromisedActions = map[string][]string{action: {sha}}
	compiled := CompiledPatterns()
	CompromisedActions = oldActions
	if len(compiled) == 1 {
		p = compiled[0]
	}
	_ = patterns
	return p
}

func TestMatchPatterns_HitOnCompromisedSHA(t *testing.T) {
	p := makePattern("aquasecurity/trivy-action", "abc1234def5678901234567890123456789012345")
	logFiles := []ghclient.LogFile{
		{
			Name:    "1_Run trivy-action.txt",
			Content: `2026-03-19T18:31:05.123Z ##[group]Run aquasecurity/trivy-action@abc1234def5678901234567890123456789012345`,
		},
	}
	matches := MatchPatterns([]ActionPattern{p}, logFiles)
	if len(matches) == 0 {
		t.Fatal("expected at least 1 match, got 0")
	}
	if matches[0].Pattern != "aquasecurity/trivy-action@abc1234def5678901234567890123456789012345" {
		t.Errorf("unexpected pattern in match: %q", matches[0].Pattern)
	}
}

func TestMatchPatterns_NoHitOnDifferentSHA(t *testing.T) {
	p := makePattern("aquasecurity/trivy-action", "abc1234def5678901234567890123456789012345")
	logFiles := []ghclient.LogFile{
		{
			Name:    "1_Run trivy-action.txt",
			Content: `2026-03-19T18:31:05.123Z ##[group]Run aquasecurity/trivy-action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef`,
		},
	}
	matches := MatchPatterns([]ActionPattern{p}, logFiles)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for different SHA, got %d", len(matches))
	}
}

func TestMatchPatterns_NoHitOnUnrelatedLog(t *testing.T) {
	p := makePattern("aquasecurity/trivy-action", "abc1234def5678901234567890123456789012345")
	logFiles := []ghclient.LogFile{
		{
			Name:    "1_setup.txt",
			Content: `2026-03-19T18:31:05.123Z Setting up environment variables`,
		},
	}
	matches := MatchPatterns([]ActionPattern{p}, logFiles)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for unrelated log, got %d", len(matches))
	}
}

func TestMatchPatterns_SnippetContent(t *testing.T) {
	p := makePattern("aquasecurity/trivy-action", "abc1234def5678901234567890123456789012345")
	content := strings.Join([]string{
		`2026-03-19T18:31:04.000Z ##[group]Starting step`,
		`2026-03-19T18:31:05.000Z ##[group]Run aquasecurity/trivy-action@abc1234def5678901234567890123456789012345`,
		`2026-03-19T18:31:06.000Z   with:`,
	}, "\n")
	logFiles := []ghclient.LogFile{{Name: "1_step.txt", Content: content}}
	matches := MatchPatterns([]ActionPattern{p}, logFiles)
	if len(matches) == 0 {
		t.Fatal("expected at least 1 match")
	}
	snippet := matches[0].Snippet
	if !strings.Contains(snippet, "Run aquasecurity/trivy-action") {
		t.Errorf("snippet should contain the matching line, got: %q", snippet)
	}
}

func TestMatchPatterns_MultipleHits(t *testing.T) {
	p1 := makePattern("aquasecurity/trivy-action", "aaa1111aaa1111aaa1111aaa1111aaa1111aaa11")
	p2 := makePattern("aquasecurity/trivy-action", "bbb2222bbb2222bbb2222bbb2222bbb2222bbb22")

	content := strings.Join([]string{
		`2026-03-19T18:31:05.000Z ##[group]Run aquasecurity/trivy-action@aaa1111aaa1111aaa1111aaa1111aaa1111aaa11`,
		`2026-03-19T18:31:10.000Z ##[group]Run aquasecurity/trivy-action@bbb2222bbb2222bbb2222bbb2222bbb2222bbb22`,
	}, "\n")
	logFiles := []ghclient.LogFile{{Name: "1_step.txt", Content: content}}
	matches := MatchPatterns([]ActionPattern{p1, p2}, logFiles)
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}
}
