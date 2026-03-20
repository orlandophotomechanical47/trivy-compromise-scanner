package scanner

import (
	"testing"
)

func TestCompiledPatterns_NoPanic(t *testing.T) {
	// Should not panic regardless of what's in CompromisedActions
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CompiledPatterns panicked: %v", r)
		}
	}()
	_ = CompiledPatterns()
}

func TestCompiledPatterns_RegexMatchesRef(t *testing.T) {
	// Temporarily inject a known action+SHA to test the compiled regex
	oldActions := CompromisedActions
	CompromisedActions = map[string][]string{
		"aquasecurity/trivy-action": {"abc1234def5678901234567890123456789012345"},
	}
	defer func() { CompromisedActions = oldActions }()

	patterns := CompiledPatterns()
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(patterns))
	}

	p := patterns[0]
	testLine := `##[group]Run aquasecurity/trivy-action@abc1234def5678901234567890123456789012345`
	if !p.Regex.MatchString(testLine) {
		t.Errorf("pattern should match %q", testLine)
	}
}

func TestCompiledPatterns_RegexNoFalsePositive(t *testing.T) {
	oldActions := CompromisedActions
	CompromisedActions = map[string][]string{
		"aquasecurity/trivy-action": {"abc1234def5678901234567890123456789012345"},
	}
	defer func() { CompromisedActions = oldActions }()

	patterns := CompiledPatterns()
	if len(patterns) != 1 {
		t.Fatalf("expected 1 pattern, got %d", len(patterns))
	}

	p := patterns[0]
	// Different SHA — should NOT match
	testLine := `##[group]Run aquasecurity/trivy-action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
	if p.Regex.MatchString(testLine) {
		t.Errorf("pattern should NOT match a different SHA: %q", testLine)
	}

	// Different action — should NOT match
	testLine2 := `##[group]Run actions/checkout@abc1234def5678901234567890123456789012345`
	if p.Regex.MatchString(testLine2) {
		t.Errorf("pattern should NOT match a different action: %q", testLine2)
	}
}
