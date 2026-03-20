package github

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-github/v69/github"
	"golang.org/x/oauth2"
)

// RateLimitEvent describes a rate-limit pause so callers can surface it in a UI.
type RateLimitEvent struct {
	Remaining int
	ResetAt   time.Time
	Sleeping  bool // true while the client is blocked; false when the pause ends
}

// Client wraps the go-github client and a plain HTTP client for log downloads.
type Client struct {
	GH          *github.Client
	PlainHTTP   *http.Client // no Authorization header; for pre-signed S3 URLs
	lastHeaders http.Header

	// OnRateLimit, if set, is called whenever the client hits or proactively
	// avoids a rate limit. Set this before issuing API calls.
	OnRateLimit func(RateLimitEvent)
}

// NewClient constructs a GitHub API client authenticated with the given token.
func NewClient(token string) *Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(context.Background(), ts)

	return &Client{
		GH: github.NewClient(tc),
		PlainHTTP: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CheckPermissions validates the token by calling /user and /rate_limit.
// For PATs it also inspects X-OAuth-Scopes for required scopes.
// GitHub App installation tokens (ghs_…) return 403 on /user — that is handled
// gracefully: the check falls back to /rate_limit only and skips scope validation
// (App tokens have permissions defined in their installation, not OAuth scopes).
func (c *Client) CheckPermissions(ctx context.Context, needsOrg bool) error {
	// GET /user — works for PATs; 403 is expected for GitHub App tokens.
	var scopes string
	user, resp, err := c.GH.Users.Get(ctx, "")
	if err != nil {
		if resp != nil && resp.StatusCode == 403 {
			slog.Info("token is a GitHub App installation token; skipping user/scope check")
		} else {
			return fmt.Errorf("token validation failed: %w", err)
		}
	} else {
		slog.Info("authenticated as", "user", user.GetLogin())
		scopes = resp.Header.Get("X-OAuth-Scopes")
		slog.Debug("token scopes", "scopes", scopes)
	}

	// GET /rate_limit — works for all token types; confirms API access.
	rate, _, err := c.GH.RateLimit.Get(ctx)
	if err != nil {
		return fmt.Errorf("rate limit check failed: %w", err)
	}
	slog.Info("rate limit status",
		"limit", rate.Core.Limit,
		"remaining", rate.Core.Remaining,
		"reset", rate.Core.Reset,
	)

	// Scope validation only applies to PATs (X-OAuth-Scopes is empty for App tokens).
	if scopes == "" {
		return nil
	}

	scopeSet := make(map[string]bool)
	for _, s := range parseScopes(scopes) {
		scopeSet[s] = true
	}

	var missing []string
	if !scopeSet["repo"] && !scopeSet["public_repo"] {
		missing = append(missing, "repo or public_repo")
	}
	if needsOrg && !scopeSet["read:org"] && !scopeSet["admin:org"] {
		missing = append(missing, "read:org")
	}
	if len(missing) > 0 {
		return fmt.Errorf("token is missing required scopes: %s (have: %s)",
			strings.Join(missing, ", "), scopes)
	}

	return nil
}

// parseScopes splits the X-OAuth-Scopes header value into individual scope strings.
func parseScopes(header string) []string {
	var scopes []string
	for _, s := range strings.Split(header, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			scopes = append(scopes, s)
		}
	}
	return scopes
}

// withRateLimitRetry executes fn, retrying once after sleeping if rate-limited.
func (c *Client) withRateLimitRetry(ctx context.Context, fn func() error) error {
	err := fn()
	if err == nil {
		return nil
	}

	var sleepUntil time.Time
	var remaining int
	switch e := err.(type) {
	case *github.RateLimitError:
		sleepUntil = e.Rate.Reset.Time
		remaining = e.Rate.Remaining
		slog.Warn("rate limit hit, sleeping", "reset", sleepUntil)
	case *github.AbuseRateLimitError:
		if e.RetryAfter != nil {
			sleepUntil = time.Now().Add(*e.RetryAfter)
		} else {
			sleepUntil = time.Now().Add(60 * time.Second)
		}
		slog.Warn("abuse rate limit hit, sleeping", "retry_after", sleepUntil)
	default:
		return err
	}

	if c.OnRateLimit != nil {
		c.OnRateLimit(RateLimitEvent{Remaining: remaining, ResetAt: sleepUntil, Sleeping: true})
	}

	wait := time.Until(sleepUntil)
	if wait > 0 {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			if c.OnRateLimit != nil {
				c.OnRateLimit(RateLimitEvent{Sleeping: false})
			}
			return ctx.Err()
		}
	}

	if c.OnRateLimit != nil {
		c.OnRateLimit(RateLimitEvent{Sleeping: false})
	}
	return fn()
}

// checkProactiveThrottle inspects the last API response rate info and sleeps
// proactively if fewer than 100 requests remain.
func (c *Client) checkProactiveThrottle(ctx context.Context, resp *github.Response) {
	if resp == nil {
		return
	}
	if resp.Rate.Remaining < 100 {
		reset := resp.Rate.Reset.Time
		wait := time.Until(reset)
		slog.Warn("proactive throttle: fewer than 100 requests remaining",
			"remaining", resp.Rate.Remaining,
			"reset", reset,
		)
		if c.OnRateLimit != nil {
			c.OnRateLimit(RateLimitEvent{
				Remaining: resp.Rate.Remaining,
				ResetAt:   reset,
				Sleeping:  wait > 0,
			})
		}
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
			}
		}
		if c.OnRateLimit != nil {
			c.OnRateLimit(RateLimitEvent{Sleeping: false})
		}
	}
}
