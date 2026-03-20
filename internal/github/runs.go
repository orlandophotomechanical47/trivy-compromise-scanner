package github

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/go-github/v69/github"
)

// ListRunsInWindow returns all workflow runs in [since, until] for the given repo.
// It paginates until all pages are consumed.
func (c *Client) ListRunsInWindow(ctx context.Context, owner, repo, since, until string) ([]*github.WorkflowRun, error) {
	var allRuns []*github.WorkflowRun

	opts := &github.ListWorkflowRunsOptions{
		Created: fmt.Sprintf("%s..%s", since, until),
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		var runs *github.WorkflowRuns
		var resp *github.Response

		err := c.withRateLimitRetry(ctx, func() error {
			var err error
			runs, resp, err = c.GH.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo, opts)
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("listing workflow runs for %s/%s: %w", owner, repo, err)
		}

		c.checkProactiveThrottle(ctx, resp)

		allRuns = append(allRuns, runs.WorkflowRuns...)
		slog.Debug("fetched runs page",
			"repo", owner+"/"+repo,
			"page", opts.Page,
			"count", len(runs.WorkflowRuns),
			"total_so_far", len(allRuns),
		)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRuns, nil
}

// ListOrgRepos returns all repos (full "owner/repo" strings) in the given org.
// It paginates until all pages are consumed.
func (c *Client) ListOrgRepos(ctx context.Context, org string) ([]string, error) {
	var allRepos []string

	opts := &github.RepositoryListByOrgOptions{
		Type: "all",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		var repos []*github.Repository
		var resp *github.Response

		err := c.withRateLimitRetry(ctx, func() error {
			var err error
			repos, resp, err = c.GH.Repositories.ListByOrg(ctx, org, opts)
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("listing repos for org %s: %w", org, err)
		}

		c.checkProactiveThrottle(ctx, resp)

		for _, r := range repos {
			allRepos = append(allRepos, r.GetFullName())
		}

		slog.Debug("fetched org repos page",
			"org", org,
			"page", opts.Page,
			"count", len(repos),
			"total_so_far", len(allRepos),
		)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}
