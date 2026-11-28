package githubactions

import (
	"context"
	"errors"
	"github.com/xmahdi1/nexus/internal/auth"
	"time"
)

func (s *Service) Workflow(ctx context.Context, a *auth.Access, server, id, branch, path string) (WorkflowFile, error) {
	c, token, err := s.scopedToken(ctx, a, server, id, "github.workflows.read", "workflows", false)
	if err != nil {
		return WorkflowFile{}, err
	}
	defer token.Clear()
	result, err := s.Client.ReadWorkflow(ctx, c.repository(), token, branch, path)
	if check := s.currentConnection(a, c, true, "github.workflows.read"); check != nil {
		return WorkflowFile{}, check
	}
	if ctx.Err() != nil {
		return WorkflowFile{}, ErrDenied
	}
	return result, err
}
func (s *Service) PublishWorkflow(ctx context.Context, a *auth.Access, server, connection, id string, input WorkflowEdit) (Change, error) {
	if input.Validate() != nil {
		return Change{}, ErrInput
	}
	const permission = "github.workflows.write"
	row, created, err := s.reserveChange(a, server, connection, id, "workflow_edit", permission, input)
	if err != nil || !created {
		return row, err
	}
	finish := func(state string, cause error) (Change, error) {
		if err := s.saveChange(&row, row.State, state, row.Phase); err != nil {
			return row, err
		}
		return row, cause
	}
	c, token, err := s.scopedToken(ctx, a, server, connection, permission, "workflows", true)
	if err != nil {
		return finish("not_submitted", err)
	}
	defer token.Clear()
	original, err := s.Client.ReadWorkflow(ctx, c.repository(), token, input.BaseBranch, input.Path)
	if err != nil {
		return finish("not_submitted", err)
	}
	if original.BaseSHA != input.BaseSHA || original.BlobSHA != input.BlobSHA || original.Content == input.Content {
		return finish("not_submitted", ErrConflict)
	}
	branch := "nexus/workflows/" + id
	allowed := func() bool { return ctx.Err() == nil && s.currentConnection(a, c, true, permission) == nil }
	if !allowed() {
		return finish("not_submitted", ErrDenied)
	}
	now := time.Now().UTC()
	row.SubmittedAt = &now
	row.Branch = branch
	if err := s.saveChange(&row, "prepared", "submitting", "branch_create"); err != nil {
		return row, err
	}
	if err := s.Client.createWorkflowBranch(ctx, c.repository(), token, branch, input.BaseSHA, allowed); err != nil {
		state := "unknown"
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrInput) {
			state = "not_submitted"
		}
		return finish(state, err)
	}
	if err := s.saveChange(&row, "submitting", "branch_created", "branch_create"); err != nil {
		return row, err
	}
	if !allowed() {
		return finish("incomplete", ErrDenied)
	}
	// Confirm the branch still points at the reviewed base before editing it.
	sha, err := s.Client.branchSHA(ctx, c.repository(), token, branch)
	if err != nil || sha != input.BaseSHA {
		return finish("incomplete", ErrConflict)
	}
	if err := s.saveChange(&row, "branch_created", "submitting", "file_write"); err != nil {
		return row, err
	}
	commit, err := s.Client.writeWorkflowOnce(ctx, c.repository(), token, branch, input, allowed)
	if err != nil {
		state := "unknown"
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrInput) {
			state = "incomplete"
		}
		return finish(state, err)
	}
	row.CommitSHA = commit
	if err := s.saveChange(&row, "submitting", "file_written", "file_write"); err != nil {
		return row, err
	}
	if !allowed() {
		return finish("incomplete", ErrDenied)
	}
	head, err := s.Client.branchSHA(ctx, c.repository(), token, branch)
	if err != nil || head != commit {
		return finish("incomplete", ErrConflict)
	}
	base, err := s.Client.branchSHA(ctx, c.repository(), token, input.BaseBranch)
	if err != nil || base != input.BaseSHA {
		return finish("incomplete", ErrConflict)
	}
	if err := s.saveChange(&row, "file_written", "submitting", "pull_create"); err != nil {
		return row, err
	}
	number, err := s.Client.workflowPullOnce(ctx, c.repository(), token, branch, commit, input, allowed)
	if err != nil {
		state := "unknown"
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrInput) {
			state = "incomplete"
		}
		return finish(state, err)
	}
	row.PullNumber = number
	return finish("applied", nil)
}
