package permissions

import (
	"embed"
	"fmt"
	"strings"

	"github.com/ossf/scorecard/v4/checker"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/finding"
)

func CreateText(t checker.TokenPermission) (string, error) {
	// By default, use the message already present.
	if t.Msg != nil {
		return *t.Msg, nil
	}

	// Ensure there's no implementation bug.
	if t.LocationType == nil {
		return "", sce.WithMessage(sce.ErrScorecardInternal, "locationType is nil")
	}

	// Use a different text depending on the type.
	if t.Type == checker.PermissionLevelUndeclared {
		return fmt.Sprintf("no %s permission defined", *t.LocationType), nil
	}

	if t.Value == nil {
		return "", sce.WithMessage(sce.ErrScorecardInternal, "Value fields is nil")
	}

	if t.Name == nil {
		return fmt.Sprintf("%s permissions set to '%v'", *t.LocationType,
			*t.Value), nil
	}

	return fmt.Sprintf("%s '%v' permission set to '%v'", *t.LocationType,
		*t.Name, *t.Value), nil
}

func CreateNegativeFinding(r checker.TokenPermission, Probe string, fs embed.FS) (*finding.Finding, error) {
		// Create finding
		text, err := CreateText(r)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}
		f, err := finding.NewWith(fs, Probe,
			text, nil, finding.OutcomeNegative)
		if err != nil {
			return nil, fmt.Errorf("create finding: %w", err)
		}

		// Create Location
		var loc *finding.Location
		if r.File != nil {
			loc = &finding.Location{
				Type:      r.File.Type,
				Path:      r.File.Path,
				LineStart: newUint(r.File.Offset),
			}
			if r.File.Snippet != "" {
				loc.Snippet = newStr(r.File.Snippet)
			}
			f = f.WithLocation(loc)
			f = f.WithRemediationMetadata(map[string]string{
				"repo":     r.Remediation.Repo,
				"branch":   r.Remediation.Branch,
				"workflow": strings.TrimPrefix(f.Location.Path, ".github/workflows/"),
			})
		}
		return f, nil
}

// avoid memory aliasing by returning a new copy.
func newUint(u uint) *uint {
	return &u
}

// avoid memory aliasing by returning a new copy.
func newStr(s string) *string {
	return &s
}