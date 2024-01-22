package permissions

import (
	"embed"
	"fmt"
	"strings"

	"github.com/ossf/scorecard/v4/checker"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/finding"

	"github.com/ossf/scorecard/v4/probes/internal/utils/uerror"
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

func CreateFindings(fs embed.FS,
					raw *checker.RawResults,
					locationType checker.PermissionLocation,
					permissionLevel checker.PermissionLevel,
					probe, tokenName, negativeOutcomeMsg,
					positiveOutcomeMsg string) ([]finding.Finding, string, error) {
	if raw == nil {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	results := raw.TokenPermissionsResults
	var findings []finding.Finding

	if results.NumTokens == 0 {
		f, err := finding.NewWith(fs, probe,
			"No token permissions found",
			nil, finding.OutcomeNotAvailable)
		if err != nil {
			return nil, probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
		return findings, probe, nil
	}

	for _, r := range results.TokenPermissions {
		if r.Name == nil {
			continue
		}
		if *r.Name != tokenName {
			continue
		}
		if r.Type != permissionLevel {
			continue
		}
		if *r.LocationType != locationType {
			continue
		}

		// Create finding
		f, err := CreateNegativeFinding(r, probe, fs)
		if err != nil {
			return nil, probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}

	if len(findings) == 0 {
		f, err := finding.NewWith(fs, probe,
			fmt.Sprintf("no workflows with write permissions for '%v' at '%v'", tokenName, permissionLevel),
			nil, finding.OutcomePositive)
		if err != nil {
			return nil, probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}
	return findings, probe, nil
}

// avoid memory aliasing by returning a new copy.
func newUint(u uint) *uint {
	return &u
}

// avoid memory aliasing by returning a new copy.
func newStr(s string) *string {
	return &s
}

type TestData struct {
	Name     string
	Raw      *checker.RawResults
	Outcomes []finding.Outcome
	Err      error
}

func GetTests(locationType checker.PermissionLocation, permissionType checker.PermissionLevel, tokenName string) []TestData {
	name := tokenName // Should come from each probe test.
	wrongName := "wrongName"
	value := "value"
	var wrongPermissionLocation checker.PermissionLocation
	if locationType == checker.PermissionLocationTop {
		wrongPermissionLocation = checker.PermissionLocationJob
	} else {
		wrongPermissionLocation = checker.PermissionLocationTop
	}
	//nolint:govet
	return []TestData {
		{
			Name: "No Tokens",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 0,
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomeNotAvailable,
			},
		},
		{
			Name: "Invalid name",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &locationType,
							Name:         &wrongName,
							Value:        &value,
							Msg:          nil,
							Type:         permissionType,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
		{
			Name: "Correct name",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &locationType,
							Name:         &name,
							Value:        &value,
							Msg:          nil,
							Type:         permissionType,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomeNegative,
			},
		},
		{
			Name: "Two tokens",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 2,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &locationType,
							Name:         &name,
							Value:        &value,
							Msg:          nil,
							Type:         permissionType,
						},
						{
							LocationType: &locationType,
							Name:         &name,
							Value:        &value,
							Msg:          nil,
							Type:         permissionType,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomeNegative, finding.OutcomeNegative,
			},
		},
		{
			Name: "Value is nil - Everything else correct",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &locationType,
							Name:         &name,
							Value:        nil,
							Msg:          nil,
							Type:         permissionType,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomeNegative,
			},
			Err: sce.ErrScorecardInternal,
		},
		{
			Name: "Value is nil - Type is wrong",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &locationType,
							Name:         &name,
							Value:        nil,
							Msg:          nil,
							Type:         checker.PermissionLevel("999"),
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
		{
			Name: "Wrong locationType wrong type",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &wrongPermissionLocation,
							Name:         &name,
							Value:        nil,
							Msg:          nil,
							Type:         checker.PermissionLevel("999"),
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
		{
			Name: "Wrong locationType correct type",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &wrongPermissionLocation,
							Name:         &name,
							Value:        nil,
							Msg:          nil,
							Type:         permissionType,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
	}
}