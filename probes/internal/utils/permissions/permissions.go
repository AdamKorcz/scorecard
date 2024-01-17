package permissions

import (
	"embed"
	"fmt"
	"strings"

	"github.com/ossf/scorecard/v4/checker"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/finding"
)

// permissionLocation represents a declaration type.
type permissionLocationType int

const (
	// permissionLocationNil is in case the permission is nil.
	permissionLocationNil permissionLocationType = iota
	// permissionLocationNotDeclared is for undeclared permission.
	permissionLocationNotDeclared
	// permissionLocationTop is top-level workflow permission.
	permissionLocationTop
	// permissionLocationJob is job-level workflow permission.
	permissionLocationJob
)

type permissionLevel int

const (
	// permissionLevelNone is a permission set to `none`.
	permissionLevelNone permissionLevel = iota
	// permissionLevelRead is a permission set to `read`.
	permissionLevelRead
	// permissionLevelUnknown is for other kinds of alerts, mostly to support debug messages.
	// TODO: remove it once we have implemented severity (#1874).
	permissionLevelUnknown
	// permissionLevelUndeclared is an undeclared permission.
	permissionLevelUndeclared
	// permissionLevelWrite is a permission set to `write` for a permission we consider potentially dangerous.
	permissionLevelWrite
)

// permissionType represents a permission type.
type permissionType int

const (
	// permissionTypeNone represents none permission type.
	permissionTypeNone permissionType = iota
	// permissionTypeNone is the "all" github permission type.
	permissionTypeAll
	// permissionTypeNone is the "statuses" github permission type.
	permissionTypeStatuses
	// permissionTypeNone is the "checks" github permission type.
	permissionTypeChecks
	// permissionTypeNone is the "security-events" github permission type.
	permissionTypeSecurityEvents
	// permissionTypeNone is the "deployments" github permission type.
	permissionTypeDeployments
	// permissionTypeNone is the "packages" github permission type.
	permissionTypePackages
	// permissionTypeNone is the "actions" github permission type.
	permissionTypeActions
)

func permTypeToEnum(tokenName *string) permissionType {
	if tokenName == nil {
		return permissionTypeNone
	}
	switch *tokenName {
	//nolint:goconst
	case "all":
		return permissionTypeAll
	case "statuses":
		return permissionTypeStatuses
	case "checks":
		return permissionTypeChecks
	case "security-events":
		return permissionTypeSecurityEvents
	case "deployments":
		return permissionTypeDeployments
	case "contents":
		return permissionTypePackages
	case "actions":
		return permissionTypeActions
	default:
		return permissionTypeNone
	}
}

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

func SetOutcomeAndLocation(r checker.TokenPermission, f *finding.Finding) {
	switch r.Type {
	case checker.PermissionLevelNone:
		f = f.WithOutcome(finding.OutcomePositive)
		f = f.WithValues(map[string]int{
			"PermissionLevel": int(permissionLevelNone),
		})
	case checker.PermissionLevelRead:
		f = f.WithOutcome(finding.OutcomePositive)
		f = f.WithValues(map[string]int{
			"PermissionLevel": int(permissionLevelRead),
		})

	case checker.PermissionLevelUnknown:
		f = f.WithValues(map[string]int{
			"PermissionLevel": int(permissionLevelUnknown),
		}).WithOutcome(finding.OutcomeError)
	case checker.PermissionLevelUndeclared:
		var locationType permissionLocationType
		//nolint:gocritic
		if r.LocationType == nil {
			locationType = permissionLocationNil
		} else if *r.LocationType == checker.PermissionLocationTop {
			locationType = permissionLocationTop
		} else {
			locationType = permissionLocationNotDeclared
		}
		permType := permTypeToEnum(r.Name)
		f = f.WithValues(map[string]int{
			"PermissionLevel": int(permissionLevelUndeclared),
			"LocationType":    int(locationType),
			"PermissionType":  int(permType),
		})
	case checker.PermissionLevelWrite:
		/*var locationType permissionLocationType
		switch *r.LocationType {
		case checker.PermissionLocationTop:
			locationType = permissionLocationTop
		case checker.PermissionLocationJob:
			locationType = permissionLocationJob
		default:
			locationType = permissionLocationNotDeclared
		}
		permType := permTypeToEnum(r.Name)
		f = f.WithValues(map[string]int{
			"PermissionLevel": int(permissionLevelWrite),
			"LocationType":    int(locationType),
			"PermissionType":  int(permType),
		})
		f = f.WithOutcome(finding.OutcomeNegative)*/
	}
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