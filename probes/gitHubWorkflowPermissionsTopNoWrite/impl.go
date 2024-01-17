// Copyright 2024 OpenSSF Scorecard Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//nolint:stylecheck
package gitHubWorkflowPermissionsTopNoWrite

/*import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/internal/utils/uerror"
	"github.com/ossf/scorecard/v4/probes/internal/utils/permissions"
)

//go:embed *.yml
var fs embed.FS

const Probe = "gitHubWorkflowPermissionsTopNoWrite"

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	if raw == nil {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	results := raw.TokenPermissionsResults
	var findings []finding.Finding

	if r.NumTokens == 0 {
		f, err := finding.NewWith(fs, Probe,
			"no tokens found", loc, finding.OutcomeNotAvailable)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
		return findings, Probe, nil
	}

	for _, r := range results.TokenPermissions {
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
		}
		text, err := permissions.CreateText(r)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		f, err := finding.NewWith(fs, Probe,
			text,
			loc, finding.OutcomeNegative)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}

		if loc != nil && loc.Path != "" {
			f = f.WithRemediationMetadata(map[string]string{
				"repo":     r.Remediation.Repo,
				"branch":   r.Remediation.Branch,
				"workflow": strings.TrimPrefix(f.Location.Path, ".github/workflows/"),
			})
		}

		permissions.SetOutcomeAndLocation(r, f)
		findings = append(findings, *f)

	}
	return findings, Probe, nil
}

// avoid memory aliasing by returning a new copy.
func newUint(u uint) *uint {
	return &u
}

// avoid memory aliasing by returning a new copy.
func newStr(s string) *string {
	return &s
}*/
