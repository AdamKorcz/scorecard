// Copyright 2023 OpenSSF Scorecard Authors
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

// nolint:stylecheck
package pinsDependencies

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/internal/utils/uerror"
	"github.com/ossf/scorecard/v4/remediation"
	"github.com/ossf/scorecard/v4/checks/fileparser"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/rule"
)

//go:embed *.yml
var fs embed.FS

const Probe = "pinsDependencies"

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	if raw == nil {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	r := raw.PinningDependenciesResults
	var findings []finding.Finding


	//nolint:errcheck
	remediationMetadata, _ := remediation.New(nil)

	for i := range r.Dependencies {
		rr := r.Dependencies[i]
		if rr.Location == nil {
			if rr.Msg == nil {
				e := sce.WithMessage(sce.ErrScorecardInternal, "empty File field")
				return nil, Probe, fmt.Errorf("create finding: %w", e)
			}
			continue
		}
		if rr.Pinned != nil {
			if !*rr.Pinned {
				location := &finding.Location{
					Type: rr.Location.Type,
					Path: rr.Location.Path,
					LineStart: &rr.Location.Offset,
					LineEnd: &rr.Location.EndOffset,
					Snippet: &rr.Location.Snippet,
				}

				f, err := finding.NewWith(fs, Probe,
				generateText(&rr), location,
					finding.OutcomeNegative)
				if err != nil {
					return nil, Probe, fmt.Errorf("create finding: %w", err)
				}
				rem := generateRemediation(remediationMetadata, &rr)
				fmt.Println("rem: ", rem)
				f = f.WithRemediationMetadata(map[string]string {
					"patch": *rem.Patch,
					"text": rem.Text,
					"markdown": rem.Markdown,
					"effort": fmt.Sprintf("%d", rem.Effort),
				})
				findings = append(findings, *f)
			} else {
				location := &finding.Location{
					Type: rr.Location.Type,
					Path: rr.Location.Path,
					LineStart: &rr.Location.Offset,
					LineEnd: &rr.Location.EndOffset,
					Snippet: &rr.Location.Snippet,
				}

				f, err := finding.NewWith(fs, Probe,
				"dependency is pinned by hash", location,
					finding.OutcomePositive)
				if err != nil {
					return nil, Probe, fmt.Errorf("create finding: %w", err)
				}
				findings = append(findings, *f)
			}
		}
	}
	return findings, Probe, nil
}

func generateRemediation(remediationMd *remediation.RemediationMetadata, rr *checker.Dependency) *rule.Remediation {
	switch rr.Type {
	case checker.DependencyUseTypeGHAction:
		return remediationMd.CreateWorkflowPinningRemediation(rr.Location.Path)
	case checker.DependencyUseTypeDockerfileContainerImage:
		fmt.Println("HERE")
		return remediation.CreateDockerfilePinningRemediation(rr, remediation.CraneDigester{})
	default:
		return nil
	}
}
func generateText(rr *checker.Dependency) string {
	if rr.Type == checker.DependencyUseTypeGHAction {
		// Check if we are dealing with a GitHub action or a third-party one.
		gitHubOwned := fileparser.IsGitHubOwnedAction(rr.Location.Snippet)
		owner := generateOwnerToDisplay(gitHubOwned)
		return fmt.Sprintf("%s not pinned by hash", owner)
	}

	return fmt.Sprintf("%s not pinned by hash", rr.Type)
}

func generateOwnerToDisplay(gitHubOwned bool) string {
	if gitHubOwned {
		return fmt.Sprintf("GitHub-owned %s", checker.DependencyUseTypeGHAction)
	}
	return fmt.Sprintf("third-party %s", checker.DependencyUseTypeGHAction)
}