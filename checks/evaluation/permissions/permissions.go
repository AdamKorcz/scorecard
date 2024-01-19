// Copyright 2021 OpenSSF Scorecard Authors
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

package evaluation

import (
	"fmt"
	//"strings"

	"github.com/ossf/scorecard/v4/checker"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/hasGithubWorkflowPermissionNone"
	"github.com/ossf/scorecard/v4/probes/hasGithubWorkflowPermissionRead"
	"github.com/ossf/scorecard/v4/probes/hasGithubWorkflowPermissionUndeclared"
	"github.com/ossf/scorecard/v4/probes/hasGithubWorkflowPermissionUnknown"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteActionsRun"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteActionsTop"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteAllRun"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteAllTop"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteChecksTop"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteContentsRun"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteContentsTop"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteDeploymentsTop"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWritePackagesRun"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWritePackagesTop"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteSecurityEventsRun"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteSecurityEventsTop"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteStatusesTop"
	"github.com/ossf/scorecard/v4/probes/hasNoGithubWorkflowsWithUndeclaredPermissionsJob"
	"github.com/ossf/scorecard/v4/probes/hasNoGithubWorkflowsWithUndeclaredPermissionsTop"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteChecksJob"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteDeploymentsJob"
	"github.com/ossf/scorecard/v4/probes/hasNoGitHubWorkflowPermissionWriteStatusesJob"
	//"github.com/ossf/scorecard/v4/remediation"
)

// TokenPermissions applies the score policy for the Token-Permissions check.
func TokenPermissions(name string,
	findings []finding.Finding,
	dl checker.DetailLogger,
) checker.CheckResult {
	expectedProbes := []string{
		hasNoGitHubWorkflowPermissionWriteActionsTop.Probe,
		hasNoGitHubWorkflowPermissionWriteAllTop.Probe,
		hasNoGitHubWorkflowPermissionWriteChecksTop.Probe,
		hasNoGitHubWorkflowPermissionWriteContentsTop.Probe,
		hasNoGitHubWorkflowPermissionWriteDeploymentsTop.Probe,
		hasNoGitHubWorkflowPermissionWritePackagesTop.Probe,
		hasNoGitHubWorkflowPermissionWriteSecurityEventsTop.Probe,
		hasNoGitHubWorkflowPermissionWriteStatusesTop.Probe,
		hasGithubWorkflowPermissionUnknown.Probe,
		hasGithubWorkflowPermissionNone.Probe,
		hasGithubWorkflowPermissionRead.Probe,
		hasGithubWorkflowPermissionUndeclared.Probe,
		hasNoGitHubWorkflowPermissionWriteAllRun.Probe,
		hasNoGitHubWorkflowPermissionWriteSecurityEventsRun.Probe,
		hasNoGitHubWorkflowPermissionWriteActionsRun.Probe,
		hasNoGitHubWorkflowPermissionWriteContentsRun.Probe,
		hasNoGitHubWorkflowPermissionWritePackagesRun.Probe,
		hasNoGithubWorkflowsWithUndeclaredPermissionsJob.Probe,
		hasNoGithubWorkflowsWithUndeclaredPermissionsTop.Probe,
		hasNoGitHubWorkflowPermissionWriteChecksJob.Probe,
		hasNoGitHubWorkflowPermissionWriteDeploymentsJob.Probe,
		hasNoGitHubWorkflowPermissionWriteStatusesJob.Probe,
	}
	if !finding.UniqueProbesEqual(findings, expectedProbes) {
		e := sce.WithMessage(sce.ErrScorecardInternal, "invalid probe results")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	// Start with a perfect score.
	score := float32(checker.MaxResultScore)

	//foundWritePermissions := false
	hasWriteAllAtTopLevel := false
	hasWriteAllAtJobLevel := false
	undeclaredPermissions := make(map[string]map[string]bool)
	undeclaredPermissions["jobLevel"] = make(map[string]bool)
	undeclaredPermissions["topLevel"] = make(map[string]bool)
	//hasUndeclaredJobLevelPermissions := false
	//hasUndeclaredTopLevelPermissions := false

	for i := range findings {
		f := &findings[i]	

		if f.Probe == hasGithubWorkflowPermissionUndeclared.Probe {
			switch f.Outcome {
			case finding.OutcomeNotAvailable:
				return checker.CreateResultWithScore(name,
					"detected GitHub workflow tokens with excessive permissions", checker.InconclusiveResultScore)
			case finding.OutcomeNotApplicable:
				// We warn only for top-level.
				dl.Debug(&checker.LogMessage{
					Finding: f,
				})
			}
		}

		// If there are no TokenPermissions
		if f.Outcome == finding.OutcomeNotAvailable {
			return checker.CreateResultWithScore(name,
					"No tokens found", checker.InconclusiveResultScore)
		}

		if f.Outcome != finding.OutcomeNegative {
			continue
		}
		if _, ok := undeclaredPermissions["jobLevel"][f.Location.Path]; !ok {
			undeclaredPermissions["jobLevel"][f.Location.Path] = false
		}
		if _, ok := undeclaredPermissions["topLevel"][f.Location.Path]; !ok {
			undeclaredPermissions["topLevel"][f.Location.Path] = false
		}
		//fmt.Println("negative probe", f.Probe)
		switch f.Probe {
		case hasGithubWorkflowPermissionUndeclared.Probe:
			if f.Values["jobLevel"] == 1 {
				dl.Debug(&checker.LogMessage{
					Finding: f,
				})
				//hasUndeclaredJobLevelPermissions = true
				undeclaredPermissions["jobLevel"][f.Location.Path] = true
				if hasWriteAllAtTopLevel || undeclaredPermissions["topLevel"][f.Location.Path] {
					score = checker.MinResultScore
				}
			} else if f.Values["topLevel"] == 1 {
				dl.Warn(&checker.LogMessage{
					Finding: f,
				})
				//hasUndeclaredTopLevelPermissions = true
				undeclaredPermissions["topLevel"][f.Location.Path] = true
				if undeclaredPermissions["jobLevel"][f.Location.Path] {
					score = checker.MinResultScore
				} else {
					score -= 0.5
				}
			}
		case hasGithubWorkflowPermissionNone.Probe, hasGithubWorkflowPermissionRead.Probe:
			dl.Info(&checker.LogMessage{
				Finding: f,
			})
		case hasGithubWorkflowPermissionUnknown.Probe:
			dl.Debug(&checker.LogMessage{
				Finding: f,
			})
		case hasNoGitHubWorkflowPermissionWriteActionsTop.Probe:
			dl.Warn(&checker.LogMessage{
				Finding: f,
			})
			score -= checker.MaxResultScore
		case hasNoGitHubWorkflowPermissionWriteAllTop.Probe:
			dl.Warn(&checker.LogMessage{
				Finding: f,
			})
			hasWriteAllAtTopLevel = true
			if hasWriteAllAtJobLevel || undeclaredPermissions["jobLevel"][f.Location.Path] {
				return checker.CreateResultWithScore(name,
					"detected GitHub workflow tokens with excessive permissions", checker.MinResultScore)
			}
			// If no top level permissions are defined, all the permissions
			// are enabled by default. In this case,
			/*if permissionIsPresentInRunLevel(perms, "all") {
				// ... give lowest score if no run level permissions are defined either.
				return checker.MinResultScore
			}*/
			// ... reduce score if run level permissions are defined.
			score -= 0.5
		case hasNoGitHubWorkflowPermissionWriteChecksTop.Probe:
			dl.Warn(&checker.LogMessage{
				Finding: f,
			})
			score -= 0.5
		case hasNoGitHubWorkflowPermissionWriteContentsTop.Probe:
			dl.Warn(&checker.LogMessage{
				Finding: f,
			})
			score -= checker.MaxResultScore
		case hasNoGitHubWorkflowPermissionWriteDeploymentsTop.Probe:
			dl.Warn(&checker.LogMessage{
				Finding: f,
			})
			score--
		case hasNoGitHubWorkflowPermissionWritePackagesTop.Probe:
			dl.Warn(&checker.LogMessage{
				Finding: f,
			})
			score -= checker.MaxResultScore
		case hasNoGitHubWorkflowPermissionWriteSecurityEventsTop.Probe:
			dl.Warn(&checker.LogMessage{
				Finding: f,
			})
			score--
		case hasNoGitHubWorkflowPermissionWriteStatusesTop.Probe:
			dl.Warn(&checker.LogMessage{
				Finding: f,
			})
			score -= 0.5
		case hasNoGitHubWorkflowPermissionWriteAllRun.Probe:
			dl.Warn(&checker.LogMessage{
				Finding: f,
			})
			hasWriteAllAtJobLevel = true
			if hasWriteAllAtTopLevel {
				score = checker.MinResultScore
				break
			}
			if undeclaredPermissions["topLevel"][f.Location.Path] {
				score -= 0.5
			}
		case hasNoGitHubWorkflowPermissionWriteStatusesJob.Probe,
		 hasNoGitHubWorkflowPermissionWriteDeploymentsJob.Probe,
		 hasNoGitHubWorkflowPermissionWriteSecurityEventsRun.Probe,
		 hasNoGitHubWorkflowPermissionWriteActionsRun.Probe,
		 hasNoGitHubWorkflowPermissionWriteContentsRun.Probe,
		 hasNoGitHubWorkflowPermissionWritePackagesRun.Probe,
		 hasNoGitHubWorkflowPermissionWriteChecksJob.Probe:
			dl.Warn(&checker.LogMessage{
				Finding: f,
			})
			hasWriteAllAtJobLevel = true
		}
	}
	if score < checker.MinResultScore {
		score = checker.MinResultScore
	}
	if !hasWriteAllAtJobLevel {
		text := fmt.Sprintf("no %s write permissions found", checker.PermissionLocationJob)
		dl.Info(&checker.LogMessage{
			Text: text,
		})
	}
	if score != checker.MaxResultScore {
		return checker.CreateResultWithScore(name,
			"detected GitHub workflow tokens with excessive permissions", int(score))
	}

	return checker.CreateMaxScoreResult(name,
		"GitHub workflow tokens follow principle of least privilege")
}
