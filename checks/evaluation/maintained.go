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

	"github.com/ossf/scorecard/v4/checker"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/activityOnIssuesByCollaboratorsMembersOrOwnersInLast90Days"
	"github.com/ossf/scorecard/v4/probes/commitsInLast90Days"
	"github.com/ossf/scorecard/v4/probes/commitsInLast90Days"
	"github.com/ossf/scorecard/v4/probes/notArchived"
	"github.com/ossf/scorecard/v4/probes/wasCreatedInLast90Days"
)

const (
	lookBackDays    = 90
	activityPerWeek = 1
	daysInOneWeek   = 7
)

// Maintained applies the score policy for the Maintained check.
func Maintained(name string,
	findings []finding.Finding, dl checker.DetailLogger,
) checker.CheckResult {
	// We have 4 unique probes, each should have a finding.
	expectedProbes := []string{
		notArchived.Probe,
		activityOnIssuesByCollaboratorsMembersOrOwnersInLast90Days.Probe,
		commitsInLast90Days.Probe,
		wasCreatedInLast90Days.Probe,
	}

	if !finding.UniqueProbesEqual(findings, expectedProbes) {
		e := sce.WithMessage(sce.ErrScorecardInternal, "invalid probe results")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	if projectIsArchived(findings) {
		checker.LogFindings(negativeFindings(findings), dl)
		return checker.CreateMinScoreResult(name, "project is archived")
	}

	if projectWasCreatedInLast90Days(findings) {
		checker.LogFindings(nonPositiveFindings(findings), dl)
		return checker.CreateMinScoreResult(name, "project was created in last 90 days. please review its contents carefully")
	}

	commitsWithinThreshold := 0
	issuesUpdatedWithinThreshold := 0

	for i := range findings {
		f := &findings[i]
		if f.Outcome == finding.OutcomePositive {
			switch f.Probe {
			case activityOnIssuesByCollaboratorsMembersOrOwnersInLast90Days.Probe:
				issuesUpdatedWithinThreshold++
			case commitsInLast90Days.Probe:
				commitsWithinThreshold++
			}
		}
	}

	return checker.CreateProportionalScoreResult(name, fmt.Sprintf(
		"%d commit(s) and %d issue activity found in the last %d days",
		commitsWithinThreshold, issuesUpdatedWithinThreshold, lookBackDays),
		commitsWithinThreshold+issuesUpdatedWithinThreshold, activityPerWeek*lookBackDays/daysInOneWeek)
}

func projectIsArchived(findings []finding.Finding) bool {
	for i := range findings {
		f := &findings[i]
		if f.Outcome == finding.OutcomeNegative {
			if f.Probe == notArchived.Probe {
				return true
			}
		}
	}
	return false
}

func projectWasCreatedInLast90Days(findings []finding.Finding) bool {
	for i := range findings {
		f := &findings[i]
		if f.Outcome == finding.OutcomeNegative {
			if f.Probe == wasCreatedInLast90Days.Probe {
				return true
			}
		}
	}
	return false
}
