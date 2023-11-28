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
	"github.com/ossf/scorecard/v4/probes/webhooksWithoutTokenAuth"
)

// Webhooks applies the score policy for the Webhooks check.
func Webhooks(name string,
	findings []finding.Finding, dl checker.DetailLogger,
) checker.CheckResult {
	expectedProbes := []string{
		webhooksWithoutTokenAuth.Probe,
	}

	if !finding.UniqueProbesEqual(findings, expectedProbes) {
		e := sce.WithMessage(sce.ErrScorecardInternal, "invalid probe results")
		return checker.CreateRuntimeErrorResult(name, e)
	}

	if len(findings) == 1 && findings[0].Outcome == finding.OutcomeNotApplicable {
		return checker.CreateMaxScoreResult(name, "project does not have webhook")
	}

	var webhooksWithoutSecret int

	totalWebhooks := findings[0].Values["totalWebhooks"]

	for i := range findings {
		f := &findings[i]
		if f.Outcome == finding.OutcomeNegative {
			webhooksWithoutSecret++
		}
	}

	if totalWebhooks == webhooksWithoutSecret {
		return checker.CreateMinScoreResult(name, "no hook(s) have a secret configured")
	}

	if webhooksWithoutSecret == 0 {
		msg := fmt.Sprintf("All %d of the projects webhooks are configure with a secret", totalWebhooks)
		return checker.CreateMaxScoreResult(name, msg)
	}

	msg := fmt.Sprintf("%d out of the projects %d webhooks are configure without a secret",
		webhooksWithoutSecret,
		totalWebhooks)

	return checker.CreateProportionalScoreResult(name,
		msg, totalWebhooks-webhooksWithoutSecret, totalWebhooks)
}
