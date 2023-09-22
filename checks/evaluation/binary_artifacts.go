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
	"github.com/ossf/scorecard/v4/checker"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/hasBinaryArtifacts"
)

// BinaryArtifacts applies the score policy for the Binary-Artifacts check.
func BinaryArtifacts(name string,
	findings []finding.Finding,
	dl checker.DetailLogger,
) checker.CheckResult {
	expectedProbes := []string{
		hasBinaryArtifacts.Probe,
	}

	err := validateFindings(findings, expectedProbes)
	if err != nil {
		return checker.CreateRuntimeErrorResult(name, err)
	}

	if findings[0].Outcome == finding.OutcomePositive {
		return checker.CreateMaxScoreResult(name, "no binaries found in the repo")
	}

	// There are only negative findings.
	// Deduct the number of findings from max score
	numberOfBinaryFilesFound := len(findings)

	score := checker.MaxResultScore - numberOfBinaryFilesFound

	if score < checker.MinResultScore {
		score = checker.MinResultScore
	}

	return checker.CreateResultWithScore(name, "binaries present in source code", score)
}

func validateFindings(findings []finding.Finding, expectedProbes []string) error {
	if !finding.UniqueProbesEqual(findings, expectedProbes) {
		return sce.WithMessage(sce.ErrScorecardInternal, "invalid probe results")
	}

	if len(findings) == 0 {
		return sce.WithMessage(sce.ErrScorecardInternal, "found 0 findings. Should not happen")
	}
	return nil
}
