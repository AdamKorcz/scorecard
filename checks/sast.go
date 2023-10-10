// Copyright 2020 OpenSSF Scorecard Authors
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

package checks

import (
	"errors"
	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/checks/evaluation"
	"github.com/ossf/scorecard/v4/checks/raw"
	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/probes"
	"github.com/ossf/scorecard/v4/probes/zrunner"
)

// CheckSAST is the registered name for SAST.
const CheckSAST = "SAST"

var errInvalid = errors.New("invalid")

var sastTools = map[string]bool{
	"github-advanced-security": true,
	"github-code-scanning":     true,
	"lgtm-com":                 true,
	"sonarcloud":               true,
}

var allowedConclusions = map[string]bool{"success": true, "neutral": true}

//nolint:gochecknoinits
func init() {
	if err := registerCheck(CheckSAST, SAST, nil); err != nil {
		// This should never happen.
		panic(err)
	}
}

// SAST runs SAST check.
func SAST(c *checker.CheckRequest) checker.CheckResult {
	rawData, err := raw.SAST(c)
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckSAST, e)
	}

	// Set the raw results.
	pRawResults := getRawResults(c)
	pRawResults.SASTResults = rawData

	// Evaluate the probes.
	findings, err := zrunner.Run(pRawResults, probes.SAST)
	if err != nil {
		e := sce.WithMessage(sce.ErrScorecardInternal, err.Error())
		return checker.CreateRuntimeErrorResult(CheckSAST, e)
	}

	// Return the score evaluation.
	return evaluation.SAST(CheckSAST, findings, c.Dlogger)
}
