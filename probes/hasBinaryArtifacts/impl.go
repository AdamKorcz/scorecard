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
package hasBinaryArtifacts

import (
	"embed"
	"fmt"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/internal/utils/uerror"
)

//go:embed *.yml
var fs embed.FS

const Probe = "hasBinaryArtifacts"

func Run(raw *checker.RawResults) ([]finding.Finding, string, error) {
	if raw == nil {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	r := raw.BinaryArtifactResults

	// Apply the policy evaluation.
	if r.Files == nil || len(r.Files) == 0 {
		return positiveOutcome()
	}

	var findings []finding.Finding

	for range r.Files {
		f, err := finding.NewWith(fs, Probe, "binary artifact detected",
			nil, finding.OutcomeNegative)
		if err != nil {
			return nil, Probe, fmt.Errorf("create finding: %w", err)
		}
		findings = append(findings, *f)
	}

	if len(findings) == 0 {
		return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
	}

	// Check if there are both positive and negative outcomes.
	// This should not happen.
	for i := range findings {
		f := &findings[i]
		if f.Outcome == finding.OutcomePositive {
			return nil, "", fmt.Errorf("%w: raw", uerror.ErrNil)
		}
	}

	return findings, Probe, nil
}

func positiveOutcome() ([]finding.Finding, string, error) {
	f, err := finding.NewWith(fs, Probe,
		"Repository does not have binary artifacts.", nil,
		finding.OutcomePositive)
	if err != nil {
		return nil, Probe, fmt.Errorf("create finding: %w", err)
	}
	return []finding.Finding{*f}, Probe, nil
}
