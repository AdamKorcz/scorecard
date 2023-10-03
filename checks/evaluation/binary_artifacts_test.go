// Copyright 2022 OpenSSF Scorecard Authors
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
	"testing"

	sce "github.com/ossf/scorecard/v4/errors"
	"github.com/ossf/scorecard/v4/finding"
	scut "github.com/ossf/scorecard/v4/utests"
)

// TestBinaryArtifacts tests the binary artifacts check.
func TestBinaryArtifacts(t *testing.T) {
	t.Parallel()
	//nolint:govet
	type args struct {
		name string
		dl   checker.DetailLogger
		r    *checker.BinaryArtifactData
	}
	tests := []struct {
		name     string
		findings     []finding.Finding
		result     scut.TestReturn
	}{
		{
			name: "no binary artifacts",
			findings: []finding.Finding {
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomePositive,
				},
			},
			result: scut.TestReturn{
				Score: 10,
			},
		},
		{
			name: "one binary artifact",
			findings: []finding.Finding {
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
			},
			result: scut.TestReturn{
				Score: 9,
			},
		},
		{
			name: "two binary artifact",
			findings: []finding.Finding {
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
			},
			result: scut.TestReturn{
				Score: 8,
			},
		},
		{
			name: "five binary artifact",
			findings: []finding.Finding {
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
			},
			result: scut.TestReturn{
				Score: 5,
			},
		},
		{
			name: "twelve binary artifact",
			findings: []finding.Finding {
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
				{
					Probe:   "hasBinaryArtifacts",
					Outcome: finding.OutcomeNegative,
				},
			},
			result: scut.TestReturn{
				Score: 0,
			},
		},
		{
			name: "invalid findings",
			findings: []finding.Finding {},
			result: scut.TestReturn{
				Score: -1,
				Error: sce.ErrScorecardInternal,
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dl := scut.TestDetailLogger{}
			got := BinaryArtifacts(tt.name, tt.findings, &dl)
			if !scut.ValidateTestReturn(t, tt.name, &tt.result, &got, &dl) {
				t.Errorf("got %v, expected %v", got, tt.result)
			}
		})
	}
}
