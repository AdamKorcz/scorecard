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
package commitsInLast90Days

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/clients"
	"github.com/ossf/scorecard/v4/finding"
)

func Test_Run(t *testing.T) {
	t.Parallel()
	fiveCommitsInThreshold := make([]clients.Commit, 0)
	for i := 0; i < 5; i++ {
		commit := clients.Commit{
			CommittedDate: time.Now().AddDate(0 /*years*/, 0 /*months*/, -1*i /*days*/),
		}
		fiveCommitsInThreshold = append(fiveCommitsInThreshold, commit)
	}
	twentyCommitsInThresholdAndtwentyNot := make([]clients.Commit, 0)
	for i := 70; i < 111; i++ {
		commit := clients.Commit{
			CommittedDate: time.Now().AddDate(0 /*years*/, 0 /*months*/, -1*i /*days*/),
		}
		twentyCommitsInThresholdAndtwentyNot = append(twentyCommitsInThresholdAndtwentyNot, commit)
	}

	fivePositiveOutcome := make([]finding.Outcome, 0)
	for i := 0; i < 5; i++ {
		fivePositiveOutcome = append(fivePositiveOutcome, finding.OutcomePositive)
	}

	twentyPositiveOutcomes := make([]finding.Outcome, 0)
	for i := 0; i < 20; i++ {
		twentyPositiveOutcomes = append(twentyPositiveOutcomes, finding.OutcomePositive)
	}

	// nolint:govet
	tests := []struct {
		name     string
		raw      *checker.RawResults
		outcomes []finding.Outcome
		err      error
	}{
		{
			name: "Has five commits in threshold",
			raw: &checker.RawResults{
				MaintainedResults: checker.MaintainedData{
					DefaultBranchCommits: fiveCommitsInThreshold,
				},
			},
			outcomes: fivePositiveOutcome,
		},
		{
			name: "Has twenty in threshold",
			raw: &checker.RawResults{
				MaintainedResults: checker.MaintainedData{
					DefaultBranchCommits: twentyCommitsInThresholdAndtwentyNot,
				},
			},
			outcomes: twentyPositiveOutcomes,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings, s, err := Run(tt.raw)
			if !cmp.Equal(tt.err, err, cmpopts.EquateErrors()) {
				t.Errorf("mismatch (-want +got):\n%s", cmp.Diff(tt.err, err, cmpopts.EquateErrors()))
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(Probe, s); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(len(tt.outcomes), len(findings)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
			for i := range tt.outcomes {
				outcome := &tt.outcomes[i]
				f := &findings[i]
				if diff := cmp.Diff(*outcome, f.Outcome); diff != "" {
					t.Errorf("mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
