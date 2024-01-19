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

//nolint:stylecheck
package hasGithubWorkflowPermissionRead

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/internal/utils/permissions"
	"github.com/ossf/scorecard/v4/probes/internal/utils/test"
)

func Test_Run(t *testing.T) {
	t.Parallel()
	tests := []permissions.TestData {
		{
			Name: "No Tokens",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 0,
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
		{
			Name: "Correct permission level",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							Type:         checker.PermissionLevelRead,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomeNegative,
			},
		},
		{
			Name: "Incorrect permission level",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							Type:         checker.PermissionLevelUnknown,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			findings, s, err := Run(tt.Raw)
			if !cmp.Equal(tt.Err, err, cmpopts.EquateErrors()) {
				t.Errorf("mismatch (-want +got):\n%s", cmp.Diff(tt.Err, err, cmpopts.EquateErrors()))
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(Probe, s); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
			test.AssertOutcomes(t, findings, tt.Outcomes)
		})
	}
}