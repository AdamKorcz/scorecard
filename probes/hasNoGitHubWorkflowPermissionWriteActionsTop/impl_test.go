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
package hasNoGitHubWorkflowPermissionWriteActionsTop

/*
import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
	"github.com/ossf/scorecard/v4/probes/internal/utils/test"
)

func Test_Run(t *testing.T) {
	t.Parallel()
	name := "name"
	all := "all"
	value := "value"
	//msg := "msg"
	permLoc := checker.PermissionLocationTop
	//nolint:govet
	tests := []struct {
		name     string
		raw      *checker.RawResults
		outcomes []finding.Outcome
		err      error
	}{
		{
			name: "Read permission.",
			raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &permLoc,
							Name:         &name,
							Value:        &value,
							Msg:          nil,
							Type:         checker.PermissionLevelRead,
						},
					},
				},
			},
			outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
		{
			name: "Write permission",
			raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &permLoc,
							Name:         &name,
							Value:        &value,
							Msg:          nil,
							Type:         checker.PermissionLevelWrite,
						},
					},
				},
			},
			outcomes: []finding.Outcome{
				finding.OutcomeNegative,
			},
		},
		{
			name: "None permission",
			raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &permLoc,
							Name:         &name,
							Value:        &value,
							Msg:          nil,
							Type:         checker.PermissionLevelNone,
						},
					},
				},
			},
			outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
		{
			name: "Unknown permission",
			raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &permLoc,
							Name:         &name,
							Value:        &value,
							Msg:          nil,
							Type:         checker.PermissionLevelUnknown,
						},
					},
				},
			},
			outcomes: []finding.Outcome{
				finding.OutcomeError,
			},
		},
		{
			name: "Undeclared permission",
			raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &permLoc,
							Name:         &all,
							Value:        &value,
							Msg:          nil,
							Type:         checker.PermissionLevelUndeclared,
						},
					},
				},
			},
			outcomes: []finding.Outcome{
				finding.OutcomeNegative,
			},
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
			test.AssertOutcomes(t, findings, tt.outcomes)
		})
	}
}
*/
