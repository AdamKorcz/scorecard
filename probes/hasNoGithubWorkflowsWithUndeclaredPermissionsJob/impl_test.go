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
package hasNoGithubWorkflowsWithUndeclaredPermissionsJob

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/probes/internal/utils/test"
	"github.com/ossf/scorecard/v4/probes/internal/utils/permissions"
	"github.com/ossf/scorecard/v4/finding"
)

func Test_Run(t *testing.T) {
	t.Parallel()
	locationType := checker.PermissionLocationJob
	wrongName := "wrongName"
	name := "name"
	permissionType := checker.PermissionLevelUndeclared	
	var wrongPermissionLocation checker.PermissionLocation
	if locationType == checker.PermissionLocationTop {
		wrongPermissionLocation = checker.PermissionLocationJob
	} else {
		wrongPermissionLocation = checker.PermissionLocationTop
	}
	value := "value"

	tests := []permissions.TestData {
		{
			Name: "No Tokens",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 0,
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomeNotAvailable,
			},
		},
		{
			Name: "Invalid name - shouldn't affect the score",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &locationType,
							Name:         &wrongName,
							Value:        &value,
							Msg:          nil,
							Type:         permissionType,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomeNegative,
			},
		},
		{
			Name: "Correct name",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &locationType,
							Name:         &name,
							Value:        &value,
							Msg:          nil,
							Type:         permissionType,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomeNegative,
			},
		},
		{
			Name: "Two tokens",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 2,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &locationType,
							Name:         &name,
							Value:        &value,
							Msg:          nil,
							Type:         permissionType,
						},
						{
							LocationType: &locationType,
							Name:         &name,
							Value:        &value,
							Msg:          nil,
							Type:         permissionType,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomeNegative, finding.OutcomeNegative,
			},
		},
		{
			Name: "Value is nil - Everything else correct",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &locationType,
							Name:         &name,
							Value:        nil,
							Msg:          nil,
							Type:         permissionType,
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomeNegative,
			},
		},
		{
			Name: "Value is nil - Type is wrong",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &locationType,
							Name:         &name,
							Value:        nil,
							Msg:          nil,
							Type:         checker.PermissionLevel("999"),
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
		{
			Name: "Wrong locationType wrong type",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &wrongPermissionLocation,
							Name:         &name,
							Value:        nil,
							Msg:          nil,
							Type:         checker.PermissionLevel("999"),
						},
					},
				},
			},
			Outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
		{
			Name: "Wrong locationType correct type",
			Raw: &checker.RawResults{
				TokenPermissionsResults: checker.TokenPermissionsData{
					NumTokens: 1,
					TokenPermissions: []checker.TokenPermission {
						{
							LocationType: &wrongPermissionLocation,
							Name:         &name,
							Value:        nil,
							Msg:          nil,
							Type:         permissionType,
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
