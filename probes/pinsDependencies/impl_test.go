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
package pinsDependencies

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/ossf/scorecard/v4/checker"
	"github.com/ossf/scorecard/v4/finding"
)

func asPointer(s string) *string {
	return &s
}

func asBoolPointer(b bool) *bool {
	return &b
}

func Test_Run(t *testing.T) {
	t.Parallel()
	// nolint:govet
	tests := []struct {
		name     string
		raw      *checker.RawResults
		outcomes []finding.Outcome
		err      error
	}{
		{
			name: "debug msg is nil",
			raw: &checker.RawResults{
				PinningDependenciesResults: checker.PinningDependenciesData{
					Dependencies: []checker.Dependency{
						{
							Location: &checker.File{
								Snippet: "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
							},
							Type:   checker.DependencyUseTypeGHAction,
							Pinned: asBoolPointer(true),
						},
					},
				},
			},
			outcomes: []finding.Outcome{
				finding.OutcomePositive,
			},
		},
		{
			name: "debug msg is nil",
			raw: &checker.RawResults{
				PinningDependenciesResults: checker.PinningDependenciesData{
					Dependencies: []checker.Dependency{
						{
							Location: &checker.File{
								Snippet: "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
							},
							Type:   checker.DependencyUseTypeGHAction,
							Pinned: asBoolPointer(true),
						},
						{
							Location: &checker.File{
								Snippet: "other/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
							},
							Type:   checker.DependencyUseTypeGHAction,
							Pinned: asBoolPointer(true),
						},
						{
							Location: &checker.File{},
							Type:     checker.DependencyUseTypeDockerfileContainerImage,
							Pinned:   asBoolPointer(true),
						},
						{
							Location: &checker.File{},
							Type:     checker.DependencyUseTypeDownloadThenRun,
							Pinned:   asBoolPointer(true),
						},
						{
							Location: &checker.File{},
							Type:     checker.DependencyUseTypeGoCommand,
							Pinned:   asBoolPointer(true),
						},
						{
							Location: &checker.File{},
							Type:     checker.DependencyUseTypeNpmCommand,
							Pinned:   asBoolPointer(true),
						},
						{
							Location: &checker.File{},
							Type:     checker.DependencyUseTypePipCommand,
							Pinned:   asBoolPointer(true),
						},
					},
				},
			},
			outcomes: []finding.Outcome{
				finding.OutcomePositive,
				finding.OutcomePositive,
				finding.OutcomePositive,
				finding.OutcomePositive,
				finding.OutcomePositive,
				finding.OutcomePositive,
				finding.OutcomePositive,
			},
		},
		{
			name: "debug msg is nil",
			raw: &checker.RawResults{
				PinningDependenciesResults: checker.PinningDependenciesData{
					Dependencies: []checker.Dependency{
						{
							Location: &checker.File{
								Snippet: "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
							},
							Type:   checker.DependencyUseTypeGHAction,
							Pinned: asBoolPointer(true),
						},
						{
							Location: &checker.File{
								Snippet: "other/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
							},
							Type:   checker.DependencyUseTypeGHAction,
							Pinned: asBoolPointer(true),
						},
						{
							Location: &checker.File{},
							Type:     checker.DependencyUseTypeDockerfileContainerImage,
							Pinned:   asBoolPointer(false),
							Name: asPointer("foo@sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"),
						},
						{
							Location: &checker.File{},
							Type:     checker.DependencyUseTypeDownloadThenRun,
							Pinned:   asBoolPointer(true),
						},
						{
							Location: &checker.File{},
							Type:     checker.DependencyUseTypeGoCommand,
							Pinned:   asBoolPointer(true),
						},
						{
							Location: &checker.File{},
							Type:     checker.DependencyUseTypeNpmCommand,
							Pinned:   asBoolPointer(true),
						},
						{
							Location: &checker.File{},
							Type:     checker.DependencyUseTypePipCommand,
							Pinned:   asBoolPointer(true),
						},
					},
				},
			},
			outcomes: []finding.Outcome{
				finding.OutcomePositive,
				finding.OutcomePositive,
				finding.OutcomePositive,
				finding.OutcomePositive,
				finding.OutcomePositive,
				finding.OutcomePositive,
				finding.OutcomePositive,
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
