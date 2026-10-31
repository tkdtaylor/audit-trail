// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"strings"
	"testing"
)

// TC-021-01: docs/ROADMAP.md marks log rotation and indexed query API as complete (✅)
// and neither entry marks the capability as "not started".
func TestTC021_01_RoadmapMarksRotationAndQueryComplete(t *testing.T) {
	data, err := os.ReadFile("docs/ROADMAP.md")
	if err != nil {
		t.Fatalf("failed to read docs/ROADMAP.md: %v", err)
	}
	content := string(data)

	// Check table rows line by line for log rotation and indexed query API.
	lines := strings.Split(content, "\n")
	var foundRotation, foundQuery bool

	for _, line := range lines {
		if strings.Contains(line, "**Log rotation / checkpointing**") {
			foundRotation = true
			if !strings.Contains(line, "✅") {
				t.Errorf("expected Log rotation row in docs/ROADMAP.md to contain ✅, got: %s", line)
			}
			if strings.Contains(strings.ToLower(line), "not started") {
				t.Errorf("expected Log rotation row in docs/ROADMAP.md not to say 'not started', got: %s", line)
			}
			if !strings.Contains(line, "014") || !strings.Contains(line, "018") {
				t.Errorf("expected Log rotation row in docs/ROADMAP.md to reference tasks 014-018, got: %s", line)
			}
		}

		if strings.Contains(line, "**Indexed query API**") {
			foundQuery = true
			if !strings.Contains(line, "✅") {
				t.Errorf("expected Indexed query API row in docs/ROADMAP.md to contain ✅, got: %s", line)
			}
			if strings.Contains(strings.ToLower(line), "not started") {
				t.Errorf("expected Indexed query API row in docs/ROADMAP.md not to say 'not started', got: %s", line)
			}
			if !strings.Contains(line, "020") {
				t.Errorf("expected Indexed query API row in docs/ROADMAP.md to reference task 020, got: %s", line)
			}
		}
	}

	if !foundRotation {
		t.Error("did not find Log rotation row in docs/ROADMAP.md table")
	}
	if !foundQuery {
		t.Error("did not find Indexed query API row in docs/ROADMAP.md table")
	}

	// Verify the dependency diagram also reflects completion.
	if !strings.Contains(content, "log rotation / checkpointing ✅") {
		t.Error("expected dependency diagram in docs/ROADMAP.md to mark log rotation as ✅")
	}
	if !strings.Contains(content, "indexed query API ✅") {
		t.Error("expected dependency diagram in docs/ROADMAP.md to mark indexed query API as ✅")
	}
}

// TC-021-02: docs/spec/SPEC.md records log rotation and indexed query API as completed (✅)
// and neither entry marks the capability as "not started".
func TestTC021_02_SpecMarksRotationAndQueryComplete(t *testing.T) {
	data, err := os.ReadFile("docs/spec/SPEC.md")
	if err != nil {
		t.Fatalf("failed to read docs/spec/SPEC.md: %v", err)
	}
	content := string(data)

	lines := strings.Split(content, "\n")
	var foundRotation, foundQuery bool

	for _, line := range lines {
		if strings.Contains(line, "Log rotation / checkpointing") {
			foundRotation = true
			if !strings.Contains(line, "✅") {
				t.Errorf("expected Log rotation row in docs/spec/SPEC.md to contain ✅, got: %s", line)
			}
			if strings.Contains(strings.ToLower(line), "not started") {
				t.Errorf("expected Log rotation row in docs/spec/SPEC.md not to say 'not started', got: %s", line)
			}
		}

		if strings.Contains(line, "Indexed query API") {
			foundQuery = true
			if !strings.Contains(line, "✅") {
				t.Errorf("expected Indexed query API row in docs/spec/SPEC.md to contain ✅, got: %s", line)
			}
			if strings.Contains(strings.ToLower(line), "not started") {
				t.Errorf("expected Indexed query API row in docs/spec/SPEC.md not to say 'not started', got: %s", line)
			}
		}
	}

	if !foundRotation {
		t.Error("did not find Log rotation entry in docs/spec/SPEC.md")
	}
	if !foundQuery {
		t.Error("did not find Indexed query API entry in docs/spec/SPEC.md")
	}

	// Ensure no stale references to rotation or query being unstarted remain in SPEC.md.
	for i, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "not started") || strings.Contains(lower, "not (yet)") {
			if strings.Contains(lower, "rotation") || strings.Contains(lower, "query") {
				t.Errorf("stale unstarted reference on line %d of docs/spec/SPEC.md: %s", i+1, line)
			}
		}
	}
}

// TC-021-03: Full test and fitness suite passes, and task 021 artifacts and coverage tracking are consistent.
func TestTC021_03_SuiteConsistency(t *testing.T) {
	// Verify test spec exists and contains TC-021 identifiers.
	specData, err := os.ReadFile("docs/tasks/test-specs/021-reconcile-roadmap-and-spec-drift-test-spec.md")
	if err != nil {
		t.Fatalf("failed to read test spec: %v", err)
	}
	specContent := string(specData)
	for _, tc := range []string{"TC-021-01", "TC-021-02", "TC-021-03"} {
		if !strings.Contains(specContent, tc) {
			t.Errorf("expected test spec to contain %s", tc)
		}
	}

	// Verify task file exists (either in backlog during dev or in completed when finished).
	_, errBacklog := os.Stat("docs/tasks/backlog/021-reconcile-roadmap-and-spec-drift.md")
	_, errCompleted := os.Stat("docs/tasks/completed/021-reconcile-roadmap-and-spec-drift.md")
	if os.IsNotExist(errBacklog) && os.IsNotExist(errCompleted) {
		t.Errorf("expected task 021 file to exist in backlog/ or completed/")
	}

	// Verify coverage tracker has an entry for task 021.
	trackerData, err := os.ReadFile("docs/tasks/test-specs/coverage-tracker.md")
	if err != nil {
		t.Fatalf("failed to read coverage tracker: %v", err)
	}
	if !strings.Contains(string(trackerData), "021") {
		t.Error("expected docs/tasks/test-specs/coverage-tracker.md to contain an entry for task 021")
	}
}
