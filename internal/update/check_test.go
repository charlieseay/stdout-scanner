package update

import "testing"

func TestIsNewer(t *testing.T) {
	tests := []struct {
		latest, current string
		want            bool
	}{
		{"v2.1.0", "v2.0.0", true},
		{"v2.0.1", "v2.0.0", true},
		{"v3.0.0", "v2.9.9", true},
		{"v2.0.0", "v2.0.0", false},
		{"v1.9.0", "v2.0.0", false},
		{"2.1.0", "2.0.0", true},     // No v prefix
		{"v2.1.0", "2.0.0", true},    // Mixed prefix
		{"v1.0.0-beta", "v0.9.0", true},
		{"v1.0.0", "v1.0.0-beta", false}, // Same base version
	}

	for _, tt := range tests {
		got := isNewer(tt.latest, tt.current)
		if got != tt.want {
			t.Errorf("isNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
		}
	}
}

func TestSplitVersion(t *testing.T) {
	tests := []struct {
		input string
		want  []int
	}{
		{"1.2.3", []int{1, 2, 3}},
		{"2.0.0", []int{2, 0, 0}},
		{"10.20.30", []int{10, 20, 30}},
		{"1.0.0-beta", []int{1, 0, 0}},
	}

	for _, tt := range tests {
		got := splitVersion(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("splitVersion(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitVersion(%q)[%d] = %d, want %d", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestCheckDevVersion(t *testing.T) {
	// Dev builds should never trigger an update check
	result := Check("dev")
	if result != nil {
		t.Error("Check(\"dev\") should return nil")
	}

	result = Check("")
	if result != nil {
		t.Error("Check(\"\") should return nil")
	}
}
