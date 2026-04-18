package beta

import (
	"strings"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════
// TTPMapper Core Tests
// ═══════════════════════════════════════════════════════════

func TestNewTTPMapper(t *testing.T) {
	m := NewTTPMapper()
	if m == nil {
		t.Fatal("NewTTPMapper returned nil")
	}
}

func TestTagTTP(t *testing.T) {
	m := NewTTPMapper()
	profile := &AttackerProfile{SrcIP: "10.0.0.1"}

	m.TagTTP(profile, "T1046", "Network Service Discovery")

	if len(profile.TTPTags) != 1 {
		t.Fatalf("TTPTags length = %d, want 1", len(profile.TTPTags))
	}
	if profile.TTPTags[0] != "T1046" {
		t.Errorf("TTPTags[0] = %q, want %q", profile.TTPTags[0], "T1046")
	}
}

func TestTagTTP_NoDuplicates(t *testing.T) {
	m := NewTTPMapper()
	profile := &AttackerProfile{SrcIP: "10.0.0.1"}

	m.TagTTP(profile, "T1046", "Network Service Discovery")
	m.TagTTP(profile, "T1046", "Network Service Discovery") // Duplicate.
	m.TagTTP(profile, "T1046", "Network Service Discovery") // Duplicate.

	if len(profile.TTPTags) != 1 {
		t.Errorf("duplicate tags not prevented: len = %d", len(profile.TTPTags))
	}
}

func TestTagTTP_MultipleTechniques(t *testing.T) {
	m := NewTTPMapper()
	profile := &AttackerProfile{SrcIP: "10.0.0.1"}

	m.TagTTP(profile, "T1046", "Network Service Discovery")
	m.TagTTP(profile, "T1110", "Brute Force")
	m.TagTTP(profile, "T1190", "Exploit Public-Facing Application")

	if len(profile.TTPTags) != 3 {
		t.Errorf("TTPTags length = %d, want 3", len(profile.TTPTags))
	}
}

// ═══════════════════════════════════════════════════════════
// Tool Detection Tests
// ═══════════════════════════════════════════════════════════

func TestDetectTool_KnownTools(t *testing.T) {
	m := NewTTPMapper()

	tests := []struct {
		input string
		want  string
	}{
		{"nmap/7.92", "nmap"},
		{"Nmap Scripting Engine", "nmap"},
		{"masscan/1.3.2", "masscan"},
		{"Mozilla/5.0 zgrab/0.x", "zgrab"},
		{"sqlmap/1.7", "sqlmap"},
		{"nikto/2.1.6", "nikto"},
		{"gobuster/3.5", "gobuster"},
		{"Nuclei", "nuclei"},
		{"dirbuster", "dirbuster"},
		{"hydra/9.4", "hydra"},
		{"wpscan/3.8", "wpscan"},
	}

	for _, tt := range tests {
		got := m.DetectTool(tt.input)
		if got == "" {
			t.Errorf("DetectTool(%q) = empty, want %q", tt.input, tt.want)
		}
	}
}

func TestDetectTool_UnknownInput(t *testing.T) {
	m := NewTTPMapper()

	got := m.DetectTool("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0")
	if got != "" {
		t.Errorf("normal browser should not be detected as tool, got %q", got)
	}
}

// ═══════════════════════════════════════════════════════════
// Report Generation Tests
// ═══════════════════════════════════════════════════════════

func TestGenerateReport(t *testing.T) {
	m := NewTTPMapper()

	profile := &AttackerProfile{
		SrcIP:       "192.168.1.100",
		FirstSeen:   time.Now().Add(-2 * time.Hour),
		LastSeen:    time.Now(),
		L1Hits:      15,
		L2Hits:      3,
		L3Drops:     200,
		ThreatScore: 85,
		TTPTags:     []string{"T1046", "T1110", "T1190"},
		ToolsDetected: []string{"nmap", "hydra"},
		CredsAttempted: []CredAttempt{
			{User: "admin", Pass: "password123", Timestamp: time.Now()},
		},
		ExploitAttempts: []ExploitAttempt{
			{Type: "sqli", PayloadHash: "abc123", Timestamp: time.Now()},
		},
	}

	report := m.GenerateReport(profile)
	if report == "" {
		t.Fatal("GenerateReport returned empty string")
	}

	// Verify report contains key information.
	checks := []string{
		"192.168.1.100",
		"T1046",
		"nmap",
		"85",
	}
	for _, check := range checks {
		if !strings.Contains(report, check) {
			t.Errorf("report missing expected content: %q", check)
		}
	}
}

func TestGenerateReport_EmptyProfile(t *testing.T) {
	m := NewTTPMapper()

	profile := &AttackerProfile{
		SrcIP:     "10.0.0.1",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}

	report := m.GenerateReport(profile)
	if report == "" {
		t.Error("GenerateReport should handle empty profile")
	}
}

// ═══════════════════════════════════════════════════════════
// Classify Exploit Tests
// ═══════════════════════════════════════════════════════════

func TestClassifyExploit(t *testing.T) {
	m := NewTTPMapper()

	tests := []struct {
		exploitType string
		wantTTP     string
	}{
		{"sqli", "T1190"},
		{"log4shell", "T1190"},
		{"ssrf", "T1190"},
		{"xss", "T1190"},
	}

	for _, tt := range tests {
		ttps := m.ClassifyExploit(tt.exploitType)

		found := false
		for _, ttp := range ttps {
			if ttp == tt.wantTTP {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ClassifyExploit(%q) = %v, should contain %q",
				tt.exploitType, ttps, tt.wantTTP)
		}
	}
}
