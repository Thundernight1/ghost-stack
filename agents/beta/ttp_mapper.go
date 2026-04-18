// Package beta — ttp_mapper.go implements MITRE ATT&CK TTP mapping
// and tool signature detection for GHOST-STACK CORE AGENT-BETA.
//
// Maps observed behaviors to MITRE ATT&CK techniques for threat
// intelligence correlation and attacker profiling.
package beta

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// TTPEntry maps a MITRE ATT&CK technique to its description.
type TTPEntry struct {
	ID          string `json:"id"`          // e.g., "T1046"
	Name        string `json:"name"`        // e.g., "Network Service Discovery"
	Tactic      string `json:"tactic"`      // e.g., "Discovery"
	Description string `json:"description"` // Brief description.
}

// ToolSignature identifies a known scanner/exploitation tool.
type ToolSignature struct {
	Name       string   `json:"name"`       // e.g., "nmap"
	Patterns   []string `json:"patterns"`   // User-Agent or payload patterns.
	TTPIDs     []string `json:"ttp_ids"`    // Associated MITRE techniques.
}

// TTPMapper handles MITRE ATT&CK technique mapping and tool detection.
type TTPMapper struct {
	mu         sync.RWMutex
	techniques map[string]*TTPEntry
	tools      []ToolSignature
}

// NewTTPMapper creates a new TTP mapper with the built-in ATT&CK knowledge base.
func NewTTPMapper() *TTPMapper {
	m := &TTPMapper{
		techniques: make(map[string]*TTPEntry),
	}
	m.loadTechniques()
	m.loadToolSignatures()
	return m
}

// loadTechniques populates the MITRE ATT&CK technique database.
func (m *TTPMapper) loadTechniques() {
	techniques := []TTPEntry{
		// Reconnaissance
		{ID: "TA0043", Name: "Reconnaissance", Tactic: "Reconnaissance", Description: "Adversary gathering information to plan future operations"},
		{ID: "T1595", Name: "Active Scanning", Tactic: "Reconnaissance", Description: "Scanning infrastructure to identify exploitable services"},
		{ID: "T1595.001", Name: "Scanning IP Blocks", Tactic: "Reconnaissance", Description: "Scanning IP address blocks to find targets"},
		{ID: "T1595.002", Name: "Vulnerability Scanning", Tactic: "Reconnaissance", Description: "Scanning for known vulnerabilities"},
		{ID: "T1046", Name: "Network Service Discovery", Tactic: "Discovery", Description: "Discovering services running on remote hosts"},

		// Initial Access
		{ID: "TA0001", Name: "Initial Access", Tactic: "Initial Access", Description: "Gaining initial foothold in target environment"},
		{ID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access", Description: "Exploiting vulnerabilities in internet-facing applications"},
		{ID: "T1078", Name: "Valid Accounts", Tactic: "Initial Access", Description: "Using stolen or compromised credentials"},
		{ID: "T1133", Name: "External Remote Services", Tactic: "Initial Access", Description: "Leveraging external remote services for access"},

		// Execution
		{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution", Description: "Using command-line or scripting interpreters"},
		{ID: "T1106", Name: "Native API", Tactic: "Execution", Description: "Interacting with native OS APIs"},

		// Persistence
		{ID: "T1098", Name: "Account Manipulation", Tactic: "Persistence", Description: "Maintaining persistence via account changes"},

		// Privilege Escalation
		{ID: "T1548", Name: "Abuse Elevation Control Mechanism", Tactic: "Privilege Escalation", Description: "Abusing elevation control mechanisms"},
		{ID: "T1068", Name: "Exploitation for Privilege Escalation", Tactic: "Privilege Escalation", Description: "Exploiting software vulnerabilities for privilege escalation"},

		// Defense Evasion
		{ID: "T1562", Name: "Impair Defenses", Tactic: "Defense Evasion", Description: "Disabling or modifying defensive mechanisms"},
		{ID: "T1070", Name: "Indicator Removal", Tactic: "Defense Evasion", Description: "Deleting or modifying indicators of compromise"},

		// Credential Access
		{ID: "T1110", Name: "Brute Force", Tactic: "Credential Access", Description: "Attempting to access accounts through password guessing"},
		{ID: "T1110.001", Name: "Password Guessing", Tactic: "Credential Access", Description: "Guessing passwords using common patterns"},
		{ID: "T1110.003", Name: "Password Spraying", Tactic: "Credential Access", Description: "Trying one password across many accounts"},
		{ID: "T1552", Name: "Unsecured Credentials", Tactic: "Credential Access", Description: "Searching for unsecured credentials"},
		{ID: "T1552.001", Name: "Credentials In Files", Tactic: "Credential Access", Description: "Finding credentials stored in files"},

		// Discovery
		{ID: "T1082", Name: "System Information Discovery", Tactic: "Discovery", Description: "Gathering system information"},
		{ID: "T1083", Name: "File and Directory Discovery", Tactic: "Discovery", Description: "Enumerating files and directories"},
		{ID: "T1087", Name: "Account Discovery", Tactic: "Discovery", Description: "Discovering accounts on the system"},

		// Lateral Movement
		{ID: "T1021", Name: "Remote Services", Tactic: "Lateral Movement", Description: "Using remote services for lateral movement"},

		// Collection
		{ID: "T1005", Name: "Data from Local System", Tactic: "Collection", Description: "Collecting data from the local system"},

		// Impact
		{ID: "T1498", Name: "Network Denial of Service", Tactic: "Impact", Description: "Performing network-level denial of service"},
		{ID: "T1499", Name: "Endpoint Denial of Service", Tactic: "Impact", Description: "Performing endpoint denial of service"},
	}

	for i := range techniques {
		m.techniques[techniques[i].ID] = &techniques[i]
	}
}

// loadToolSignatures populates known scanner/tool signatures.
func (m *TTPMapper) loadToolSignatures() {
	m.tools = []ToolSignature{
		{
			Name:     "nmap",
			Patterns: []string{"nmap", "Nmap", "NMAP", "nmap-service-probe"},
			TTPIDs:   []string{"T1046", "T1595"},
		},
		{
			Name:     "masscan",
			Patterns: []string{"masscan", "Masscan"},
			TTPIDs:   []string{"T1595.001", "T1046"},
		},
		{
			Name:     "metasploit",
			Patterns: []string{"Metasploit", "msf", "meterpreter", "metasploit"},
			TTPIDs:   []string{"T1190", "T1059", "T1068"},
		},
		{
			Name:     "nuclei",
			Patterns: []string{"nuclei", "Nuclei", "projectdiscovery"},
			TTPIDs:   []string{"T1595.002", "T1190"},
		},
		{
			Name:     "sqlmap",
			Patterns: []string{"sqlmap", "SQLMap"},
			TTPIDs:   []string{"T1190", "T1059"},
		},
		{
			Name:     "nikto",
			Patterns: []string{"Nikto", "nikto"},
			TTPIDs:   []string{"T1595.002"},
		},
		{
			Name:     "gobuster",
			Patterns: []string{"gobuster", "GoBuster"},
			TTPIDs:   []string{"T1083", "T1595"},
		},
		{
			Name:     "dirb",
			Patterns: []string{"dirb", "DirBuster"},
			TTPIDs:   []string{"T1083"},
		},
		{
			Name:     "hydra",
			Patterns: []string{"Hydra", "hydra", "THC-Hydra"},
			TTPIDs:   []string{"T1110", "T1110.001"},
		},
		{
			Name:     "burpsuite",
			Patterns: []string{"Burp", "burp", "BurpSuite"},
			TTPIDs:   []string{"T1190", "T1595.002"},
		},
		{
			Name:     "wpscan",
			Patterns: []string{"WPScan", "wpscan"},
			TTPIDs:   []string{"T1595.002", "T1190"},
		},
		{
			Name:     "ffuf",
			Patterns: []string{"Fuzz Faster", "ffuf"},
			TTPIDs:   []string{"T1083", "T1595"},
		},
		{
			Name:     "curl",
			Patterns: []string{"curl/"},
			TTPIDs:   []string{"T1082"},
		},
		{
			Name:     "wget",
			Patterns: []string{"Wget/"},
			TTPIDs:   []string{"T1082"},
		},
		{
			Name:     "python-requests",
			Patterns: []string{"python-requests", "Python-urllib"},
			TTPIDs:   []string{"T1106"},
		},
		{
			Name:     "zgrab",
			Patterns: []string{"zgrab", "ZGrab"},
			TTPIDs:   []string{"T1595", "T1046"},
		},
		{
			Name:     "shodan",
			Patterns: []string{"Shodan", "shodan"},
			TTPIDs:   []string{"T1595.001"},
		},
		{
			Name:     "censys",
			Patterns: []string{"Censys", "censys"},
			TTPIDs:   []string{"T1595.001"},
		},
	}
}

// DetectTool checks if a User-Agent or payload string matches a known tool.
func (m *TTPMapper) DetectTool(input string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lower := strings.ToLower(input)
	for _, tool := range m.tools {
		for _, pattern := range tool.Patterns {
			if strings.Contains(lower, strings.ToLower(pattern)) {
				return tool.Name
			}
		}
	}
	return ""
}

// TagTTP adds a MITRE ATT&CK tag to an attacker profile.
func (m *TTPMapper) TagTTP(profile *AttackerProfile, ttpID, name string) {
	// profile.mu should be held by the caller.
	for _, existing := range profile.TTPTags {
		if existing == ttpID {
			return // Already tagged.
		}
	}
	profile.TTPTags = append(profile.TTPTags, ttpID)
}

// GetTechnique returns the full TTP entry for a technique ID.
func (m *TTPMapper) GetTechnique(ttpID string) *TTPEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.techniques[ttpID]
}

// GetToolTTPs returns the MITRE techniques associated with a detected tool.
func (m *TTPMapper) GetToolTTPs(toolName string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, tool := range m.tools {
		if strings.EqualFold(tool.Name, toolName) {
			return tool.TTPIDs
		}
	}
	return nil
}

// ClassifyExploit determines the MITRE technique(s) for an exploit type.
func (m *TTPMapper) ClassifyExploit(exploitType string) []string {
	lower := strings.ToLower(exploitType)

	switch {
	case strings.Contains(lower, "sqli") || strings.Contains(lower, "sql_injection"):
		return []string{"T1190"}
	case strings.Contains(lower, "xss"):
		return []string{"T1190", "T1059"}
	case strings.Contains(lower, "ssrf"):
		return []string{"T1190", "T1552"}
	case strings.Contains(lower, "log4shell") || strings.Contains(lower, "log4j"):
		return []string{"T1190", "T1059"}
	case strings.Contains(lower, "shellshock"):
		return []string{"T1190", "T1059"}
	case strings.Contains(lower, "rce") || strings.Contains(lower, "command_injection"):
		return []string{"T1190", "T1059"}
	case strings.Contains(lower, "lfi") || strings.Contains(lower, "path_traversal"):
		return []string{"T1083", "T1005"}
	case strings.Contains(lower, "deserialization"):
		return []string{"T1190", "T1059"}
	case strings.Contains(lower, "xxe"):
		return []string{"T1190", "T1005"}
	default:
		return []string{"T1190"}
	}
}

// BuildTTPTimeline creates a chronological view of an attacker's TTPs.
func (m *TTPMapper) BuildTTPTimeline(profile *AttackerProfile) []TTPTimelineEntry {
	var timeline []TTPTimelineEntry

	profile.mu.Lock()
	defer profile.mu.Unlock()

	// Map credential attempts.
	for _, cred := range profile.CredsAttempted {
		timeline = append(timeline, TTPTimelineEntry{
			Timestamp:  cred.Timestamp,
			TTPIDs:     []string{"T1110"},
			Action:     "Credential attempt",
			Detail:     "User: " + cred.User,
		})
	}

	// Map exploit attempts.
	for _, exploit := range profile.ExploitAttempts {
		ttps := m.ClassifyExploit(exploit.Type)
		timeline = append(timeline, TTPTimelineEntry{
			Timestamp:  exploit.Timestamp,
			TTPIDs:     ttps,
			Action:     "Exploit attempt",
			Detail:     exploit.Type,
		})
	}

	return timeline
}

// TTPTimelineEntry is a single entry in a TTP timeline.
type TTPTimelineEntry struct {
	Timestamp time.Time `json:"timestamp"`
	TTPIDs    []string  `json:"ttp_ids"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
}

// GenerateReport creates a human-readable threat intelligence report
// for an attacker profile. This is used for forensic export.
func (m *TTPMapper) GenerateReport(profile *AttackerProfile) string {
	profile.mu.Lock()
	defer profile.mu.Unlock()

	var b strings.Builder

	b.WriteString("═══════════════════════════════════════════════\n")
	b.WriteString("  GHOST-STACK CORE — Threat Actor Report\n")
	b.WriteString("═══════════════════════════════════════════════\n\n")

	b.WriteString("Source IP:     " + profile.SrcIP + "\n")
	b.WriteString("First Seen:    " + profile.FirstSeen.Format(time.RFC3339) + "\n")
	b.WriteString("Last Seen:     " + profile.LastSeen.Format(time.RFC3339) + "\n")
	b.WriteString("Threat Score:  " + strings.Repeat("█", min(profile.ThreatScore/5, 20)))
	b.WriteString(" " + fmt.Sprint(profile.ThreatScore) + "/100\n\n")

	b.WriteString("── Layer Activity ──\n")
	b.WriteString("  L1 (nftables):  " + fmt.Sprint(profile.L1Hits) + " hits\n")
	b.WriteString("  L2 (eBPF TC):   " + fmt.Sprint(profile.L2Hits) + " hits\n")
	b.WriteString("  L3 (XDP):       " + fmt.Sprint(profile.L3Drops) + " drops\n")
	b.WriteString("  L4 (AppArmor):  " + fmt.Sprint(profile.L4Violations) + " violations\n\n")

	if len(profile.ToolsDetected) > 0 {
		b.WriteString("── Detected Tools ──\n")
		for _, tool := range profile.ToolsDetected {
			b.WriteString("  • " + tool + "\n")
		}
		b.WriteString("\n")
	}

	if len(profile.TTPTags) > 0 {
		b.WriteString("── MITRE ATT&CK Techniques ──\n")
		for _, ttpID := range profile.TTPTags {
			if entry := m.techniques[ttpID]; entry != nil {
				b.WriteString("  " + entry.ID + " — " + entry.Name + " [" + entry.Tactic + "]\n")
			} else {
				b.WriteString("  " + ttpID + "\n")
			}
		}
		b.WriteString("\n")
	}

	if len(profile.CredsAttempted) > 0 {
		b.WriteString("── Credential Attempts ──\n")
		for _, cred := range profile.CredsAttempted {
			b.WriteString("  " + cred.Timestamp.Format("15:04:05") +
				" user=" + cred.User + " pass=" + maskPassword(cred.Pass) + "\n")
		}
		b.WriteString("\n")
	}

	if len(profile.ExploitAttempts) > 0 {
		b.WriteString("── Exploit Attempts ──\n")
		for _, exp := range profile.ExploitAttempts {
			b.WriteString("  " + exp.Timestamp.Format("15:04:05") +
				" type=" + exp.Type + " hash=" + exp.PayloadHash + "\n")
		}
	}

	b.WriteString("\n═══════════════════════════════════════════════\n")

	return b.String()
}

func maskPassword(p string) string {
	if len(p) <= 2 {
		return "**"
	}
	return string(p[0]) + strings.Repeat("*", len(p)-2) + string(p[len(p)-1])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}



