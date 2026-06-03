// Package beta — profiler.go implements AttackerProfile with LRU cache
// for GHOST-STACK CORE AGENT-BETA.
//
// Memory management:
//   - Max 50,000 entries in LRU cache
//   - Profiles older than 24h with threat_score < 20: evict
//   - High-value profiles (score > 60): retain 7 days in-memory
//   - NEVER write profiles to disk unless orchestrator explicitly
//     requests forensic export (signed command)
package beta

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// CredAttempt records a captured credential attempt.
type CredAttempt struct {
	User      string    `json:"user"`
	Pass      string    `json:"pass"`
	Timestamp time.Time `json:"ts"`
}

// ExploitAttempt records a detected exploit attempt.
type ExploitAttempt struct {
	Type        string    `json:"type"`
	PayloadHash string    `json:"payload_hash"`
	Timestamp   time.Time `json:"ts"`
}

// AttackerProfile holds the in-memory-only profile of a threat actor.
// NEVER persisted to disk unless signed forensic export is requested.
type AttackerProfile struct {
	mu sync.Mutex

	// Source identification.
	SrcIP     string    `json:"src_ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	// Layer hit counters.
	L1Hits       uint64 `json:"l1_hits"`
	L2Hits       uint64 `json:"l2_hits"`
	L3Drops      uint64 `json:"l3_drops"`
	L4Violations uint64 `json:"l4_violations"`

	// Tool detection.
	ToolsDetected []string `json:"tools_detected"`

	// Credential capture.
	CredsAttempted []CredAttempt `json:"creds_attempted"`

	// Exploit detection.
	ExploitAttempts []ExploitAttempt `json:"exploit_attempts"`

	// Threat assessment.
	ThreatScore int      `json:"threat_score"`
	TTPTags     []string `json:"ttp_tags"` // MITRE ATT&CK technique IDs.

	// Internal LRU tracking (not serialized).
	lruElement *list.Element `json:"-"`
}

// Profiler manages AttackerProfiles with an LRU cache.
type Profiler struct {
	mu       sync.Mutex
	profiles map[string]*AttackerProfile // IP → profile
	lru      *list.List                  // LRU eviction list
	maxSize  int
}

// NewProfiler creates a new profiler with the given maximum cache size.
func NewProfiler(maxSize int) *Profiler {
	return &Profiler{
		profiles: make(map[string]*AttackerProfile),
		lru:      list.New(),
		maxSize:  maxSize,
	}
}

// GetOrCreate returns the existing profile for an IP or creates a new one.
func (p *Profiler) GetOrCreate(srcIP string) *AttackerProfile {
	p.mu.Lock()
	defer p.mu.Unlock()

	if profile, exists := p.profiles[srcIP]; exists {
		// Move to front of LRU.
		p.lru.MoveToFront(profile.lruElement)
		return profile
	}

	// Create new profile.
	profile := &AttackerProfile{
		SrcIP:     srcIP,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}

	// Check capacity — evict if needed.
	for p.lru.Len() >= p.maxSize {
		p.evictOne()
	}

	// Add to LRU and map.
	element := p.lru.PushFront(srcIP)
	profile.lruElement = element
	p.profiles[srcIP] = profile

	return profile
}

// Get returns a profile by IP without creating a new one.
func (p *Profiler) Get(srcIP string) *AttackerProfile {
	p.mu.Lock()
	defer p.mu.Unlock()

	if profile, exists := p.profiles[srcIP]; exists {
		p.lru.MoveToFront(profile.lruElement)
		return profile
	}
	return nil
}

// evictOne removes the least recently used profile.
// Must be called with p.mu held.
func (p *Profiler) evictOne() {
	if p.lru.Len() == 0 {
		return
	}

	// Start from the back (least recently used).
	for e := p.lru.Back(); e != nil; e = e.Prev() {
		ip := e.Value.(string)
		profile, exists := p.profiles[ip]
		if !exists {
			p.lru.Remove(e)
			return
		}

		profile.mu.Lock()
		score := profile.ThreatScore
		lastSeen := profile.LastSeen
		profile.mu.Unlock()

		age := time.Since(lastSeen)

		// Eviction policy:
		// - score < 20 and older than 24h: evict
		// - score >= 60: retain up to 7 days
		// - everything else: LRU eviction
		if score < 20 && age > 24*time.Hour {
			p.lru.Remove(e)
			delete(p.profiles, ip)
			return
		}

		if score >= 60 && age < 7*24*time.Hour {
			// High-value profile — skip eviction.
			continue
		}

		// Default: evict LRU.
		p.lru.Remove(e)
		delete(p.profiles, ip)
		return
	}
}

// RunEvictionLoop periodically cleans up expired profiles.
func (p *Profiler) RunEvictionLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.evictExpired()
		}
	}
}

// evictExpired removes all profiles past their retention period.
func (p *Profiler) evictExpired() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()

	for e := p.lru.Back(); e != nil; {
		prev := e.Prev()
		ip := e.Value.(string)
		profile, exists := p.profiles[ip]

		if !exists {
			p.lru.Remove(e)
			e = prev
			continue
		}

		profile.mu.Lock()
		score := profile.ThreatScore
		lastSeen := profile.LastSeen
		profile.mu.Unlock()

		age := now.Sub(lastSeen)

		shouldEvict := false

		if score < 20 && age > 24*time.Hour {
			shouldEvict = true
		} else if score >= 20 && score < 60 && age > 72*time.Hour {
			shouldEvict = true
		} else if score >= 60 && age > 7*24*time.Hour {
			shouldEvict = true
		}

		if shouldEvict {
			p.lru.Remove(e)
			delete(p.profiles, ip)
		}

		e = prev
	}
}

// Size returns the current number of profiles in the cache.
func (p *Profiler) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.profiles)
}

// AllProfiles returns a snapshot of all current profiles.
// WARNING: This is for forensic export ONLY — requires signed command.
func (p *Profiler) AllProfiles() []*AttackerProfile {
	p.mu.Lock()
	defer p.mu.Unlock()

	profiles := make([]*AttackerProfile, 0, len(p.profiles))
	for _, profile := range p.profiles {
		profiles = append(profiles, profile)
	}
	return profiles
}

// HighValueProfiles returns all profiles with threat_score > threshold.
func (p *Profiler) HighValueProfiles(threshold int) []*AttackerProfile {
	p.mu.Lock()
	defer p.mu.Unlock()

	var result []*AttackerProfile
	for _, profile := range p.profiles {
		profile.mu.Lock()
		if profile.ThreatScore > threshold {
			result = append(result, profile)
		}
		profile.mu.Unlock()
	}
	return result
}

// Stats returns profiler statistics.
func (p *Profiler) Stats() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	totalScore := 0
	maxScore := 0
	highValue := 0

	for _, profile := range p.profiles {
		profile.mu.Lock()
		totalScore += profile.ThreatScore
		if profile.ThreatScore > maxScore {
			maxScore = profile.ThreatScore
		}
		if profile.ThreatScore > 60 {
			highValue++
		}
		profile.mu.Unlock()
	}

	return map[string]interface{}{
		"total_profiles": len(p.profiles),
		"max_capacity":   p.maxSize,
		"avg_score":      totalScore / max(len(p.profiles), 1),
		"max_score":      maxScore,
		"high_value":     highValue,
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
