package beta

import (
	"sync"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════
// Profiler Core Tests
// ═══════════════════════════════════════════════════════════

func TestNewProfiler(t *testing.T) {
	p := NewProfiler(100)
	if p == nil {
		t.Fatal("NewProfiler returned nil")
	}
	if p.maxSize != 100 {
		t.Errorf("maxSize = %d, want 100", p.maxSize)
	}
	if p.Size() != 0 {
		t.Errorf("initial size = %d, want 0", p.Size())
	}
}

func TestGetOrCreate_NewProfile(t *testing.T) {
	p := NewProfiler(100)

	profile := p.GetOrCreate("192.168.1.1")
	if profile == nil {
		t.Fatal("GetOrCreate returned nil")
	}
	if profile.SrcIP != "192.168.1.1" {
		t.Errorf("SrcIP = %q, want %q", profile.SrcIP, "192.168.1.1")
	}
	if p.Size() != 1 {
		t.Errorf("size = %d after first insert, want 1", p.Size())
	}
}

func TestGetOrCreate_ExistingProfile(t *testing.T) {
	p := NewProfiler(100)

	p1 := p.GetOrCreate("10.0.0.1")
	p1.mu.Lock()
	p1.ThreatScore = 42
	p1.mu.Unlock()

	p2 := p.GetOrCreate("10.0.0.1")

	if p2.ThreatScore != 42 {
		t.Error("second GetOrCreate should return existing profile")
	}
	if p.Size() != 1 {
		t.Errorf("size = %d, want 1 (should not duplicate)", p.Size())
	}
}

func TestGet_NonExistent(t *testing.T) {
	p := NewProfiler(100)

	profile := p.Get("192.168.99.99")
	if profile != nil {
		t.Error("Get should return nil for non-existent IP")
	}
}

func TestGet_Existing(t *testing.T) {
	p := NewProfiler(100)
	p.GetOrCreate("10.0.0.1")

	profile := p.Get("10.0.0.1")
	if profile == nil {
		t.Error("Get should return existing profile")
	}
}

// ═══════════════════════════════════════════════════════════
// LRU Eviction Tests
// ═══════════════════════════════════════════════════════════

func TestLRUEviction_CapacityLimit(t *testing.T) {
	p := NewProfiler(5)

	// Fill to capacity.
	for i := 0; i < 5; i++ {
		p.GetOrCreate(ipAddr(i))
	}
	if p.Size() != 5 {
		t.Fatalf("size = %d, want 5", p.Size())
	}

	// Add one more — should evict.
	p.GetOrCreate(ipAddr(5))
	if p.Size() != 5 {
		t.Errorf("size after overflow = %d, want 5", p.Size())
	}
}

func TestLRUEviction_LowScoreFirst(t *testing.T) {
	p := NewProfiler(3)

	// Add 3 IPs.
	p1 := p.GetOrCreate("10.0.0.1")
	p2 := p.GetOrCreate("10.0.0.2")
	p3 := p.GetOrCreate("10.0.0.3")

	// Make p2 high-value so it's retained.
	p2.mu.Lock()
	p2.ThreatScore = 90
	p2.LastSeen = time.Now()
	p2.mu.Unlock()

	// Make p1 low-value and old.
	p1.mu.Lock()
	p1.ThreatScore = 5
	p1.LastSeen = time.Now().Add(-25 * time.Hour)
	p1.mu.Unlock()

	// Keep p3 recent.
	p3.mu.Lock()
	p3.ThreatScore = 10
	p3.LastSeen = time.Now()
	p3.mu.Unlock()

	// Add new IP — should evict p1 (low score, old).
	p.GetOrCreate("10.0.0.4")

	if p.Get("10.0.0.1") != nil {
		t.Error("low-score old profile should have been evicted")
	}
	if p.Get("10.0.0.2") == nil {
		t.Error("high-value profile should be retained")
	}
}

// ═══════════════════════════════════════════════════════════
// Eviction Policy Tests
// ═══════════════════════════════════════════════════════════

func TestEvictExpired_LowScore24h(t *testing.T) {
	p := NewProfiler(100)

	profile := p.GetOrCreate("10.0.0.1")
	profile.mu.Lock()
	profile.ThreatScore = 10
	profile.LastSeen = time.Now().Add(-25 * time.Hour)
	profile.mu.Unlock()

	p.evictExpired()

	if p.Get("10.0.0.1") != nil {
		t.Error("score<20, age>24h should be evicted")
	}
}

func TestEvictExpired_MediumScore72h(t *testing.T) {
	p := NewProfiler(100)

	profile := p.GetOrCreate("10.0.0.1")
	profile.mu.Lock()
	profile.ThreatScore = 40
	profile.LastSeen = time.Now().Add(-73 * time.Hour)
	profile.mu.Unlock()

	p.evictExpired()

	if p.Get("10.0.0.1") != nil {
		t.Error("score 20-60, age>72h should be evicted")
	}
}

func TestEvictExpired_HighScoreRetained(t *testing.T) {
	p := NewProfiler(100)

	profile := p.GetOrCreate("10.0.0.1")
	profile.mu.Lock()
	profile.ThreatScore = 80
	profile.LastSeen = time.Now().Add(-48 * time.Hour)
	profile.mu.Unlock()

	p.evictExpired()

	if p.Get("10.0.0.1") == nil {
		t.Error("score≥60, age<7d should be retained")
	}
}

func TestEvictExpired_HighScoreExpires7d(t *testing.T) {
	p := NewProfiler(100)

	profile := p.GetOrCreate("10.0.0.1")
	profile.mu.Lock()
	profile.ThreatScore = 90
	profile.LastSeen = time.Now().Add(-8 * 24 * time.Hour) // 8 days old.
	profile.mu.Unlock()

	p.evictExpired()

	if p.Get("10.0.0.1") != nil {
		t.Error("score≥60, age>7d should be evicted")
	}
}

// ═══════════════════════════════════════════════════════════
// Stats & Forensics Tests
// ═══════════════════════════════════════════════════════════

func TestStats(t *testing.T) {
	p := NewProfiler(100)

	for i := 0; i < 10; i++ {
		profile := p.GetOrCreate(ipAddr(i))
		profile.mu.Lock()
		profile.ThreatScore = i * 10
		profile.mu.Unlock()
	}

	stats := p.Stats()
	if stats["total_profiles"].(int) != 10 {
		t.Errorf("total_profiles = %v, want 10", stats["total_profiles"])
	}
	if stats["max_score"].(int) != 90 {
		t.Errorf("max_score = %v, want 90", stats["max_score"])
	}
}

func TestHighValueProfiles(t *testing.T) {
	p := NewProfiler(100)

	for i := 0; i < 10; i++ {
		profile := p.GetOrCreate(ipAddr(i))
		profile.mu.Lock()
		profile.ThreatScore = i * 15
		profile.mu.Unlock()
	}

	hvp := p.HighValueProfiles(60)
	for _, profile := range hvp {
		if profile.ThreatScore <= 60 {
			t.Errorf("high-value profile has score %d, should be > 60", profile.ThreatScore)
		}
	}
}

func TestAllProfiles(t *testing.T) {
	p := NewProfiler(100)

	for i := 0; i < 5; i++ {
		p.GetOrCreate(ipAddr(i))
	}

	all := p.AllProfiles()
	if len(all) != 5 {
		t.Errorf("AllProfiles() = %d, want 5", len(all))
	}
}

// ═══════════════════════════════════════════════════════════
// Concurrency Tests
// ═══════════════════════════════════════════════════════════

func TestConcurrentGetOrCreate(t *testing.T) {
	p := NewProfiler(1000)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := ipAddr(idx % 20) // 20 unique IPs across 100 goroutines.
			profile := p.GetOrCreate(ip)
			profile.mu.Lock()
			profile.ThreatScore++
			profile.L1Hits++
			profile.mu.Unlock()
		}(i)
	}
	wg.Wait()

	if p.Size() != 20 {
		t.Errorf("size = %d after concurrent ops, want 20", p.Size())
	}
}

func TestConcurrentProfileUpdateAndEviction(t *testing.T) {
	p := NewProfiler(50)

	var wg sync.WaitGroup

	// Writer goroutines.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				profile := p.GetOrCreate(ipAddr(idx*10 + j))
				profile.mu.Lock()
				profile.ThreatScore = idx + j
				profile.mu.Unlock()
			}
		}(i)
	}

	// Reader goroutines.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				p.Stats()
				p.Size()
			}
		}()
	}

	wg.Wait()

	// Should not exceed max capacity.
	if p.Size() > 50 {
		t.Errorf("size = %d, exceeds max capacity 50", p.Size())
	}
}

// ═══════════════════════════════════════════════════════════
// Benchmark
// ═══════════════════════════════════════════════════════════

func BenchmarkGetOrCreate(b *testing.B) {
	p := NewProfiler(50000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.GetOrCreate(ipAddr(i % 50000))
	}
}

func BenchmarkEvictExpired(b *testing.B) {
	p := NewProfiler(50000)
	for i := 0; i < 50000; i++ {
		profile := p.GetOrCreate(ipAddr(i))
		profile.mu.Lock()
		profile.ThreatScore = i % 100
		profile.LastSeen = time.Now().Add(-time.Duration(i) * time.Minute)
		profile.mu.Unlock()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.evictExpired()
	}
}

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

func ipAddr(n int) string {
	return "10.0." + itoa(n/256) + "." + itoa(n%256)
}

func itoa(n int) string {
	if n < 0 {
		n = -n
	}
	s := ""
	for {
		s = string(rune('0'+n%10)) + s
		n /= 10
		if n == 0 {
			break
		}
	}
	return s
}
