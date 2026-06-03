package auth

import (
	"strings"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestIntegrityScanner_Types(t *testing.T) {
	types := []struct {
		st   ScanType
		want string
	}{
		{ScanFilesystemHash, "FILESYSTEM_HASH"},
		{ScanProcessAnomaly, "PROCESS_ANOMALY"},
		{ScanNetworkAudit, "NETWORK_AUDIT"},
		{ScanCgroupDelta, "CGROUP_DELTA"},
		{ScanSeccompViolation, "SECCOMP_VIOLATION"},
		{ScanType(99), "UNKNOWN"},
	}

	for _, tt := range types {
		if got := tt.st.String(); got != tt.want {
			t.Errorf("ScanType(%d).String() = %v, want %v", tt.st, got, tt.want)
		}
	}
}

func TestNewIntegrityScanner(t *testing.T) {
	scanner := NewIntegrityScanner(1, 1000, "/tmp/rootfs", "/sys/fs/cgroup/dept-1", "/tmp/alert.sock")

	if scanner.deptID != 1 {
		t.Errorf("deptID = %d, want 1", scanner.deptID)
	}
	if scanner.containerPID != 1000 {
		t.Errorf("containerPID = %d, want 1000", scanner.containerPID)
	}
	if scanner.fsBaseline == nil || scanner.procBaseline == nil {
		t.Error("baselines not initialized")
	}
}

func TestIntegrityScanner_SendResult(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "a.sock")
	
	// Create dummy UNIX domain socket listener
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on socket: %v", err)
	}
	defer l.Close()

	scanner := NewIntegrityScanner(1, 1000, "/tmp", "/tmp", sockPath)

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		
		msg := string(buf[:n])
		if len(msg) == 0 {
			t.Error("received empty message on alert socket")
		}
	}()

	result := &ScanResult{
		DeptID: 1,
		Type:   ScanNetworkAudit.String(),
		Status: "OK",
	}

	// Will trigger the socket write which should be picked up by the listener
	scanner.sendResult(result)
}

func TestHashFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	_ = os.WriteFile(tmpFile, []byte("hello world\n"), 0644)

	// sha256 of "hello world\n"
	expected := "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"

	hash, err := hashFile(tmpFile)
	if err != nil {
		t.Fatalf("hashFile error: %v", err)
	}
	if hash != expected {
		t.Errorf("hashFile() = %q, want %q", hash, expected)
	}
}

func TestScanResultJSON(t *testing.T) {
	// Verify JSON tags
	res := ScanResult{
		DeptID: 1,
		Type:   "TEST",
		Status: "OK",
		Details: map[string]interface{}{
			"foo": "bar",
		},
	}
	
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	
	s := string(out)
	if !strings.Contains(s, `"dept_id":1`) {
		t.Error("missing dept_id in JSON")
	}
	if !strings.Contains(s, `"foo":"bar"`) {
		t.Error("missing details content in JSON")
	}
}
