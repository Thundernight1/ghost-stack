package beta

import (
	"encoding/binary"
	"testing"
)

// buildNFLOGDatagram crafts a synthetic NETLINK_NETFILTER datagram with one
// NFULNL_MSG_PACKET containing a prefix and an IPv4/TCP payload.
func buildNFLOGDatagram(t *testing.T) []byte {
	t.Helper()

	// IPv4 header (20 bytes) + TCP ports (4 bytes).
	ip := make([]byte, 24)
	ip[0] = 0x45
	ip[9] = 6 // TCP
	copy(ip[12:16], []byte{10, 0, 0, 5})
	copy(ip[16:20], []byte{10, 0, 0, 9})
	binary.BigEndian.PutUint16(ip[20:], 4321) // src port
	binary.BigEndian.PutUint16(ip[22:], 443)  // dst port

	attrs := nlaPut(nfulaAttrPrefix, []byte("nft-log\x00"))
	attrs = append(attrs, nlaPut(nfulaAttrPayload, ip)...)

	nfgen := []byte{0, 0, 0, 0} // family=AF_UNSPEC, version, res_id
	body := append(nfgen, attrs...)

	nlh := make([]byte, 16)
	binary.LittleEndian.PutUint32(nlh[0:], uint32(16+len(body)))
	binary.LittleEndian.PutUint16(nlh[4:], uint16(nfnlSubsysUlog<<8|nfulnlMsgPacket))
	binary.LittleEndian.PutUint32(nlh[8:], 7) // seq
	return append(nlh, body...)
}

func TestParseNFLOGDatagram(t *testing.T) {
	packets, err := parseNFLOGDatagram(buildNFLOGDatagram(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(packets) != 1 {
		t.Fatalf("got %d packets, want 1", len(packets))
	}
	p := packets[0]
	if p.SrcIP.String() != "10.0.0.5" {
		t.Errorf("SrcIP = %s, want 10.0.0.5", p.SrcIP)
	}
	if p.DstIP.String() != "10.0.0.9" {
		t.Errorf("DstIP = %s, want 10.0.0.9", p.DstIP)
	}
	if p.Proto != 6 {
		t.Errorf("Proto = %d, want 6", p.Proto)
	}
	if p.SrcPort != 4321 || p.DstPort != 443 {
		t.Errorf("ports = %d->%d, want 4321->443", p.SrcPort, p.DstPort)
	}
	if p.Prefix != "nft-log" {
		t.Errorf("Prefix = %q, want nft-log", p.Prefix)
	}
}

func TestParseNFLOGDatagram_TwoMessages(t *testing.T) {
	one := buildNFLOGDatagram(t)
	two := append(append([]byte{}, one...), one...)
	packets, err := parseNFLOGDatagram(two)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(packets) != 2 {
		t.Fatalf("got %d packets, want 2", len(packets))
	}
}

func TestParseNFLOGDatagram_Garbage(t *testing.T) {
	packets, err := parseNFLOGDatagram([]byte{0xff, 0x00, 0x11})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(packets) != 0 {
		t.Fatalf("got %d packets from garbage, want 0", len(packets))
	}
}

func buildAuditDatagram(t *testing.T, msgType uint16, payload string) []byte {
	t.Helper()
	nlh := make([]byte, 16)
	binary.LittleEndian.PutUint32(nlh[0:], uint32(16+len(payload)))
	binary.LittleEndian.PutUint16(nlh[4:], msgType)
	binary.LittleEndian.PutUint32(nlh[8:], 9)
	return append(nlh, []byte(payload)...)
}

func TestParseAuditDatagram(t *testing.T) {
	data := buildAuditDatagram(t, auditAVC,
		"avc:  denied  { read } for  pid=123 comm=\"nginx\" saddr=10.1.2.3 scontext=system_u")
	events, err := parseAuditDatagram(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Type != auditAVC {
		t.Errorf("Type = %d, want %d", events[0].Type, auditAVC)
	}

	le := auditLayerEvent(events[0])
	if le.EventType != "LSM_AVC_DENIED" {
		t.Errorf("EventType = %s, want LSM_AVC_DENIED", le.EventType)
	}
	if le.SourceIP != "10.1.2.3" {
		t.Errorf("SourceIP = %q, want 10.1.2.3", le.SourceIP)
	}
	if le.Layer != 4 {
		t.Errorf("Layer = %d, want 4", le.Layer)
	}
}

func TestParseAuditDatagram_IgnoresUninteresting(t *testing.T) {
	data := buildAuditDatagram(t, 1300, "type=SYSCALL ...") // AUDIT_SYSCALL — not watched
	events, err := parseAuditDatagram(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("got %d events for unwatched type, want 0", len(events))
	}
}

func TestExtractAuditIP(t *testing.T) {
	if got := extractAuditIP("foo saddr=192.168.1.10 bar"); got != "192.168.1.10" {
		t.Errorf("got %q", got)
	}
	if got := extractAuditIP("no ip here"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestNflogEventMapping(t *testing.T) {
	packets, _ := parseNFLOGDatagram(buildNFLOGDatagram(t))
	ev := nflogEvent(packets[0])
	if ev.Layer != 1 || ev.SourceIP != "10.0.0.5" || ev.EventType != "NFLOG_PACKET" {
		t.Errorf("unexpected mapping: %+v", ev)
	}
	if ev.Details["dst_port"] != uint16(443) {
		t.Errorf("dst_port = %v", ev.Details["dst_port"])
	}
}
