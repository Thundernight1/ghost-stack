// Package beta — real data-plane sources for AGENT-BETA.
//
// This file implements the four layer feeds with real kernel interfaces:
//
//	L1: NFLOG via a raw NETLINK_NETFILTER socket (nftables LOG → nflog group)
//	L2: eBPF perf_event_array via cilium/ebpf perf.Reader on the pinned map
//	L3: XDP drop-counter map via pinned-map iteration + per-CPU aggregation
//	L4: Linux audit (NETLINK_AUDIT) socket, parsing AVC/NETFILTER messages
//
// All sources are read-only and passive. Each reader is context-aware: when
// the agent's context is cancelled the underlying fd is closed (via
// SetReadDeadline-free shutdown through fd close), which unblocks the
// pending read and lets the goroutine exit.
//
// These paths need privileges (CAP_NET_ADMIN/CAP_BPF/CAP_AUDIT_READ or
// root) and the kernel objects to exist. When they don't, the reader logs
// once and its goroutine exits — the agent keeps running on the remaining
// feeds instead of busy-looping on stubs.
package beta

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// L1 — NFLOG (NETLINK_NETFILTER)
// ---------------------------------------------------------------------------

// Netlink / NFLOG constants (from <linux/netlink.h>, <linux/netfilter/nfnetlink.h>,
// <linux/netfilter/nfnetlink_log.h>).
const (
	nfnlSubsysUlog       = 1 // NFNL_SUBSYS_ULOG
	nfulnlMsgConfig      = 1 // NFULNL_MSG_CONFIG
	nfulnlMsgPacket      = 0 // NFULNL_MSG_PACKET
	nfulnlCfgCmdBind     = 1 // NFULNL_CFG_CMD_BIND
	nfulnlCfgCmdUnbind   = 2
	nfulnlCfgCmdPfBind   = 3 // NFULNL_CFG_CMD_PF_BIND
	nfulnlCfgCmdPfUnbind = 4
	nfulnlCfgCmdMode     = 5 // NFULNL_CFG_CMD_MODE — copy mode
	nfulnlCopyPacket     = 2 // NFULNL_COPY_PACKET — copy entire packet

	nfulaCfgCmd      = 1 // NFULA_CFG_CMD
	nfulaCfgMode     = 2 // NFULA_CFG_MODE
	nfulaAttrHwaddr  = 1 // NFULA_HWADDR
	nfulaAttrPrefix  = 2 // NFULA_PREFIX
	nfulaAttrPayload = 9 // NFULA_PAYLOAD

	afInet = 2 // AF_INET
)

// nflogReader owns a NETLINK_NETFILTER socket bound to one nflog group.
type nflogReader struct {
	fd    int
	group uint16
}

// openNFLOG creates the NETLINK_NETFILTER socket, binds it to the nflog
// multicast group, and arms COPY_PACKET mode for AF_INET.
func openNFLOG(group uint16) (*nflogReader, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nflog: socket: %w", err)
	}
	r := &nflogReader{fd: fd, group: group}

	// Bind to the nflog multicast group: group N is bit N.
	if err := unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: 1 << group,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("nflog: bind group %d: %w", group, err)
	}

	// PF_BIND for AF_INET so the group receives IPv4 log packets.
	if err := r.sendConfig(nfulnlCfgCmdPfBind, pfBindPayload(afInet)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("nflog: PF_BIND: %w", err)
	}
	// Bind this specific group.
	if err := r.sendConfig(nfulnlCfgCmdBind, nil); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("nflog: group bind: %w", err)
	}
	// COPY_PACKET with a generous range so we get full headers.
	if err := r.sendConfig(nfulnlCfgCmdMode, copyModePayload(nfulnlCopyPacket, 0xffff)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("nflog: copy mode: %w", err)
	}
	return r, nil
}

func pfBindPayload(family uint8) []byte { return []byte{family} }

func copyModePayload(mode uint8, rng uint32) []byte {
	b := make([]byte, 8)
	b[0] = mode
	binary.BigEndian.PutUint32(b[4:], rng)
	return b
}

// sendConfig sends one NFULNL_MSG_CONFIG for our group.
func (r *nflogReader) sendConfig(cmd uint8, payload []byte) error {
	// nfgenmsg: {family=AF_UNSPEC, version=NFNETLINK_V0, res_id=htons(group)}
	hdr := make([]byte, 4)
	hdr[1] = 0 // version NFNETLINK_V0
	binary.BigEndian.PutUint16(hdr[2:], r.group)

	attr := nlaPut(nfulaCfgCmd, []byte{cmd})
	var attrs []byte
	attrs = append(attrs, attr...)
	if payload != nil {
		attrs = append(attrs, nlaPut(nfulaCfgMode, payload)...)
	}
	msg := append(hdr, attrs...)

	nlh := make([]byte, 16)
	binary.LittleEndian.PutUint32(nlh[0:], uint32(16+len(msg)))
	binary.LittleEndian.PutUint16(nlh[4:], uint16(nfnlSubsysUlog<<8|nfulnlMsgConfig))
	binary.LittleEndian.PutUint16(nlh[6:], 0) // flags
	binary.LittleEndian.PutUint32(nlh[8:], 1) // seq
	binary.LittleEndian.PutUint32(nlh[12:], uint32(os.Getpid()))
	packet := append(nlh, msg...)

	return unix.Sendto(r.fd, packet, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// nlaPut builds one netlink attribute (4-byte aligned).
func nlaPut(typ uint16, payload []byte) []byte {
	l := 4 + len(payload)
	padded := (l + 3) &^ 3
	b := make([]byte, padded)
	binary.LittleEndian.PutUint16(b[0:], uint16(l))
	binary.LittleEndian.PutUint16(b[2:], typ)
	copy(b[4:], payload)
	return b
}

func (r *nflogReader) close() error { return unix.Close(r.fd) }

// readPacket reads one netlink datagram and returns parsed NFLOG packets.
func (r *nflogReader) readPacket(buf []byte) ([]nflogPacket, error) {
	n, _, err := unix.Recvfrom(r.fd, buf, 0)
	if err != nil {
		return nil, err
	}
	return parseNFLOGDatagram(buf[:n])
}

// nflogPacket is one parsed NFULNL_MSG_PACKET.
type nflogPacket struct {
	Prefix  string
	SrcIP   net.IP
	DstIP   net.IP
	Proto   uint8
	SrcPort uint16
	DstPort uint16
}

func parseNFLOGDatagram(data []byte) ([]nflogPacket, error) {
	var out []nflogPacket
	for len(data) >= 16 {
		msgLen := int(binary.LittleEndian.Uint32(data[0:]))
		if msgLen < 16 || msgLen > len(data) {
			break
		}
		msgType := binary.LittleEndian.Uint16(data[4:])
		payload := data[16:msgLen]
		if msgType>>8 == nfnlSubsysUlog && msgType&0xff == nfulnlMsgPacket {
			if p, ok := parseNFLOGPacket(payload); ok {
				out = append(out, p)
			}
		}
		// Advance to next message (4-byte aligned).
		adv := (msgLen + 3) &^ 3
		if adv >= len(data) {
			break // unpadded/truncated tail — never slice past the buffer
		}
		data = data[adv:]
	}
	return out, nil
}

func parseNFLOGPacket(payload []byte) (nflogPacket, bool) {
	var p nflogPacket
	if len(payload) < 4 {
		return p, false
	}
	attrs := payload[4:] // skip nfgenmsg
	for len(attrs) >= 4 {
		l := int(binary.LittleEndian.Uint16(attrs[0:]))
		t := binary.LittleEndian.Uint16(attrs[2:])
		if l < 4 || l > len(attrs) {
			break
		}
		val := attrs[4:l]
		switch t {
		case nfulaAttrPrefix:
			p.Prefix = nulString(val)
		case nfulaAttrPayload:
			parseIPv4Header(val, &p)
		}
		attrs = attrs[(l+3)&^3:]
	}
	if p.SrcIP == nil {
		return p, false
	}
	return p, true
}

// parseIPv4Header extracts the 5-tuple from a raw IPv4 (+TCP/UDP) header.
func parseIPv4Header(b []byte, p *nflogPacket) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	if len(b) < ihl {
		return
	}
	p.Proto = b[9]
	p.SrcIP = net.IP(append([]byte{}, b[12:16]...))
	p.DstIP = net.IP(append([]byte{}, b[16:20]...))
	if len(b) >= ihl+4 && (p.Proto == 6 || p.Proto == 17) {
		p.SrcPort = binary.BigEndian.Uint16(b[ihl:])
		p.DstPort = binary.BigEndian.Uint16(b[ihl+2:])
	}
}

func nulString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// nflogEvent converts a parsed packet into a LayerEvent.
func nflogEvent(p nflogPacket) LayerEvent {
	return LayerEvent{
		Layer:     1,
		Timestamp: time.Now(),
		SourceIP:  p.SrcIP.String(),
		EventType: "NFLOG_PACKET",
		Details: map[string]interface{}{
			"dst_ip":   p.DstIP.String(),
			"proto":    p.Proto,
			"src_port": p.SrcPort,
			"dst_port": p.DstPort,
			"prefix":   p.Prefix,
		},
	}
}

// ---------------------------------------------------------------------------
// L2 — eBPF perf_event_array
// ---------------------------------------------------------------------------

// l2PerfEvent mirrors the struct the Layer 2 TC program emits.
// Keep in sync with firewall/layer2 C source: keep the layout simple and
// version the wire with the leading magic.
type l2PerfEvent struct {
	Magic   uint32
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Verdict uint8 // 0=allow 1=deceive 2=drop
	Pad     uint16
}

const l2PerfMagic = 0x6c326576 // "l2ev"

// l2PerfReader wraps cilium/ebpf's perf reader over the pinned map.
type l2PerfReader struct {
	rd *perf.Reader
}

// openL2Perf opens the pinned perf_event_array at mapPath.
func openL2Perf(mapPath string) (*l2PerfReader, error) {
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return nil, fmt.Errorf("l2 perf: load pinned map %s: %w", mapPath, err)
	}
	rd, err := perf.NewReader(m, os.Getpagesize()*64)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("l2 perf: new reader: %w", err)
	}
	// perf.Reader takes ownership of the map fd lifecycle via Close.
	m.Close()
	return &l2PerfReader{rd: rd}, nil
}

func (r *l2PerfReader) close() { r.rd.Close() }

// nextEvent decodes one perf record into a LayerEvent.
func (r *l2PerfReader) nextEvent() (LayerEvent, error) {
	for {
		rec, err := r.rd.Read()
		if err != nil {
			return LayerEvent{}, err
		}
		if rec.LostSamples > 0 {
			// Ring-buffer overrun: the kernel dropped samples. Count it
			// as an event so the correlator sees the pressure.
			return LayerEvent{
				Layer:     2,
				Timestamp: time.Now(),
				EventType: "PERF_LOST_SAMPLES",
				Details:   map[string]interface{}{"lost": rec.LostSamples},
			}, nil
		}
		if len(rec.RawSample) < 16 {
			continue // malformed — skip
		}
		var e l2PerfEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		if e.Magic != l2PerfMagic {
			continue // not our event layout — skip
		}
		src := make(net.IP, 4)
		dst := make(net.IP, 4)
		binary.LittleEndian.PutUint32(src, e.SrcIP)
		binary.LittleEndian.PutUint32(dst, e.DstIP)
		verdict := "allow"
		switch e.Verdict {
		case 1:
			verdict = "deceive"
		case 2:
			verdict = "drop"
		}
		return LayerEvent{
			Layer:     2,
			Timestamp: time.Now(),
			SourceIP:  src.String(),
			EventType: "L2_TC_" + strings.ToUpper(verdict),
			Details: map[string]interface{}{
				"dst_ip":   dst.String(),
				"src_port": e.SrcPort,
				"dst_port": e.DstPort,
				"proto":    e.Proto,
				"verdict":  verdict,
			},
		}, nil
	}
}

// ---------------------------------------------------------------------------
// L3 — XDP drop-counter map polling
// ---------------------------------------------------------------------------

// l3DropKey mirrors the XDP program's per-IP drop-counter key (IPv4).
type l3DropKey struct {
	IP uint32
}

// l3DropValue mirrors the XDP program's per-CPU value layout.
type l3DropValue struct {
	Count       uint64
	LastDstPort uint16
	LastProto   uint8
	Pad         uint8
}

// pollL3Drops iterates the pinned L3 drop map and aggregates per-CPU
// values into per-IP totals. Only IPs whose counters grew since the last
// poll are returned (delta-based, so the correlator sees new drops).
func pollL3Drops(mapPath string, prev map[string]uint64) (map[string]l3DropStats, error) {
	m, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return nil, fmt.Errorf("l3 poll: load pinned map %s: %w", mapPath, err)
	}
	defer m.Close()

	drops := make(map[string]l3DropStats)
	var key l3DropKey
	var values []l3DropValue

	it := m.Iterate()
	for it.Next(&key, &values) {
		var total uint64
		var lastPort uint16
		var lastProto uint8
		for _, v := range values {
			total += v.Count
			if v.Count > 0 {
				lastPort = v.LastDstPort
				lastProto = v.LastProto
			}
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, key.IP)
		ipStr := ip.String()
		if total > prev[ipStr] {
			drops[ipStr] = l3DropStats{Count: total - prev[ipStr], LastDstPort: lastPort, LastProto: lastProto}
		}
		prev[ipStr] = total
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("l3 poll: iterate: %w", err)
	}
	return drops, nil
}

// ---------------------------------------------------------------------------
// L4 — Linux audit (NETLINK_AUDIT)
// ---------------------------------------------------------------------------

// auditReader owns a NETLINK_AUDIT socket.
type auditReader struct {
	fd int
}

// openAuditNetlink opens a read-only NETLINK_AUDIT socket. Note: only one
// audit reader may exist per host (kauditd); if auditd holds it, the
// bind fails and we return the error so the caller can degrade.
func openAuditNetlink() (*auditReader, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_AUDIT)
	if err != nil {
		return nil, fmt.Errorf("audit: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: 0,
		Pid:    uint32(os.Getpid()),
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("audit: bind (is auditd running?): %w", err)
	}
	return &auditReader{fd: fd}, nil
}

func (r *auditReader) close() error { return unix.Close(r.fd) }

// auditEvent is a parsed audit datagram relevant to LSM/network.
type auditEvent struct {
	Type    uint16 // AUDIT_AVC, AUDIT_NETFILTER_PKT, ...
	Payload string
}

// Audit message types we care about (from <linux/audit.h>).
const (
	auditAVC          = 1400
	auditNetfilterPkt = 1325
	auditNetfilterCfg = 1326
	auditAnomAbort    = 1701
	auditSeccomp      = 1326 // shares value space; filtered by text
)

func (r *auditReader) readMessage(buf []byte) ([]auditEvent, error) {
	n, _, err := unix.Recvfrom(r.fd, buf, 0)
	if err != nil {
		return nil, err
	}
	return parseAuditDatagram(buf[:n])
}

func parseAuditDatagram(data []byte) ([]auditEvent, error) {
	var out []auditEvent
	for len(data) >= 16 {
		msgLen := int(binary.LittleEndian.Uint32(data[0:]))
		if msgLen < 16 || msgLen > len(data) {
			break
		}
		msgType := binary.LittleEndian.Uint16(data[4:])
		payload := data[16:msgLen]
		switch msgType {
		case auditAVC, auditNetfilterPkt, auditNetfilterCfg:
			out = append(out, auditEvent{Type: msgType, Payload: nulString(payload)})
		}
		adv := (msgLen + 3) &^ 3
		if adv >= len(data) {
			break // unpadded/truncated tail — never slice past the buffer
		}
		data = data[adv:]
	}
	return out, nil
}

// auditLayerEvent converts an audit message into a LayerEvent, extracting
// the source IP from common AVC / netfilter payload fields.
func auditLayerEvent(e auditEvent) *LayerEvent {
	evType := "AUDIT_UNKNOWN"
	switch e.Type {
	case auditAVC:
		evType = "LSM_AVC_DENIED"
	case auditNetfilterPkt:
		evType = "AUDIT_NETFILTER_PKT"
	case auditNetfilterCfg:
		evType = "AUDIT_NETFILTER_CFG"
	}
	srcIP := extractAuditIP(e.Payload)
	le := &LayerEvent{
		Layer:     4,
		Timestamp: time.Now(),
		SourceIP:  srcIP,
		EventType: evType,
		Details: map[string]interface{}{
			"audit_type": e.Type,
			"payload":    truncate(e.Payload, 512),
		},
	}
	return le
}

// extractAuditIP pulls saddr=/src= style addresses from audit text.
func extractAuditIP(payload string) string {
	for _, key := range []string{"saddr=", "src=", " SRC=", "srcaddr="} {
		if i := strings.Index(payload, key); i >= 0 {
			rest := payload[i+len(key):]
			end := strings.IndexAny(rest, " \t\n\"'")
			if end < 0 {
				end = len(rest)
			}
			if ip := net.ParseIP(rest[:end]); ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// ---------------------------------------------------------------------------
