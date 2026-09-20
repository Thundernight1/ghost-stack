package layer2

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestGenerateSelfSignedCert_Valid(t *testing.T) {
	cert, err := generateSelfSignedCert("webmail")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("expected parsed leaf certificate")
	}
	now := time.Now()
	if now.Before(cert.Leaf.NotBefore) || now.After(cert.Leaf.NotAfter) {
		t.Fatal("certificate not currently valid")
	}
	if cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore) > 25*time.Hour {
		t.Fatal("certificate lifetime should be short (~24h)")
	}
	if cert.Leaf.Subject.CommonName != "webmail.internal" {
		t.Errorf("CN = %q, want webmail.internal", cert.Leaf.Subject.CommonName)
	}
	// The self-signature must verify against the leaf's own public key.
	if err := cert.Leaf.CheckSignature(cert.Leaf.SignatureAlgorithm, cert.Leaf.RawTBSCertificate, cert.Leaf.Signature); err != nil {
		t.Fatalf("self-signature invalid: %v", err)
	}
}

func TestGenerateSelfSignedCert_TLSHandshake(t *testing.T) {
	cert, err := generateSelfSignedCert("vpn")
	if err != nil {
		t.Fatalf("generateSelfSignedCert: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 1)
		_, _ = conn.Read(buf) // force handshake
		serverErr <- nil
	}()

	client, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true, // self-signed by design
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte{0}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}

	state := client.ConnectionState()
	if len(state.PeerCertificates) != 1 {
		t.Fatalf("got %d peer certs, want 1", len(state.PeerCertificates))
	}
	if state.PeerCertificates[0].Subject.CommonName != "vpn.internal" {
		t.Errorf("peer CN = %q", state.PeerCertificates[0].Subject.CommonName)
	}
}

func TestGenerateSelfSignedCert_Unique(t *testing.T) {
	a, _ := generateSelfSignedCert("svc")
	b, _ := generateSelfSignedCert("svc")
	if string(a.Certificate[0]) == string(b.Certificate[0]) {
		t.Fatal("two generations must not produce identical certificates")
	}
}
