// Package layer2 implements fake service responders for GHOST-STACK CORE
// Layer 2 deception firewall.
//
// These fake services respond to connections on L2 ports:
//   - 8443: Fake Kubernetes API server
//   - 9200: Fake Elasticsearch API
//   - 5601: Fake Kibana dashboard
//   - 2375: Fake Docker API (unencrypted — honeypot bait)
//   - 4789: VXLAN overlay probe responder
//
// All responses contain synthetic but plausible-looking data.
// Fake credentials "work" — attackers get "access" to synthetic environments.
// All credential attempts and payloads are captured and sent to AGENT-BETA.
package layer2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DeceptionListener manages all fake service listeners.
type DeceptionListener struct {
	mu        sync.Mutex
	listeners []net.Listener
	servers   []*http.Server
	stopCh    chan struct{}
	alertFunc func(event DeceptionEvent)
}

// DeceptionEvent represents an interaction with a fake service.
type DeceptionEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	SourceIP    string            `json:"source_ip"`
	SourcePort  int               `json:"source_port"`
	Service     string            `json:"service"`
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	UserAgent   string            `json:"user_agent"`
	Credentials *CredAttempt      `json:"credentials,omitempty"`
}

// CredAttempt represents a captured credential attempt.
type CredAttempt struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token,omitempty"`
	Method   string `json:"method"` // basic, bearer, api_key, etc.
}

// NewDeceptionListener creates a new deception service manager.
func NewDeceptionListener(alertFn func(DeceptionEvent)) *DeceptionListener {
	return &DeceptionListener{
		stopCh:    make(chan struct{}),
		alertFunc: alertFn,
	}
}

// Start launches all fake service listeners.
func (dl *DeceptionListener) Start() error {
	// Port 8443: Fake Kubernetes API server.
	if err := dl.startTLSService(8443, "kubernetes", dl.kubernetesHandler()); err != nil {
		return fmt.Errorf("k8s API start: %w", err)
	}

	// Port 9200: Fake Elasticsearch API.
	if err := dl.startHTTPService(9200, "elasticsearch", dl.elasticsearchHandler()); err != nil {
		return fmt.Errorf("elasticsearch start: %w", err)
	}

	// Port 5601: Fake Kibana dashboard.
	if err := dl.startHTTPService(5601, "kibana", dl.kibanaHandler()); err != nil {
		return fmt.Errorf("kibana start: %w", err)
	}

	// Port 2375: Fake Docker API (unencrypted — intentional honeypot bait).
	if err := dl.startHTTPService(2375, "docker", dl.dockerHandler()); err != nil {
		return fmt.Errorf("docker API start: %w", err)
	}

	return nil
}

// Stop shuts down all fake services.
func (dl *DeceptionListener) Stop() {
	close(dl.stopCh)
	dl.mu.Lock()
	defer dl.mu.Unlock()

	for _, s := range dl.servers {
		s.Close()
	}
	for _, l := range dl.listeners {
		l.Close()
	}
}

// startHTTPService starts an HTTP fake service on the given port.
func (dl *DeceptionListener) startHTTPService(port int, name string, handler http.Handler) error {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	dl.mu.Lock()
	dl.listeners = append(dl.listeners, ln)
	dl.servers = append(dl.servers, srv)
	dl.mu.Unlock()

	go srv.Serve(ln)
	return nil
}

// startTLSService starts a TLS fake service with a self-signed cert.
func (dl *DeceptionListener) startTLSService(port int, name string, handler http.Handler) error {
	cert, err := generateSelfSignedCert(name)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	dl.mu.Lock()
	dl.listeners = append(dl.listeners, ln)
	dl.servers = append(dl.servers, srv)
	dl.mu.Unlock()

	go srv.Serve(ln)
	return nil
}

// captureRequest logs a deception event and extracts credentials.
func (dl *DeceptionListener) captureRequest(r *http.Request, service string) {
	if dl.alertFunc == nil {
		return
	}

	event := DeceptionEvent{
		Timestamp: time.Now(),
		SourceIP:  extractIP(r.RemoteAddr),
		Service:   service,
		Method:    r.Method,
		Path:      r.URL.Path,
		UserAgent: r.UserAgent(),
		Headers:   extractHeaders(r),
	}

	// Extract credentials from various authentication methods.
	event.Credentials = extractCredentials(r)

	dl.alertFunc(event)
}

// --- Fake Kubernetes API Server (port 8443) ---

func (dl *DeceptionListener) kubernetesHandler() http.Handler {
	mux := http.NewServeMux()

	// K8s API version endpoint.
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "kubernetes")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"kind":     "APIVersions",
			"versions": []string{"v1"},
			"serverAddressByClientCIDRs": []map[string]string{
				{"clientCIDR": "0.0.0.0/0", "serverAddress": "10.200.0.1:8443"},
			},
		})
	})

	// K8s API discovery.
	mux.HandleFunc("/api/v1", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "kubernetes")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"kind":         "APIResourceList",
			"groupVersion": "v1",
			"resources": []map[string]interface{}{
				{"name": "pods", "namespaced": true, "kind": "Pod"},
				{"name": "services", "namespaced": true, "kind": "Service"},
				{"name": "secrets", "namespaced": true, "kind": "Secret"},
				{"name": "configmaps", "namespaced": true, "kind": "ConfigMap"},
				{"name": "nodes", "namespaced": false, "kind": "Node"},
			},
		})
	})

	// Fake pods listing.
	mux.HandleFunc("/api/v1/namespaces/default/pods", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "kubernetes")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(generateFakePods())
	})

	// Fake secrets — high-value deception target.
	mux.HandleFunc("/api/v1/namespaces/default/secrets", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "kubernetes")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(generateFakeSecrets())
	})

	// Catch-all.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "kubernetes")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"kind":    "Status",
			"status":  "Failure",
			"message": "the server could not find the requested resource",
			"reason":  "NotFound",
			"code":    404,
		})
	})

	return mux
}

// --- Fake Elasticsearch API (port 9200) ---

func (dl *DeceptionListener) elasticsearchHandler() http.Handler {
	mux := http.NewServeMux()

	// ES cluster info.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":         "ghost-es-node-01",
			"cluster_name": "ghost-production",
			"cluster_uuid": "xR4d1a2bTy-ghost-internal",
			"version": map[string]interface{}{
				"number":         "8.12.0",
				"build_flavor":   "default",
				"build_type":     "deb",
				"build_hash":     "abc123def456",
				"build_date":     "2024-01-15T10:00:00.000Z",
				"lucene_version": "9.9.1",
			},
			"tagline": "You Know, for Search",
		})
	})

	// Fake indices listing.
	mux.HandleFunc("/_cat/indices", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "elasticsearch")
		w.Header().Set("Content-Type", "text/plain")
		indices := []string{
			"green open employees-2024       5 1 15432  0  45mb  22mb",
			"green open payroll-confidential  3 1  8921  0  128mb  64mb",
			"green open internal-comms        5 1 89234  0  512mb  256mb",
			"green open security-logs         10 1 456789 0  2gb  1gb",
			"green open api-keys-vault        1 1  342   0  1mb  512kb",
		}
		fmt.Fprint(w, strings.Join(indices, "\n"))
	})

	// Fake search — returns synthetic but plausible employee data.
	mux.HandleFunc("/_search", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "elasticsearch")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(generateFakeSearchResults())
	})

	return mux
}

// --- Fake Kibana (port 5601) ---

func (dl *DeceptionListener) kibanaHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "kibana")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":    "ghost-kibana",
			"uuid":    "k1b4n4-gh05t-1nt3rn4l",
			"version": map[string]string{"number": "8.12.0"},
			"status": map[string]interface{}{
				"overall": map[string]string{"state": "green", "title": "Green"},
			},
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "kibana")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Kibana - Ghost Internal</title></head>
<body><div id="kbn-loading-message">Loading Ghost Internal Kibana...</div></body></html>`)
	})

	return mux
}

// --- Fake Docker API (port 2375) --- HIGH VALUE HONEYPOT ---

func (dl *DeceptionListener) dockerHandler() http.Handler {
	mux := http.NewServeMux()

	// Docker version — this is what attackers check first.
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "docker")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Version":       "24.0.7",
			"ApiVersion":    "1.43",
			"MinAPIVersion": "1.12",
			"Os":            "linux",
			"Arch":          "amd64",
			"KernelVersion": "6.1.0-ghost",
			"BuildTime":     "2024-01-15T10:00:00.000000000+00:00",
		})
	})

	// Docker info — rich synthetic data.
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "docker")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"Containers":        42,
			"ContainersRunning": 38,
			"ContainersPaused":  0,
			"ContainersStopped": 4,
			"Images":            127,
			"Name":              "ghost-docker-host-prod-01",
			"OperatingSystem":   "Ubuntu 22.04.3 LTS",
			"Architecture":      "x86_64",
			"NCPU":              16,
			"MemTotal":          68719476736,
		})
	})

	// Fake container listing.
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "docker")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(generateFakeContainers())
	})

	// Catch-all: accept any command (capture payload).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		dl.captureRequest(r, "docker")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "OK",
		})
	})

	return mux
}

// --- Fake data generators ---

func generateFakePods() map[string]interface{} {
	pods := []map[string]interface{}{
		fakePod("api-gateway-7b5f9d8c4f-x2k9m", "ghost-api", "Running"),
		fakePod("auth-service-5c4d3b2a1f-p8n7q", "ghost-auth", "Running"),
		fakePod("payment-processor-9d8e7f6g5h-y4w3r", "ghost-payments", "Running"),
		fakePod("db-migration-job-completed-k8j2l", "ghost-db", "Succeeded"),
		fakePod("monitoring-agent-3a2b1c0d9e-m6n5o", "ghost-monitor", "Running"),
	}
	return map[string]interface{}{
		"kind":       "PodList",
		"apiVersion": "v1",
		"items":      pods,
	}
}

func fakePod(name, image, phase string) map[string]interface{} {
	return map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": "default",
			"labels":    map[string]string{"app": image, "env": "production"},
		},
		"spec": map[string]interface{}{
			"containers": []map[string]string{
				{"name": image, "image": fmt.Sprintf("ghost-registry.internal/%s:latest", image)},
			},
		},
		"status": map[string]string{"phase": phase},
	}
}

func generateFakeSecrets() map[string]interface{} {
	return map[string]interface{}{
		"kind":       "SecretList",
		"apiVersion": "v1",
		"items": []map[string]interface{}{
			{
				"metadata": map[string]string{"name": "db-credentials", "namespace": "default"},
				"type":     "Opaque",
				"data": map[string]string{
					"username": "Z2hvc3RfZGJfYWRtaW4=",     // ghost_db_admin (fake)
					"password": "c3VwZXJfc2VjcmV0X3Bhc3M=", // super_secret_pass (fake)
				},
			},
			{
				"metadata": map[string]string{"name": "api-keys", "namespace": "default"},
				"type":     "Opaque",
				"data": map[string]string{
					"stripe-key": "c2tfdGVzdF9mYWtlX2tleQ==", // fake
					"aws-key":    "QUtJQUZBS0VGQUtFRkFLRQ==", // fake
				},
			},
		},
	}
}

func generateFakeSearchResults() map[string]interface{} {
	fakeEmployees := []map[string]interface{}{
		{"_source": map[string]string{"name": "John Mitchell", "dept": "Engineering", "email": "john.m@xio.cybersurhub.com", "badge": "EMP-4521"}},
		{"_source": map[string]string{"name": "Sarah Chen", "dept": "Security", "email": "sarah.c@xio.cybersurhub.com", "badge": "EMP-1892"}},
		{"_source": map[string]string{"name": "Michael Torres", "dept": "Finance", "email": "michael.t@xio.cybersurhub.com", "badge": "EMP-3344"}},
	}
	return map[string]interface{}{
		"took":      3,
		"timed_out": false,
		"hits": map[string]interface{}{
			"total": map[string]interface{}{"value": 15432, "relation": "eq"},
			"hits":  fakeEmployees,
		},
	}
}

func generateFakeContainers() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"Id":     "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
			"Names":  []string{"/ghost-api-gateway"},
			"Image":  "ghost-registry.internal/api-gateway:2.1.4",
			"State":  "running",
			"Status": "Up 14 days",
			"Ports":  []map[string]interface{}{{"PrivatePort": 8080, "PublicPort": 80, "Type": "tcp"}},
		},
		{
			"Id":     "b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7",
			"Names":  []string{"/ghost-auth-service"},
			"Image":  "ghost-registry.internal/auth-service:3.0.1",
			"State":  "running",
			"Status": "Up 14 days",
			"Ports":  []map[string]interface{}{{"PrivatePort": 9090, "Type": "tcp"}},
		},
		{
			"Id":     "c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
			"Names":  []string{"/ghost-postgres-primary"},
			"Image":  "postgres:16-alpine",
			"State":  "running",
			"Status": "Up 30 days",
			"Ports":  []map[string]interface{}{{"PrivatePort": 5432, "Type": "tcp"}},
		},
	}
}

// --- Utility functions ---

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func extractHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)
	for key, vals := range r.Header {
		headers[key] = strings.Join(vals, ", ")
	}
	return headers
}

func extractCredentials(r *http.Request) *CredAttempt {
	// Check Basic auth.
	if user, pass, ok := r.BasicAuth(); ok {
		return &CredAttempt{Username: user, Password: pass, Method: "basic"}
	}

	// Check Bearer token.
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return &CredAttempt{Token: strings.TrimPrefix(auth, "Bearer "), Method: "bearer"}
	}

	// Check API key headers.
	for _, key := range []string{"X-API-Key", "Api-Key", "X-Auth-Token"} {
		if val := r.Header.Get(key); val != "" {
			return &CredAttempt{Token: val, Method: "api_key"}
		}
	}

	return nil
}

// generateSelfSignedCert creates a real, valid short-lived self-signed
// certificate for a deception TLS listener. The subject mimics plausible
// internal infrastructure (per-service CN) so scanners fingerprint a
// boring corporate service, not a honeypot. Certificates live 24 hours —
// listeners are recycled regularly, so long-lived certs would only aid
// fingerprinting.
func generateSelfSignedCert(name string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("deception: keygen: %w", err)
	}

	serial := make([]byte, 16)
	if _, err := crand.Read(serial); err != nil {
		return tls.Certificate{}, fmt.Errorf("deception: serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serial),
		Subject: pkix.Name{
			CommonName:   name + ".internal",
			Organization: []string{"IT Infrastructure"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{name + ".internal"},
	}

	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("deception: create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("deception: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("deception: load keypair: %w", err)
	}
	// Attach the parsed leaf so handlers can inspect validity windows.
	if leaf, err := x509.ParseCertificate(der); err == nil {
		cert.Leaf = leaf
	}
	return cert, nil
}

// Note: the old math/rand seeding init() was removed — math/rand is
// auto-seeded since Go 1.20 and crypto/rand is used for key material.
