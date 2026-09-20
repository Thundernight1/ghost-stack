# GHOST-STACK — Düzeltme Günlüğü (CHANGELOG)

Tarih: 2026-09-20
Kapsam: `ghost-stack-main_0_6ltn.zip` içindeki hayalet/sahte/çalışmayan kodun
gerçek, derlenen ve testle doğrulanan implementasyonlarla değiştirilmesi.
Mimari ve kod stili korundu; değişiklikler cerrahi.

Doğrulama durumu: `go build ./...` ✅ · `go vet ./...` ✅ ·
`go test -count=1 -timeout=120s ./...` ✅ · `go test -race ./...` ✅ ·
dashboard JS `node --check` ✅

> **Dürüstlük notu:** Aşağıda "test geçti" yazan her şey yukarıdaki
> komutlarla doğrulandı. **Gerçek kernel runtime doğrulaması yapılmadı:**
> XDP attach, NFLOG, perf-event, audit-netlink ve gerçek container spawn
> root + CAP_BPF/CAP_NET_ADMIN/CAP_AUDIT_READ gerektirir ve bu ortamda
> çalıştırılamadı. eBPF C derlemesi için arşivde `vmlinux.h` yok.

---

## 1. Layer 3 — XDP allowlist yöneticisi

**Dosya:** `firewall/layer3/allowlist_manager.go`, `firewall/layer3/allowlist_manager_test.go`

- `LoadAndAttach()` idempotent; `attached` durumu + `IsAttached()` eklendi.
- `Detach()` map/link referanslarını temizleyip durumu sıfırlıyor.
- `HasEntry()` (:188), `RemoveIP()` (:282), `PlanIPRemoval()` (:267) eklendi.
- Geniş CIDR içinde allowlist'li IP için minimal CIDR carve-out
  (hole-punching): yalnız hedef IP dışarıda bırakılır.
- `ApplyUpdate()` ve expiry-cleanup içindeki yeniden kilitleme
  deadlock'ları giderildi (`addEntryLocked`/`removeEntryLocked`).
- **Atomik `carve` aksiyonu** (:448 `carveEntriesLocked`, :735
  `SignCarveUpdate`): remove+add tek imzayla, tek kilit altında; add
  başarısız olursa in-memory + BPF map snapshot'a geri alınır.
  İmza `Remove` alanını da kapsar (`verifySignature`).
- Testler: exact /32, /24 içinden IP çıkarma, kapsam dışı IP, complement,
  carve atomikliği, carve rollback, carve sahte imza reddi.

## 2. Threat response — socket framing + atomik blok

**Dosya:** `cmd/ghost-ctl/threat_response.go`, `cmd/ghost-ctl/threat_response_test.go`

- `BETA:<length>:<json>` protokolü gerçek length-framed buffered parser.
- Parçalı (split) ve birleşik (coalesced) read'ler destekleniyor;
  frame/buffer boyut limitleri var.
- `blockIP()` (:356) artık `PlanIPRemoval()` sonucunu **tek** imzalı
  `carve` güncellemesiyle uyguluyor — yarım blok penceresi yok.
- Hiç allowlist'lenmemiş IP için sahte başarı yerine audit'e
  `NOOP_ALREADY_DENIED` yazılıyor.
- Testler: split/coalesced/incomplete/corrupt/oversize frame.

## 3. Orchestrator init, daemon lifecycle, XDP

**Dosya:** `cmd/ghost-ctl/main.go`

- `initialize()` `sync.Once` ile idempotent (`initializeOnce`, :268);
  `cmdDaemon()` içindeki çift çağrı kaldırıldı.
- Global `sessionMgr` artık oluşturulup atılmıyor.
- Alert listener init'ten çıkarıldı; yalnız daemon'da
  `startThreatListener()` (:339) ile başlıyor.
- Daemon: session rotation/expiry cleanup döngüleri + graceful
  shutdown'ta listener stop ve XDP `Detach()`.
- XDP attach daemon-only (`initializeOnce` :323); env:
  `GHOST_XDP_OBJECT` (boşsa attach atlanır), `GHOST_ALERT_SOCKET`,
  `GHOST_STATUS_ADDR`, `GHOST_AUDIT_PATH`, `GHOST_BASE_PATH`.
- XDP interface artık hardcoded `eth0` değil (`xdpIface` env ile
  yapılandırılabilir).
- `auth status` komutu eklendi.
- `container-init` re-exec dalı (:151): department container
  çocuk prosesi daemon state'ine dokunmadan `namespace.ContainerInit()`
  çalıştırır.

## 4. Read-only status API

**Dosya:** `cmd/ghost-ctl/status_api.go` (`serveStatusAPI`, :44),
`namespace/dept.go` (`ListContainers`)

- Bind: `127.0.0.1:9090` (env: `GHOST_STATUS_ADDR`).
- `GET /api/status`, `/api/allowlist`, `/api/blocks`,
  `/api/audit?limit=N`, `/api/depts`. GET dışı metodlar 405.
- Dashboard (`demo/dashboard/index.html`) artık **gerçek** API polling
  yapıyor: sayaçlar `/api/status`, aktörler + MITRE TTP vurgusu
  `/api/blocks`, canlı akış `/api/audit`, hiyerarşi ağacı `/api/depts`,
  grafik son 30 dk audit hızı. `Math.random()` veri üretimi tamamen
  silindi; API erişilemezse dashboard OFFLINE gösterir, sahte veri
  göstermez.

## 5. Audit log — hash chain + rotation

**Dosya:** `cmd/ghost-ctl/main.go` (`appendAudit` :1117,
`verifyAuditChain` :1238, `writeAuditLine`, `statAuditFile`),
`cmd/ghost-ctl/audit_chain_test.go`, `deploy/deploy.sh`

- `O_APPEND|O_CREATE|O_WRONLY`, `0600`, her kayıtta `Sync()`.
- SHA-256 `PrevHash` zinciri; `ghost-ctl audit-trail --verify`.
- Yazımlar `auditMu` ile sıralı.
- **Rotation:** inode/size takibiyle logrotate rename'i algılanır; yeni
  dosya `AUDIT_CHAIN_ROTATED` genesis entry'siyle (önceki tail hash'ine
  bağlantılı) kendi kendini doğrulayan yeni segment başlatır.
- `deploy.sh`: `copytruncate` **kaldırıldı** (append-only dosyada truncate
  EPERM verir; copy-truncate arası yazılan kayıtlar kaybolur; hash
  zinciri kırılır). Yerine rename-based rotation (`create 0600`,
  `postrotate` ile `chattr +a`). `chattr +a` artık dizine değil
  **dosyaya** uygulanıyor (dizindeki +a rename'i engellerdi).
- Kod ve dokümantasyondaki gerçek dışı "immutable" iddiaları
  "append-only + hash-chained" olarak düzeltildi.
- Testler: zincir doğrulama, tahrifat tespiti, rotation sonrası yeni
  segment + eski segmentin bağımsız doğrulanması.

## 6. AGENT-BETA — gerçek kaynaklar

**Dosya:** `agents/beta/beta.go`, `agents/beta/sources.go` (yeni),
`agents/beta/sources_test.go` (yeni), `go.mod`

- NFLOG: raw `NETLINK_NETFILTER` socket, group bind/config, paket/netlink
  attribute parser.
- L2: pinned perf-event map için `cilium/ebpf` `perf.Reader`.
- L3: pinned drop-map iterasyonu + per-CPU toplama.
- L4: `NETLINK_AUDIT` socket, AVC/netfilter parser.
- Blocking read'ler context iptalinde fd/perf reader kapatılarak
  sonlandırılıyor (watcher'larda `sync.Once` tabanlı idempotent close —
  double-close/fd reuse riski kapatıldı).
- `golang.org/x/sys` doğrudan dependency.
- Testler: sentetik NFLOG/audit datagram parser testleri ✅.
- ⚠️ **Doğrulanmadı:** gerçek kernel runtime (root/CAP_BPF gerektirir);
  L2 event struct/magic'in `layer2_tc.bpf.c` layout'uyla birebir uyumu
  gözle doğrulanmalı; `THREAT_ACTOR_PROFILED` alertinin düzenli
  profiling tetikleyicisi runtime'da test edilmedi.

## 7. Auth — WebAuthn + OTP + token

**Dosya:** `auth/session.go`, `auth/webauthn.go` (yeni), `auth/otp.go`
(yeni), `auth/webauthn_test.go` (yeni)

- Gerçek WebAuthn assertion doğrulaması: challenge karşılaştırma,
  `webauthn.get` type, origin, RP ID hash, user-present flag, credential
  ID binding, COSE EC2/ES256/P-256 parser, ECDSA imza doğrulama, signature
  counter clone detection, tek kullanımlık/süreli challenge.
- `OTPSender` arayüzü + `SMTPSender`; test sender ile uçtan uca testler.
- Token HMAC artık `DeptID`, `Tier`, `RotatedAt` dahil.
- `RegisteredDeviceCount()` eklendi.
- ✅ **Kapatılan auth açıkları (2026-09-20):**
  - `StartAuthentication()` ve `verifyFIDO2Attestation()` silindi —
    assertion'sız OTP üreten yol artık yok. Login yalnızca gerçek
    WebAuthn ceremony (`BeginWebAuthnAuth` → imzalı assertion →
    `CompleteWebAuthnAuth`) ile mümkün.
  - `issueOTP()` artık kodu çağırana dönmüyor; dönen challenge'da
    `Code == ""`. Kod yalnız sunucu tarafındaki pending kayıtta ve
    `OTPSender` üzerinden kullanıcıya gidiyor. OTP karşılaştırma
    constant-time (`subtle.ConstantTimeCompare`); HMAC karşılaştırma
    `hmac.Equal`.
  - `ValidateSession()` artık `EncryptedPayload`'u AES-GCM ile çözüp
    `TokenID`/`DeptID`/`UserEmail`/`Tier`/fingerprint/issued/expiry
    alanlarını zarfla karşılaştırıyor (`verifyTokenPayload`).
    Zarf-payload uyumsuzluğu reddediliyor.
- Testler güvenli modele geçirildi: `auth/ceremony_test.go` gerçek
  P-256 anahtar + imzalı assertion üreten helper'lar içeriyor;
  concurrent test race-safe `routeSender` kullanıyor; payload-tamper
  regresyon testi eklendi.

## 8. Layer 2 — deception TLS sertifikası

**Dosya:** `firewall/layer2/deception_responder.go`,
`firewall/layer2/deception_responder_test.go`

- Sahte PEM silindi; ECDSA P-256 + `crypto/x509` ile 24 saatlik gerçek
  sertifika, PEM encoding, `tls.X509KeyPair()`.
- Testler: validity, benzersizlik, gerçek TLS handshake, self-signature
  (`CheckSignature`, CA olmayan leaf için `CheckSignatureFrom` değil).

## 9. Container izolasyonu — pivot_root + /dev + fatal hatalar

**Dosya:** `namespace/container_init.go` (yeni),
`namespace/container_init_test.go` (yeni), `namespace/dept.go`,
`cmd/ghost-ctl/main.go` (:151)

- `SpawnDepartment` artık `/proc/self/exe container-init` re-exec yapar;
  çocuk `namespace.ContainerInit()` (:32) içinde:
  1. mount'ları private yapar (host'a propagation yok),
  2. rootfs'i kendine bind edip **pivot_root** yapar (belgelendiği halde
     hiç yapılmıyordu — container host rootfs'inde çalışıyordu),
  3. `/proc`, `/sys` (ro), `/dev` (tmpfs) + `devpts` mount eder,
  4. **gerçek** device node'ları (`null, zero, full, random, urandom, tty`)
     eski root üzerinden bind-mount eder (sahte/mknod yok),
  5. eski root'u `MNT_DETACH` ile ayırır,
  6. department init'i exec'ler (`/sbin/init`, yoksa `/bin/sh`).
- Ebeveyn tarafı bind-mount'lar (agent binary ro, alert socket) artık
  `cmd.Start()` **öncesi** yapılıyor (önceki pivot-yarışı giderildi).
- Hata yutma kaldırıldı: hostname, veth pair, cgroup ataması
  başarısız olursa spawn **fail** olur ve `destroyFailedSpawn` (:376)
  ile tam temizlik yapılır (SIGKILL + unmount + cgroup silme). Yarım
  izole container asla "running" kaydedilmez.
- `awaitContainerInit` (:394): pivot/exec sırasında ölen init
  `Wait4(WNOHANG)` ile yakalanır, ölü PID kaydedilmez.
- Testler: `ContainerInit` guard'ları (env'siz çalışmayı reddeder).
  Gerçek spawn root gerektirir — **runtime'da doğrulanmadı**.
- Bilinen eksik: tam stop/teardown lifecycle hâlâ yok (zombi birikimini
  önlemek için reaper goroutine eklendi).

## 10. systemd unitleri

**Dosya:** `systemd/ghost-agent-beta.service`,
`systemd/ghost-agent-alpha@.service`, `systemd/ghost-orchestrator.service`

- Agent unitlerindeki **yok sayılan `--flag` argümanları silindi**
  (binary'ler flag parse etmiyor; `--dept-id=%i` sessizce yutulup bütün
  instance'lar dept 0 izliyordu). Unitler env-var modeline geçirildi:
  `GHOST_NFLOG_GROUP`, `GHOST_L2_PERF_MAP`, `GHOST_L3_DROP_MAP`,
  `GHOST_DEPT_ID=%i`, `GHOST_BPF_OBJECT`, `GHOST_ALERT_SOCKET`.
- Beta map yolları binary default'larıyla eşitlendi:
  `/sys/fs/bpf/ghost-stack/l2_events`, `/sys/fs/bpf/ghost-stack/l3_drops`
  (unitte yanlış `ghost_l2_events` yazıyordu).
- Orchestrator unit'e `GHOST_XDP_OBJECT` ve `GHOST_STATUS_ADDR` eklendi.

## 11. CI ve deploy

**Dosya:** `.github/workflows/ci.yml`, `deploy/deploy.sh`

- CI: gerçek `gosec` + `staticcheck` adımı eklendi (önceki "security
  scan" adımı sadece echo'ydu). Sahte SonarCloud adımı gerçek
  `sonarqube-scan-action` ile değiştirildi ve `SONAR_TOKEN` yoksa
  **skip** oluyor (analiz yapmış gibi davranmıyor).
- `deploy.sh`: logrotate düzeltmesi (bkz. §5).

## 12. `.gitignore`

`*.o`, `*.a`, `*.test`, `*.bak`, `*.swp`, `*.swo`, `*~`, `*.orig`,
`*.rej`, `.DS_Store`, `.cache/`, `tmp/` eklendi.

## 13. Bilinen sınırlamalar (dürüst liste)

- XDP/NFLOG/perf-event/audit-netlink/container-spawn gerçek kernel
  runtime'ı root gerektirir — parser ve zincir mantığı test edildi,
  kernel etkileşimi edilmedi.
- eBPF C derlemesi için arşivde `vmlinux.h` yok.
- Auth açıkları kapatıldı (§7): assertion'sız OTP yolu silindi, OTP kodu
  artık çağırana dönmüyor, token validation encrypted payload'u zarfla
  karşılaştırıyor.
- Container stop/teardown lifecycle yok; audit rotation dışında
  `pivot_root` sonrası eski mount'ların host'ta kalma durumu deploy'da
  izlenmeli.
- Dashboard status API'yi aynı origin'den bekler (reverse proxy / SSH
  tüneli gerekir); API kapalıysa OFFLINE gösterir.

## 14. CI — security scan pin'leri ve bulgu triyajı (2026-09-20)

**Dosya:** `.github/workflows/ci.yml`, `auth/webauthn.go`, `auth/session.go`,
`agents/beta/sources.go`, `firewall/layer3/allowlist_manager.go`,
`firewall/layer2/deception_responder.go`, `cmd/ghost-ctl/main.go`,
`cmd/ghost-ctl/status_api.go`, `cmd/agent-alpha/main.go`,
`cmd/agent-beta/main.go`

Kök neden: `go install ...@latest` ile kurulan gosec/staticcheck'in yeni
sürümleri Go >= 1.25/1.26 istiyor ve yeni kurallar ekledi; CI'daki Go 1.22.2
ile 4. adım ("Security Scan") main'de de dependabot PR'larında da kırmızıydı.
Gerçek gosec bu kodda daha önce hiç yeşil olmamıştı (önceden echo stub'du).

- gosec `v2.22.0`, staticcheck `v0.5.1`'e pin'lendi (CI'daki Go 1.22.2 ile
  çalışan en yeni sürümler); gerekçesi ci.yml'de yorum olarak yazılı.
- 6 staticcheck bulgusu düzeltildi: kullanılmayan `ensureLoopback` ve
  `AllowlistManager.addEntry` silindi, 4 hata metni küçültüldü, argümansız
  `fmt.Sprintf` kaldırıldı.
- 19 G115 (int overflow) bulgusu tek tek incelendi:
  - `auth/webauthn.go` CBOR çözümleyiciye gerçek range-check eklendi
    (negatif int ve map anahtarı `math.MaxInt64` üstündeyse reddedilir);
    ayrıca saldırgan-kontrollü `make` size-hint'i kaldırıldı (bellek
    tüketimi DoS'u) ve iç içe map'ler için derinlik sınırı (32) eklendi.
  - Sınırı kanıtlanabilir güvenli dönüşümlere (prefix len 0-32, deptID
    0-99, pid, sabitler, fingerprint hash girdisi) gerekçeli
    `// #nosec G115` eklendi.
  - `GHOST_PID_NS` negatife, `GHOST_NFLOG_GROUP` 0-65535 aralığına
    doğrulandı.
- Denetlenen false-positive sınıfları ci.yml'de gerekçesiyle exclude edildi:
  G104 (42, hepsi LOW Close/Encode), G204 (26, hepsi shell'siz
  `exec.Command` + sabit binary), G304 (24, hepsi daemon-içi procfs/cgroup/
  config yolu), G301/G302/G306 (21, container için 0755/0644/0660).
  Tehlikeli sınıflar (G101, G201, G401-G405, G115 dahil) aktif.
- Doğrulama: `gosec` 0 bulgu, `staticcheck` temiz, `go vet` temiz,
  3 binary derleniyor, CI test alt kümesi geçiyor.

## 15. CI — Go 1.25'e geçiş ve staticcheck v0.7.0 (2026-09-20)

**Dosya:** `.github/workflows/ci.yml`, `go.mod`, `auth/webauthn.go`

`github.com/cilium/ebpf v0.22.0` (dependabot PR #12) `go >= 1.25` istiyor;
CI'daki Go 1.22.2 + staticcheck v0.5.1 kombinasyonu 4. adımı tekrar kırdı
(v0.5.1, Go 1.25'in export formatını okuyamıyor:
`internal error ... unsupported version: 2`).

- CI `go-version: '1.25'`'e çekildi; `go.mod`'daki `go` direktifi de
  `1.25.0` oldu (ebpf bağımlılığı bunu zaten zorunlu kılıyordu).
- staticcheck `v0.7.0`'a pin'lendi (Go 1.25 export formatını anlayan en eski
  sürüm); gosec `v2.22.0`'da kaldı (Go 1.25 altında 0 bulgu doğrulandı).
- v0.7.0'ın tek yeni bulgusu düzeltildi: `auth/webauthn.go`'daki
  `elliptic.Curve.IsOnCurve` (SA1019, Go 1.21'den beri deprecated) yerine
  `crypto/ecdh` ile on-curve doğrulaması; dönüş tipi (`*ecdsa.PublicKey`)
  ve davranış aynı.
- Doğrulama: `gosec` 0 bulgu, `staticcheck v0.7.0` temiz, `go vet` temiz,
  3 binary derleniyor, `go test ./...` geçiyor.
