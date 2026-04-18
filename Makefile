# ═══════════════════════════════════════════════════════════
# GHOST-STACK CORE — Makefile
# ═══════════════════════════════════════════════════════════

.PHONY: all build test lint clean ebpf help

BINARY     := ghost-ctl
BUILD_DIR  := build
GO         := go
CGO        := CGO_ENABLED=1
CLANG      := clang
BPF_FLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_x86
LDFLAGS    := -s -w
GOFLAGS    := -race
PACKAGES   := ./hierarchy/... ./agents/beta/... ./db/... ./auth/...
ALL_PKGS   := ./...

# ─────────────────────────────────────────────────
# Default
# ─────────────────────────────────────────────────
all: lint test build  ## Run lint, tests, and build

# ─────────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────────
build: ## Build ghost-ctl binary
	@echo "==> Building $(BINARY)..."
	@mkdir -p $(BUILD_DIR)
	$(CGO) $(GO) build -o $(BUILD_DIR)/$(BINARY) -ldflags="$(LDFLAGS)" ./cmd/ghost-ctl/
	@echo "==> Built: $(BUILD_DIR)/$(BINARY)"

# ─────────────────────────────────────────────────
# Test
# ─────────────────────────────────────────────────
test: ## Run all unit tests with race detection
	@echo "==> Running unit tests..."
	$(GO) test -v $(GOFLAGS) -count=1 -timeout=120s \
		-coverprofile=coverage.out \
		$(PACKAGES)
	@echo "==> Coverage:"
	@$(GO) tool cover -func=coverage.out | tail -1

test-short: ## Run tests without verbose output
	$(GO) test $(GOFLAGS) -count=1 -timeout=60s $(PACKAGES)

test-bench: ## Run benchmarks
	@echo "==> Running benchmarks..."
	$(GO) test -bench=. -benchmem -count=1 -timeout=120s $(PACKAGES)

coverage-html: test ## Generate HTML coverage report
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "==> Coverage report: coverage.html"

# ─────────────────────────────────────────────────
# Lint
# ─────────────────────────────────────────────────
lint: ## Run linters
	@echo "==> Running go vet..."
	$(GO) vet $(PACKAGES)
	@echo "==> Running staticcheck (if available)..."
	@which staticcheck > /dev/null 2>&1 && staticcheck $(PACKAGES) || echo "  (staticcheck not installed)"

fmt: ## Format all Go code
	$(GO) fmt $(ALL_PKGS)
	@echo "==> Code formatted"

# ─────────────────────────────────────────────────
# eBPF
# ─────────────────────────────────────────────────
ebpf: ## Compile eBPF programs (requires clang + kernel headers)
	@echo "==> Compiling eBPF programs..."
	@mkdir -p $(BUILD_DIR)/bpf
	$(CLANG) $(BPF_FLAGS) -c agents/alpha/alpha.bpf.c -o $(BUILD_DIR)/bpf/alpha.bpf.o || echo "  (alpha.bpf.c — needs vmlinux.h)"
	$(CLANG) $(BPF_FLAGS) -c firewall/layer2/layer2_tc.bpf.c -o $(BUILD_DIR)/bpf/layer2_tc.bpf.o || echo "  (layer2_tc.bpf.c — needs vmlinux.h)"
	$(CLANG) $(BPF_FLAGS) -c firewall/layer3/layer3_invisible.bpf.c -o $(BUILD_DIR)/bpf/layer3_invisible.bpf.o || echo "  (layer3_invisible.bpf.c — needs vmlinux.h)"
	@echo "==> eBPF objects: $(BUILD_DIR)/bpf/"

# ─────────────────────────────────────────────────
# Clean
# ─────────────────────────────────────────────────
clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR) coverage.out coverage.html
	@echo "==> Cleaned"

# ─────────────────────────────────────────────────
# CI (matches GitHub Actions pipeline)
# ─────────────────────────────────────────────────
ci: lint test build ## Run full CI pipeline locally
	@echo "==> CI pipeline passed ✓"

# ─────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────
help: ## Show this help
	@echo "GHOST-STACK CORE — Build Targets"
	@echo "═══════════════════════════════════"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
