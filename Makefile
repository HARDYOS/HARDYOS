# HardyOS build entry points. Run `make help` for the list.

SHELL := /bin/bash
VERSION ?= $(shell scripts/version.sh)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
ARCH    ?= amd64
GOARCH  ?= $(ARCH)
DIST    := $(CURDIR)/dist
NFPM_VERSION ?= v2.41.1

VERSION_PKG := github.com/hardyos/hardyos/daemon/internal/version
LDFLAGS := -s -w -X $(VERSION_PKG).Version=$(VERSION) -X $(VERSION_PKG).Commit=$(COMMIT)

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

.PHONY: build
build: build-daemon build-web ## Build Go binaries and the web desktop

.PHONY: build-daemon
build-daemon: ## Build hardyd, hardyd-priv and hardyctl into dist/bin
	@mkdir -p $(DIST)/bin
	cd daemon && CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/bin/ ./cmd/...

.PHONY: build-web
build-web: web/node_modules ## Build the web desktop into web/apps/shell/dist
	cd web && pnpm build

web/node_modules: web/pnpm-lock.yaml
	cd web && pnpm install --frozen-lockfile
	@touch $@

.PHONY: test
test: test-go test-web ## Run all tests

.PHONY: test-go
test-go:
	cd daemon && test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt needed" && exit 1)
	cd daemon && go vet ./... && go test -race ./...

.PHONY: test-web
test-web: web/node_modules
	cd web && pnpm typecheck && pnpm test

.PHONY: gen
gen: web/node_modules ## Regenerate the TypeScript API client from api/openapi.yaml
	cd web && pnpm gen:api

DEV := $(CURDIR)/.dev

.PHONY: dev-daemon
dev-daemon: ## Run hardyd locally over plain HTTP on :8080 (state in .dev/)
	@mkdir -p $(DEV)
	cd daemon && go run ./cmd/hardyd -https "" -http 127.0.0.1:8080 -db $(DEV)/hardyd.db \
		-priv-socket $(DEV)/priv.sock -web-root ../web/apps/shell/dist -log-level debug

.PHONY: dev-priv
dev-priv: ## Run hardyd-priv as you on .dev/priv.sock (privileged ops will fail without root)
	@mkdir -p $(DEV)
	cd daemon && go run ./cmd/hardyd-priv -socket $(DEV)/priv.sock -allow-user $$(id -un)

.PHONY: dev-web
dev-web: web/node_modules ## Run the web desktop dev server on :5173 (proxies /api to :8080)
	cd web && pnpm dev

.PHONY: deb
deb: build ## Build the hardyos-core Debian package into dist/
	@command -v nfpm >/dev/null || go install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)
	cd packaging && VERSION=$(VERSION) ARCH=$(ARCH) $$(command -v nfpm || echo $$(go env GOPATH)/bin/nfpm) \
		package --packager deb --config nfpm.yaml --target $(DIST)/

.PHONY: iso
iso: deb ## Build the live/installer ISO into dist/ (needs Docker)
	VERSION=$(VERSION) os/build-iso.sh

.PHONY: clean
clean: ## Remove build output
	rm -rf $(DIST) web/apps/shell/dist
