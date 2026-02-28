VERSION ?= dev
COMMIT ?= unknown
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: dev-up dev-down dev-logs \
	hub-build hub-test hub-lint hub-migrate hub-build-prod \
	fe-install fe-build fe-test fe-lint \
	build-agent agent-build agent-test \
	dev-keys seed shellcheck \
	test build-all

# Development environment
dev-up:
	docker compose -f docker/compose.dev.yml up -d

dev-down:
	docker compose -f docker/compose.dev.yml down

dev-logs:
	docker compose -f docker/compose.dev.yml logs -f

dev-keys:
	bash scripts/gen-dev-keys.sh

seed:
	bash scripts/seed-admin.sh

shellcheck:
	shellcheck deploy/setup.sh deploy/upgrade.sh scripts/*.sh

# Hub backend
hub-build:
	go build -o bin/nodepass-hub ./cmd/server

hub-test:
	go test -race -count=1 ./...

hub-lint:
	golangci-lint run ./...

hub-migrate:
	migrate -path migrations/ -database $$DATABASE_URL up

hub-build-prod:
	go build \
		-ldflags="-s -w \
		-X main.Version=$(VERSION) \
		-X main.Commit=$(COMMIT) \
		-X main.BuildTime=$(BUILD_TIME)" \
		-o bin/nodepass-hub ./cmd/server

# Frontend
fe-install:
	cd frontend && npm ci

fe-build:
	cd frontend && npm run build

fe-test:
	cd frontend && npm run test -- --run

fe-lint:
	cd frontend && npm run lint

# Agent
build-agent:
	@echo "Checking embedded NodePass binaries..."
	@test -f nodepass-agent/embedfs/nodepass_linux_amd64 || (echo "ERROR: missing nodepass-agent/embedfs/nodepass_linux_amd64"; exit 1)
	@test -f nodepass-agent/embedfs/nodepass_linux_arm64 || (echo "ERROR: missing nodepass-agent/embedfs/nodepass_linux_arm64"; exit 1)
	@test -f nodepass-agent/embedfs/nodepass_darwin_amd64 || (echo "ERROR: missing nodepass-agent/embedfs/nodepass_darwin_amd64"; exit 1)
	cd nodepass-agent && mkdir -p bin && go build -o bin/nodepass-agent ./cmd/agent
	@echo "Agent size: $$(du -sh nodepass-agent/bin/nodepass-agent | cut -f1)"

agent-build: build-agent

agent-test:
	cd nodepass-agent && go test -race ./...

# Full
test:
	$(MAKE) hub-test && $(MAKE) fe-test && $(MAKE) agent-test

build-all:
	$(MAKE) hub-build && $(MAKE) fe-build && $(MAKE) agent-build
