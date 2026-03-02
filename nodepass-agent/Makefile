VERSION ?= $(shell cat embed/VERSION 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

BIN_DIR := bin
BINARY := nodepass-agent

.PHONY: build-linux-amd64 build-linux-arm64 build-linux-386 run test docker-build download-nodepass

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -ldflags="-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)" -o $(BIN_DIR)/$(BINARY)-linux-amd64 ./cmd/agent

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -ldflags="-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)" -o $(BIN_DIR)/$(BINARY)-linux-arm64 ./cmd/agent

build-linux-386:
	GOOS=linux GOARCH=386 go build -ldflags="-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)" -o $(BIN_DIR)/$(BINARY)-linux-386 ./cmd/agent

run:
	go run ./cmd/agent

test:
	go test ./...

docker-build:
	docker build -t nodepass-agent:$(VERSION) .

download-nodepass:
	@echo "Provide NODEPASS_RELEASE_BASE to download real binaries"
	@test -n "$(NODEPASS_RELEASE_BASE)" || (echo "NODEPASS_RELEASE_BASE is required" && exit 1)
	curl -fL "$(NODEPASS_RELEASE_BASE)/nodepass_linux_amd64" -o embed/nodepass_linux_amd64
	curl -fL "$(NODEPASS_RELEASE_BASE)/nodepass_linux_arm64" -o embed/nodepass_linux_arm64
	curl -fL "$(NODEPASS_RELEASE_BASE)/nodepass_linux_386" -o embed/nodepass_linux_386
