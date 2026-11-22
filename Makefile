.PHONY: build test vet run api agent downloads mkmanifest docker

AGENT_VERSION ?= 0.1.0

build: api agent downloads mkmanifest

api:
	CGO_ENABLED=1 go build -o bin/ssh-sync-api ./cmd/api

agent:
	CGO_ENABLED=0 go build -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=$(AGENT_VERSION)" -o bin/ssh-sync ./cmd/agent

mkmanifest:
	CGO_ENABLED=0 go build -trimpath -o bin/mkmanifest ./cmd/mkmanifest

downloads:
	@mkdir -p downloads
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=$(AGENT_VERSION)" -o downloads/ssh-sync-linux-amd64 ./cmd/agent
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=$(AGENT_VERSION)" -o downloads/ssh-sync-linux-arm64 ./cmd/agent
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=$(AGENT_VERSION)" -o downloads/ssh-sync-windows-amd64.exe ./cmd/agent
	cd downloads && zip -j ssh-sync-windows-amd64.zip ssh-sync-windows-amd64.exe
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=$(AGENT_VERSION)" -o downloads/ssh-sync-darwin-amd64 ./cmd/agent
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=$(AGENT_VERSION)" -o downloads/ssh-sync-darwin-arm64 ./cmd/agent

vet:
	go vet ./...

test: vet
	go test ./...
	node web/keygen_test.mjs
	node web/login_form_test.mjs
	node web/auth_no_password_test.mjs
	node web/open_account_archive_test.mjs

run: api
	./bin/ssh-sync-api -addr :8080 -db data/ssh-sync.db -web web

docker:
	docker build --build-arg AGENT_VERSION=$(AGENT_VERSION) -t ssh-sync-api .
