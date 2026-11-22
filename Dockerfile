# Digests pinned (linux/amd64). Update when rebasing images.
FROM golang:1.27-bookworm@sha256:fb7cceb528b47141eccd9b60bf3cbd27d5ef5f8cf5b7d338bec866da495b50dc AS build
WORKDIR /src
ARG AGENT_VERSION=0.1.0
ARG RELEASE_PRIVATE_KEY_HEX=
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=1 go build -mod=readonly -o /out/ssh-sync-api ./cmd/api
RUN mkdir -p /out/downloads
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=readonly -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=${AGENT_VERSION}" -o /out/downloads/ssh-sync-linux-amd64 ./cmd/agent && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -mod=readonly -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=${AGENT_VERSION}" -o /out/downloads/ssh-sync-linux-arm64 ./cmd/agent && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -mod=readonly -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=${AGENT_VERSION}" -o /out/downloads/ssh-sync-windows-amd64.exe ./cmd/agent
RUN apt-get update && apt-get install -y --no-install-recommends zip && \
    cd /out/downloads && zip -j ssh-sync-windows-amd64.zip ssh-sync-windows-amd64.exe && \
    rm -rf /var/lib/apt/lists/*
RUN CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -mod=readonly -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=${AGENT_VERSION}" -o /out/downloads/ssh-sync-darwin-amd64 ./cmd/agent && \
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -mod=readonly -ldflags "-X github.com/thelad-dev/ssh-sync/internal/version.Agent=${AGENT_VERSION}" -o /out/downloads/ssh-sync-darwin-arm64 ./cmd/agent
RUN CGO_ENABLED=0 go build -mod=readonly -o /out/signrelease ./cmd/signrelease
RUN if [ -n "$RELEASE_PRIVATE_KEY_HEX" ]; then \
      printf '%s\n' "$RELEASE_PRIVATE_KEY_HEX" > /tmp/release.ed25519.priv && \
      chmod 600 /tmp/release.ed25519.priv && \
      /out/signrelease -version "$AGENT_VERSION" -dir /out/downloads -key /tmp/release.ed25519.priv && \
      rm -f /tmp/release.ed25519.priv ; \
    else \
      echo "WARN: RELEASE_PRIVATE_KEY_HEX nicht gesetzt  -  Downloads ohne Signatur (Updates schlagen fehl)" >&2 ; \
    fi

FROM debian:bookworm-slim@sha256:c67e92c8099ba22853ab4cfda7cfb494d253d6012ca82dee98ba8976772af018
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 sshsync \
    && useradd --system --uid 10001 --gid sshsync --home-dir /app --shell /usr/sbin/nologin sshsync
WORKDIR /app
COPY --from=build /out/ssh-sync-api /usr/local/bin/ssh-sync-api
COPY web /app/web
COPY --from=build /out/downloads /app/downloads
RUN mkdir -p /app/data && chown -R sshsync:sshsync /app
ENV SSH_SYNC_JWT_SECRET=""
EXPOSE 8080
VOLUME ["/app/data"]
USER sshsync:sshsync
CMD ["ssh-sync-api", "-addr", ":8080", "-db", "/app/data/ssh-sync.db", "-web", "/app/web"]
