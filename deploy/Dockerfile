# Obrazy ASI: server (API + UI + scheduler), worker (nmap + naabu), labweb (emulator usług laboratorium).

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund --loglevel=error
COPY web/ ./
RUN npm run build

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/asi ./cmd/asi && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/labweb ./lab/labweb

FROM golang:1.26-bookworm AS naabu
ARG NAABU_VERSION=v2.6.1
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}

FROM alpine:3.20 AS server
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/asi /usr/local/bin/asi
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s CMD ["asi", "healthcheck"]
ENTRYPOINT ["asi"]
CMD ["server"]

FROM debian:bookworm-slim AS worker
RUN apt-get update && apt-get install -y --no-install-recommends nmap libpcap0.8 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=naabu /go/bin/naabu /usr/local/bin/naabu
COPY --from=build /out/asi /usr/local/bin/asi
ENTRYPOINT ["asi"]
CMD ["worker"]

FROM alpine:3.20 AS labweb
COPY --from=build /out/labweb /usr/local/bin/labweb
ENTRYPOINT ["labweb"]
