FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS frontend
WORKDIR /app
COPY nexus-vue/package*.json ./
RUN npm ci
COPY nexus-vue/ ./
RUN npm run build

FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS backend
RUN apk add --no-cache gcc musl-dev
WORKDIR /build
COPY nexus/ .
COPY integrations/ansible/environment.py integrations/ansible/requirements.lock /integrations/ansible/
COPY --from=frontend /app/dist ./internal/static/dist
RUN CGO_ENABLED=1 go test ./...
ARG VERSION=dev
ARG REVISION=""
ARG BUILD_DATE=""
RUN CGO_ENABLED=1 go build -trimpath -tags production \
    -ldflags="-X github.com/xmahdi1/nexus/internal/buildinfo.version=${VERSION} -X github.com/xmahdi1/nexus/internal/buildinfo.commit=${REVISION} -X github.com/xmahdi1/nexus/internal/buildinfo.built=${BUILD_DATE}" \
    -o nexus ./cmd/nexus

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata python3
RUN addgroup -g 1000 nexus && adduser -D -u 1000 -G nexus nexus
WORKDIR /app
COPY --from=backend /build/nexus .
RUN mkdir -p /data && chown nexus:nexus /app /app/nexus /data && chmod 700 /data
ENV NEXUS_DB_PATH=/data/nexus.db
VOLUME ["/data"]
EXPOSE 8080
ARG VERSION=dev
ARG REVISION=""
ARG BUILD_DATE=""
LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.description="Self-hosted Linux infrastructure dashboard" \
      org.opencontainers.image.source="https://github.com/xmahdi1/nexus" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="Nexus"
USER nexus
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=2).close()"]
ENTRYPOINT ["./nexus"]
