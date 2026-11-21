FROM node:22-alpine AS frontend
WORKDIR /app
COPY nexus-vue/package*.json ./
RUN npm ci
COPY nexus-vue/ ./
RUN npm run build

FROM golang:1.26-alpine AS backend
RUN apk add --no-cache gcc musl-dev
WORKDIR /build
COPY nexus/ .
COPY --from=frontend /app/dist ./internal/static/dist
RUN CGO_ENABLED=1 go test ./... && CGO_ENABLED=1 go build -tags production -o nexus ./cmd/nexus

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -g 1000 nexus && adduser -D -u 1000 -G nexus nexus
WORKDIR /app
COPY --from=backend /build/nexus .
RUN mkdir -p /data && chown nexus:nexus /app /app/nexus /data && chmod 700 /data
ENV NEXUS_DB_PATH=/data/nexus.db
VOLUME ["/data"]
EXPOSE 8080
USER nexus
ENTRYPOINT ["./nexus"]
