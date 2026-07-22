FROM node:20-alpine AS frontend
WORKDIR /app
COPY nexus-vue/package*.json ./
RUN npm ci
COPY nexus-vue/ ./
RUN npm run build

FROM golang:1.23-alpine AS backend
RUN apk add --no-cache gcc musl-dev
WORKDIR /build
COPY nexus/ .
COPY --from=frontend /app/dist ./internal/static/dist
RUN CGO_ENABLED=1 go build -tags production -o nexus ./cmd/nexus

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
RUN addgroup -g 1000 nexus && adduser -D -u 1000 -G nexus nexus
WORKDIR /app
COPY --from=backend /build/nexus .
RUN chown nexus:nexus /app/nexus
VOLUME ["/data"]
EXPOSE 8080
USER nexus
ENTRYPOINT ["./nexus"]