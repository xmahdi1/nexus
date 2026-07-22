# ── Nexus Makefile ────────────────────────────────────────────────────────────
# Assumes the frontend lives at ../nexus-vue relative to this Makefile.
# Adjust FRONTEND_DIR if your layout differs.

BINARY      = nexus
FRONTEND_DIR = ../nexus-vue
STATIC_DIR  = internal/static/dist

.PHONY: all build build-fe build-go dev setup clean docker docker-push


all: build


build: build-fe build-go

build-fe:
	@echo "▶ Building frontend…"
	cd $(FRONTEND_DIR) && npm ci && npm run build
	rm -rf $(STATIC_DIR)
	cp -r $(FRONTEND_DIR)/dist $(STATIC_DIR)
	@echo "✓ Frontend built → $(STATIC_DIR)"

build-go:
	@echo "▶ Building Go binary (production)…"
	CGO_ENABLED=1 go build \
		-tags production \
		-ldflags="-s -w" \
		-o $(BINARY) \
		./cmd/nexus
	@echo "✓ Binary: ./$(BINARY)"


dev:
	go run ./cmd/nexus

setup:
	go run ./cmd/nexus setup


docker:
	docker build -t nexus-app/nexus:latest .

docker-push:
	docker push nexus-app/nexus:latest

clean:
	rm -f $(BINARY)
	rm -rf $(STATIC_DIR)
	@echo "✓ Cleaned"