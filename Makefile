.PHONY: help install check backend frontend docs scripts-check scripts-format format-scripts build browser recovery

PYTHON ?= $(if $(wildcard docs/validation/ci-tools/bin/python),docs/validation/ci-tools/bin/python,python3)

help:
	@echo 'install  Install locked JavaScript and Python fixture dependencies'
	@echo 'check    Run backend, frontend, docs and script checks'
	@echo 'build    Build a native binary with the production frontend'
	@echo 'browser  Run the isolated browser fixture (after build and browser install)'
	@echo 'recovery Run the isolated native CLI upgrade/rotation/recovery fixture'
	@echo 'format-scripts  Format Python, JavaScript and shell scripts'

install:
	npm --prefix nexus-vue ci
	python3 -m venv docs/validation/ci-tools
	docs/validation/ci-tools/bin/python -m pip install --require-hashes --only-binary=:all: -r scripts/requirements-ci.txt

check: backend frontend docs scripts-check

scripts-check: scripts-format
	$(PYTHON) scripts/ci/check_scripts.py
	$(PYTHON) scripts/ci/test_export_source.py
	$(PYTHON) scripts/deploy_test.py
	$(PYTHON) scripts/ansible_collections_test.py
	$(PYTHON) scripts/ansible_callback_test.py

scripts-format:
	$(PYTHON) -m ruff format --check scripts
	node nexus-vue/node_modules/prettier/bin/prettier.cjs --config nexus-vue/.prettierrc.json --check 'scripts/**/*.mjs' 'scripts/**/*.json'
	go run mvdan.cc/sh/v3/cmd/shfmt@v3.12.0 -d -i 2 -ci -sr scripts/*_lab/entrypoint.sh

format-scripts:
	$(PYTHON) -m ruff format scripts
	node nexus-vue/node_modules/prettier/bin/prettier.cjs --config nexus-vue/.prettierrc.json --write 'scripts/**/*.mjs' 'scripts/**/*.json'
	go run mvdan.cc/sh/v3/cmd/shfmt@v3.12.0 -w -i 2 -ci -sr scripts/*_lab/entrypoint.sh

backend:
	$(PYTHON) scripts/ci/check_go_format.py
	cd nexus && go build ./cmd/nexus
	cd nexus && go test -race ./...
	cd nexus && go vet ./...
	cd nexus && go mod verify

frontend:
	npm --prefix nexus-vue run lint
	npm --prefix nexus-vue run format:check
	npm --prefix nexus-vue run typecheck
	npm --prefix nexus-vue test
	npm --prefix nexus-vue run build

docs:
	$(PYTHON) scripts/ci/check_markdown_links.py

build:
	npm --prefix nexus-vue run build
	$(PYTHON) scripts/ci/build_native.py

browser:
	$(PYTHON) scripts/browser_lab.py nexus/nexus

recovery:
	$(PYTHON) scripts/native_recovery_lab.py
