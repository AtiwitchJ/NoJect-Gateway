.PHONY: all build test test-go test-py redteam test-python-lib test-ts-lib test-libs build-libs lint clean proto run-gateway run-guard

GO ?= go
PYTHON ?= python3
UV ?= uv
NPM ?= npm

all: build build-libs

build:
	$(GO) build -o bin/noject-gateway cmd/gateway/main.go

build-libs:
	cd packages/noject-python && $(UV) build
	cd packages/noject-ts && $(NPM) run build

run-gateway:
	$(GO) run ./cmd/gateway

run-guard:
	cd guard-engine && $(PYTHON) server.py

test: test-go test-py test-libs redteam

test-go:
	$(GO) test -v -race ./...

test-py:
	cd guard-engine && $(PYTHON) -m pytest tests/ -v

test-libs: test-python-lib test-ts-lib

test-python-lib:
	cd packages/noject-python && $(UV) run pytest tests/ -v

test-ts-lib:
	cd packages/noject-ts && $(NPM) test

# Adversarial corpora, gated against a recorded baseline (see
# guard-engine/redteam_baseline.py). Fails on regression AND on an
# un-locked-in improvement, so coverage can only ratchet upward.
redteam:
	cd guard-engine && $(PYTHON) redteam_guard.py
	cd guard-engine && $(PYTHON) redteam_guard2.py

bench: bench-go bench-py bench-models bench-sentinels

bench-go:
	$(GO) test -bench=. -benchmem -run=^$$ ./internal/waf/... ./internal/audit/...

bench-py:
	$(PYTHON) guard-engine/benchmark.py

bench-models:
	$(PYTHON) guard-engine/model_evaluator.py

bench-sentinels:
	$(PYTHON) guard-engine/sentinel_benchmark.py

clean:
	rm -rf bin/ logs/ *.log packages/noject-python/dist packages/noject-ts/dist

