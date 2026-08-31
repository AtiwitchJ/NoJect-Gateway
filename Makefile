.PHONY: all build test test-go test-py test-python-lib test-ts-lib test-libs build-libs lint clean proto run-gateway run-guard

GO ?= /Users/up-mac/.local/go/bin/go
PYTHON ?= /opt/miniconda3/bin/python
UV ?= /opt/miniconda3/bin/uv
NPM ?= /Users/up-mac/.local/bin/npm

all: build build-libs

build:
	$(GO) build -o bin/noject-gateway cmd/gateway/main.go

build-libs:
	cd packages/noject-python && $(UV) build
	cd packages/noject-ts && $(NPM) run build

test: test-go test-py test-libs

test-go:
	$(GO) test -v -race ./...

test-py:
	cd guard-engine && $(PYTHON) -m pytest tests/ -v

test-libs: test-python-lib test-ts-lib

test-python-lib:
	cd packages/noject-python && $(UV) run pytest tests/ -v

test-ts-lib:
	cd packages/noject-ts && $(NPM) test

bench: bench-go bench-py bench-models

bench-go:
	$(GO) test -bench=. -benchmem -run=^$$ ./internal/waf/... ./internal/audit/...

bench-py:
	$(PYTHON) guard-engine/benchmark.py

bench-models:
	$(PYTHON) guard-engine/model_evaluator.py

clean:
	rm -rf bin/ logs/ *.log packages/noject-python/dist packages/noject-ts/dist

