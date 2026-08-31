.PHONY: all build test test-go test-py lint clean proto run-gateway run-guard

GO ?= /Users/up-mac/.local/go/bin/go
PYTHON ?= /opt/miniconda3/bin/python

all: build

build:
	$(GO) build -o bin/noject-gateway cmd/gateway/main.go

test: test-go test-py

test-go:
	$(GO) test -v -race ./...

test-py:
	cd guard-engine && $(PYTHON) -m pytest tests/ -v

bench: bench-go bench-py bench-models

bench-go:
	$(GO) test -bench=. -benchmem -run=^$$ ./internal/waf/... ./internal/audit/...

bench-py:
	$(PYTHON) guard-engine/benchmark.py

bench-models:
	$(PYTHON) guard-engine/model_evaluator.py

clean:
	rm -rf bin/ logs/ *.log
