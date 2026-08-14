GO ?= $(HOME)/.local/go/bin/go
PY ?= .venv/bin/python
VERSION ?= dev

.PHONY: all fixtures test conform mutate build image clean fmt

# The default target is the one that must pass before anything ships. Running
# the conformance suite without the mutation check would tell you the fixtures
# agree with Go, but not whether the fixtures are capable of disagreeing.
all: fmt test mutate

fmt:
	$(GO) fmt ./...
	$(GO) vet ./...

# Regenerate the golden files from revoco. Only ever run deliberately: the
# fixtures are the oracle, and an oracle that regenerates itself whenever the
# code changes is not an oracle.
fixtures:
	$(PY) -m recoup.generate

test conform:
	$(GO) test -count=1 ./...

mutate:
	python3 conformance/mutate.py

build:
	$(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" \
	  -o bin/recoup-enforcer ./cmd/recoup-enforcer
	@echo "binary: $$(du -h bin/recoup-enforcer | cut -f1)"

image:
	docker build --build-arg VERSION=$(VERSION) -t recoup-enforcer:$(VERSION) .

clean:
	rm -rf bin
