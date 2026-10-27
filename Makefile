# Citadel build and verification targets. Development tools run through
# `go run tool@version`, so they never enter go.mod.

GO                  ?= go
FUZZTIME            ?= 10m
TRIALS              ?= 5
CONFIGS             ?= C0,C1-instr,C1-data,C2
IMPL                ?= model
STATICCHECK_VERSION ?= 2026.2.2
GOVULNCHECK_VERSION ?= v1.9.0
COVERAGE_MIN        ?= 90
BIN                 := bin/citadel

# Packages with the 90% statement-coverage requirement.
COVER_PKGS := ./internal/label ./internal/authz ./internal/policy ./internal/runstate \
              ./internal/signed ./internal/handoff ./internal/evidence

# Every fuzz target, as package:FuzzName.
FUZZ_TARGETS := \
	./internal/value:FuzzParseIPv4 \
	./internal/value:FuzzParseAccountID \
	./internal/value:FuzzParseHostname \
	./internal/value:FuzzDecodeStrict \
	./internal/label:FuzzJoinNeverLosesSources \
	./internal/handoff:FuzzDecodeOuter \
	./internal/handoff:FuzzDecodePayload \
	./internal/handoff:FuzzVerifyMutatedEnvelope \
	./internal/policy:FuzzApprovalKeyEncoding

.PHONY: bench concurrency all build check fmt-check vet staticcheck govulncheck test traceability coverage \
        fuzz fuzz-ci keys m1 tune eval dash clean

all: build

build:
	$(GO) build -o $(BIN) ./cmd/citadel

check: fmt-check vet staticcheck govulncheck test concurrency traceability coverage

fmt-check:
	@out="$$(gofmt -l $$(find . -name '*.go' -not -path './runs/*' -not -path './.git/*'))"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

govulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

test:
	$(GO) test -race ./...

# The traceability test parses docs/TRACEABILITY.md and fails if any
# specification ID lacks a test or any listed test does not exist.
traceability:
	$(GO) test -run '^TestTraceability' ./internal/harness

coverage:
	@mkdir -p bin
	@fail=0; for p in $(COVER_PKGS); do \
		$(GO) test -covermode=atomic -coverprofile=bin/cover.out $$p >/dev/null || exit 1; \
		pct=$$($(GO) tool cover -func=bin/cover.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
		echo "coverage $$p $$pct%"; \
		if awk "BEGIN {exit !($$pct < $(COVERAGE_MIN))}"; then echo "  below $(COVERAGE_MIN)%"; fail=1; fi; \
	done; exit $$fail

fuzz:
	@for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t##*:}; \
		echo "fuzz $$name ($$pkg) for $(FUZZTIME)"; \
		$(GO) test -run '^$$' -fuzz "^$$name$$" -fuzztime $(FUZZTIME) $$pkg || exit 1; \
	done

# Experiment 4: the Go layer's overhead, separate from model time.
bench:
	@mkdir -p runs/bench
	$(GO) test -run '^$$' -bench . -benchmem -count 5 ./internal/... | tee runs/bench/bench.txt

# Concurrency tests run 50 times under the race detector.
concurrency:
	$(GO) test -race -count=50 -run '^Test(CT[1-7]|L7)_' ./internal/runstate ./internal/handoff

fuzz-ci:
	$(MAKE) fuzz FUZZTIME=30s

keys: build
	./$(BIN) keygen --dir keys --agent orchestrator --role orchestrator --kid orchestrator
	./$(BIN) keygen --dir keys --agent investigator --role agent --kid investigator
	./$(BIN) keygen --dir keys --agent responder --role agent --kid responder

m1: build
	$(GO) test -race -run '^TestM1$$' -v ./internal/harness
	./$(BIN) demo m1 --out runs/m1

tune: build
	./$(BIN) tune --fixtures testdata/dev --out configs/thresholds.yaml

eval: build
	./$(BIN) harness --configs $(CONFIGS) --trials $(TRIALS) --fixtures testdata/eval --impl $(IMPL)

dash: build
	./$(BIN) dash --runs runs/

clean:
	rm -rf bin
