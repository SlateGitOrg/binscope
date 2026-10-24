# binscope - one entry point for every gate. `make check` is what CI runs.
SHELL := /bin/bash
CARGO ?= cargo
# Minimum line coverage (whole crate, generated tables excluded).
COVERAGE_MIN ?= 85
COV_IGNORE := (hashes/ordinals|fuzzy/tlsh_tables)\.rs

.PHONY: check fmt fmt-check lint test coverage demo bench eval loc fixtures reference clean

## check: format check + clippy (-D warnings) + rustdoc + tests under coverage with a threshold
check: fmt-check lint coverage
	@echo "make check: all gates passed"

fmt:
	$(CARGO) fmt

fmt-check:
	$(CARGO) fmt --check

## lint: clippy (pedantic, warnings are errors) and warning-free rustdoc; also type-checks every target
lint:
	$(CARGO) clippy --all-targets --locked -- -D warnings
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --no-deps --locked --quiet

test:
	$(CARGO) test --locked

## coverage: runs the whole test suite instrumented and fails under COVERAGE_MIN% lines
coverage:
	@command -v cargo-llvm-cov >/dev/null || { echo "cargo-llvm-cov missing: cargo install cargo-llvm-cov --locked"; exit 1; }
	$(CARGO) llvm-cov --locked --summary-only --ignore-filename-regex '$(COV_IGNORE)' --fail-under-lines $(COVERAGE_MIN)

## demo: offline end-to-end run against the bundled fixtures
demo:
	@./scripts/demo.sh

## bench: throughput benchmark (release build)
bench:
	$(CARGO) run --release --locked --example throughput

## eval: clustering evaluation on the fixture corpus + synthetic edit study
eval:
	$(CARGO) run --release --locked --example cluster_eval

## loc: non-test source lines (excludes generated tables and #[cfg(test)] modules)
loc:
	@./scripts/loc.sh

## fixtures: rebuild fixtures/bin from fixtures/src (macOS: clang, rust-lld, lipo)
fixtures:
	./fixtures/build.sh

## reference: rebuild ssdeep/TLSH/pefile in a temp dir and regenerate tests/reference (network)
reference:
	@set -e; T=$$(./scripts/reference/build_tools.sh); \
	$(CARGO) run --release --locked --example gen_synth -- "$$T/synth"; \
	"$$T/venv/bin/python" scripts/reference/gen_reference.py "$$T"; \
	rm -rf "$$T"

clean:
	$(CARGO) clean
