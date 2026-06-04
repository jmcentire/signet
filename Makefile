.PHONY: no-key build test clippy fmt audit demo e2e clean check install

no-key:
	python3 -B scripts/no_key_material_scan.py

build:
	cargo check --workspace --locked

test: no-key
	@echo "No project test suite is approved for execution until a key-free partition is defined." >&2
	@exit 2

clippy:
	cargo clippy --workspace -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

audit:
	cargo audit

demo: no-key
	@echo "BlindDB demo execution is quarantined because its test path carries key material." >&2
	@exit 2

e2e: no-key
	@echo "Integration test execution is quarantined because its test path carries key material." >&2
	@exit 2

clean:
	cargo clean

check: no-key
	$(MAKE) build clippy fmt-check
	@echo "Build-only checks passed. Test execution remains a separate no-key-gated activity."

install:
	cargo install --path crates/signet
