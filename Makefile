.PHONY: no-key secrets build test clippy fmt fmt-check audit demo e2e clean check install

no-key: secrets

secrets:
	python3 -B scripts/no_key_material_scan.py

build:
	cargo check --workspace --locked

test: secrets
	python3 -B -m unittest discover -s scripts -p 'test_*.py'
	cargo test --workspace --locked

clippy:
	cargo clippy --workspace --locked -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

audit:
	cargo audit

demo: secrets
	cargo test --locked --package signet-vault --test show_db -- --nocapture

e2e: secrets
	cargo test --locked --package signet --test integration_e2e --test journey_e2e

clean:
	cargo clean

check: secrets
	$(MAKE) build clippy fmt-check test

install:
	cargo install --locked --path crates/signet
