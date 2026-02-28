.PHONY: build test clippy fmt audit demo e2e clean check install

build:
	cargo build --workspace

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

audit:
	cargo audit

demo:
	cargo test --package signet-vault --test show_db -- --nocapture

e2e:
	cargo test --package signet --test integration_e2e -- --nocapture

clean:
	cargo clean

check: build test clippy fmt-check
	@echo "All checks passed."

install:
	cargo install --path crates/signet
