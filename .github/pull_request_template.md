## Summary

Brief description of the change.

## Type

- [ ] Feature
- [ ] Bug fix
- [ ] Refactor
- [ ] Documentation
- [ ] CI/tooling

## Testing

- [ ] `make secrets` passes (Gitleaks installed; findings reviewed)
- [ ] Test keys are generated or documented test-only vectors; no production credentials are used
- [ ] `cargo test --workspace --locked` passes
- [ ] `cargo check --workspace --locked` passes
- [ ] `cargo clippy --workspace -- -D warnings` clean
- [ ] `cargo fmt --all -- --check` passes

## Security Checklist

If this PR touches cryptographic code or storage:

- [ ] Secret comparisons use `subtle::ConstantTimeEq`
- [ ] Cryptographic randomness uses `OsRng`
- [ ] Secret key material wrapped in `Zeroizing<>`
- [ ] No plaintext or labels leak to storage backend
- [ ] No `.unwrap()` or `.expect()` in library code
