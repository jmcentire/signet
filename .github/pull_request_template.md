## Summary

Brief description of the change.

## Type

- [ ] Feature
- [ ] Bug fix
- [ ] Refactor
- [ ] Documentation
- [ ] CI/tooling

## Testing

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` clean
- [ ] `cargo fmt --all -- --check` passes

## Security Checklist

If this PR touches cryptographic code or storage:

- [ ] Secret comparisons use `subtle::ConstantTimeEq`
- [ ] Cryptographic randomness uses `OsRng`
- [ ] Secret key material wrapped in `Zeroizing<>`
- [ ] No plaintext or labels leak to storage backend
- [ ] No `.unwrap()` or `.expect()` in library code
