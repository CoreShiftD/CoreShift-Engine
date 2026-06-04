# Testing CoreShift-Engine

Run validation from the repository root:

```bash
cargo fmt --check
cargo test -j 1
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps
```

## Focus Areas

Engine tests should cover:

- Foreground source parsing and cache updates.
- Socket connect/read/write mechanics.
- Preload report accounting and limit behavior.
- Error propagation from Core primitives.

## Boundary Checks

Changes should not introduce Android path defaults, package discovery, or daemon
protocol behavior into Engine. Those belong in Policy or product wrappers.
