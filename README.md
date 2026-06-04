# CoreShift Engine

CoreShift Engine is the reusable mechanism layer over `coreshift-core`.

```text
Policy / product behavior
        ↓
Engine mechanisms
        ↓
Core syscall and filesystem primitives
```

Engine composes Core primitives into reusable foreground, cache, socket, watch,
execution, and preload services. It does not own Android default paths, package
policy, daemon protocols, or product behavior.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Preload executor](docs/PRELOAD_EXECUTOR.md)
- [Foreground and cache](docs/FOREGROUND_AND_CACHE.md)
- [Testing](docs/TESTING.md)
