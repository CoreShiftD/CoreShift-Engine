# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-05-17

### Added

- Added reusable game-list parsing, installed-target filtering, and managed
  game downscale state helpers for higher-layer callers.

## [0.3.0] - 2026-05-11

### Added

- Exposed Unix socket peer credential lookup through `EngineUnixStream::peer_cred()`.

## [0.2.0] - 2026-05-10

### Added

- Added generic preload executor for readahead, mmap/madvise, and chunked readahead plans.
- Extended foreground package cache entries with optional base APK metadata.
- Preserved persistent daemon/socket mechanisms for repeated client requests.

## [0.1.0] - 2026-05-04

### Added

- Initial official CoreShift Engine release.
- Reusable execution, foreground, package-cache, identity-cache invalidation,
  watch, socket-wrapper, reducer, and runtime mechanisms.
- Explicit foreground sources for caller-supplied cgroup v1 and cgroup v2 paths.
- cgroup v2 `cgroup.events` priority fd registration, stale watch removal, root
  rescanning, and replacement registration.
- ActivityManager output parser for higher-layer command fallback.
- Observable watch registration failures.

### Notes

- Engine coordinates Core primitives but does not decide product behavior.
- Android paths, foreground source order, blocklists, daemon behavior, and socket
  protocols belong to Policy or another caller layer.
