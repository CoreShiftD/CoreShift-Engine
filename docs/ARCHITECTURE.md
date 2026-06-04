# CoreShift-Engine Architecture

CoreShift-Engine sits between Core primitives and Android/product policy. It
provides reusable mechanisms while callers decide paths, command choices,
blocklists, protocols, and product behavior.

## Role

Engine owns:

- Runtime coordination and event dispatch.
- Core-backed command execution helpers.
- Foreground source abstractions.
- Package identity and cache mechanisms.
- Unix socket client/server helpers.
- Filesystem watch bridges.
- Bounded preload execution over caller-provided targets.

## Boundaries

Engine does not own:

- Android default cgroup or `/proc` paths.
- `cmd package` execution policy.
- Package discovery under `/data/app`.
- Daemon commands or socket protocols.
- App-specific preload rules.
- Product configuration files.

Policy or another caller supplies those choices.

## How Higher Layers Use Engine

Higher layers build explicit requests from their own policy inputs and pass them
to Engine. For example, Policy resolves Android package metadata, chooses APK/OAT
or shared-library preload methods, then calls Engine preload execution with
targets and limits.

Engine reports what happened. It does not decide whether a package should be
preloaded again, whether a foreground event should be ignored, or whether a
socket client should be authorized.
