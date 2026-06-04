# Foreground and Cache Mechanisms

Engine provides reusable foreground and cache building blocks. It does not
select Android defaults or product policy.

## Foreground Sources

Engine includes mechanisms for:

- cgroup v1 top-app process lists supplied by a caller.
- cgroup v2 `cgroup.events` roots supplied by a caller.
- ActivityManager output parsing supplied by a caller.

The caller chooses source order, paths, fallback behavior, and command execution.

## Cache Behavior

Foreground cache mechanisms can hold package/UID metadata from a caller-provided
package-list provider. Package marker fingerprints support invalidation when the
underlying package state changes.

Engine does not run `cmd package` on its own and does not know which Android
paths should be trusted. Policy supplies those providers and defaults.

## Socket Mechanics

`services::socket` wraps Unix stream socket mechanics used by higher layers:

- Abstract socket connect helpers.
- Stream read/write behavior.
- Nonblocking mechanics exposed through Engine-owned wrappers.

Engine owns socket mechanics, not daemon message protocols. For example, Policy
defines `GET\n`; Engine only supplies the underlying stream operations.

## Maintenance Notes

Keep Android path constants, package blocklists, and foreground policy outside
Engine. Add new mechanisms as caller-configurable services.
