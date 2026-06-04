# Preload Executor

The Engine preload module executes bounded preload work over caller-provided
file targets. It is generic and has no Android path defaults.

## API Shape

Engine v0.2.0 exposes:

- `PreloadMethod`
- `PreloadLimits`
- `PreloadTarget`
- `PreloadReport`
- `execute_preload_plan(targets, limits)`

There is no standalone public `PreloadRequest` type in v0.2.0. A preload request
is represented by the caller passing a slice of `PreloadTarget` values plus
`PreloadLimits` into `execute_preload_plan`.

## `PreloadMethod`

`PreloadMethod` selects how each target is warmed:

- `Readahead`: direct Core `readahead`.
- `MmapMadvise`: Core `mmap_madvise` without page touching.
- `MmapMadviseTouch`: Core `mmap_madvise` with page touching.
- `ChunkedReadahead`: repeated readahead chunks for larger assets.

## `PreloadTarget`

Each target carries:

- `path`
- `method`
- `len`

The caller decides how the target was discovered and why that method is
appropriate.

## `PreloadLimits`

Limits bound the work before it reaches Core:

- `mmap_madvise_max_bytes`
- `mmap_touch_max_bytes`
- `asset_max_bytes`
- `chunk_bytes`

`Readahead` is not capped by the mmap-specific limits. Chunked readahead uses
`asset_max_bytes` and `chunk_bytes`.

## `PreloadReport`

Reports include:

- `attempted_files`
- `preloaded_files`
- `preloaded_bytes`
- `skipped`

Skipped entries include the path and error string. Callers can treat skips as
best-effort results or policy failures.

## Method Boundaries

Engine does not scan package directories, classify file types, or choose Android
defaults. Policy can map APK/OAT files to readahead and `.so` files to
mmap/madvise, but Engine only sees explicit targets.
