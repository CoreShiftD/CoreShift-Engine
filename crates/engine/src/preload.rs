use crate::EngineError;
use coreshift_core::fs::{mmap_madvise, readahead};
use std::fs::File;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreloadMethod {
    Readahead,
    MmapMadvise,
    MmapMadviseTouch,
    ChunkedReadahead,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreloadLimits {
    pub mmap_madvise_max_bytes: Option<u64>,
    pub mmap_touch_max_bytes: Option<u64>,
    pub asset_max_bytes: Option<u64>,
    pub chunk_bytes: u64,
}

impl Default for PreloadLimits {
    fn default() -> Self {
        Self {
            mmap_madvise_max_bytes: None,
            mmap_touch_max_bytes: None,
            asset_max_bytes: None,
            chunk_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreloadTarget {
    pub path: PathBuf,
    pub method: PreloadMethod,
    pub len: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreloadReport {
    pub attempted_files: usize,
    pub preloaded_files: usize,
    pub preloaded_bytes: u64,
    pub skipped: Vec<PreloadFileError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreloadFileError {
    pub path: PathBuf,
    pub error: String,
}

pub fn execute_preload_plan(
    targets: &[PreloadTarget],
    limits: &PreloadLimits,
) -> Result<PreloadReport, EngineError> {
    let mut report = PreloadReport::default();
    for target in targets {
        report.attempted_files += 1;
        match preload_one(target, limits) {
            Ok(bytes) => {
                report.preloaded_files += 1;
                report.preloaded_bytes = report.preloaded_bytes.saturating_add(bytes);
            }
            Err(error) => report.skipped.push(PreloadFileError {
                path: target.path.clone(),
                error: error.to_string(),
            }),
        }
    }
    Ok(report)
}

fn preload_one(target: &PreloadTarget, limits: &PreloadLimits) -> Result<u64, EngineError> {
    let file = File::open(&target.path).map_err(EngineError::Io)?;
    let fd = RawFdRef(file.as_raw_fd());
    let len = capped_len(target, limits);
    match target.method {
        PreloadMethod::Readahead => {
            readahead(fd, 0, len as usize).map_err(EngineError::Core)?;
        }
        PreloadMethod::MmapMadvise => {
            mmap_madvise(fd, 0, len as usize, false).map_err(EngineError::Core)?;
        }
        PreloadMethod::MmapMadviseTouch => {
            mmap_madvise(fd, 0, len as usize, true).map_err(EngineError::Core)?;
        }
        PreloadMethod::ChunkedReadahead => {
            let chunk = limits.chunk_bytes.max(1);
            let mut offset = 0;
            while offset < len {
                let part = (len - offset).min(chunk);
                readahead(fd, offset, part as usize).map_err(EngineError::Core)?;
                offset += part;
            }
        }
    }
    Ok(len)
}

#[derive(Clone, Copy)]
struct RawFdRef(RawFd);

impl AsRawFd for RawFdRef {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

fn capped_len(target: &PreloadTarget, limits: &PreloadLimits) -> u64 {
    let cap = match target.method {
        PreloadMethod::Readahead => None,
        PreloadMethod::MmapMadvise => limits.mmap_madvise_max_bytes,
        PreloadMethod::MmapMadviseTouch => limits.mmap_touch_max_bytes,
        PreloadMethod::ChunkedReadahead => limits.asset_max_bytes,
    };
    cap.map_or(target.len, |cap| target.len.min(cap))
}
