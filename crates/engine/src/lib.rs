//! CoreShift Engine runtime coordination.
//!
//! Engine sits above `coreshift-core` and coordinates explicit low-level
//! primitives. It does not define daemon product behavior, app rules, preload
//! behavior, foreground policy, protocol framing, JSON, root strategy, or
//! fallback magic.
//!
//! Current foreground identity flow is:
//! foreground source -> payload dedupe -> `ForegroundCandidateChanged` ->
//! `ResolveIdentity` -> `IdentityResolved` -> reducer state.

pub mod config;
pub mod dispatch;
pub mod error;
pub mod events;
pub mod exec;
pub mod game;
pub mod preload;
pub mod runtime;
pub mod services;
pub mod state;

pub use config::EngineConfig;
pub use dispatch::{Dispatcher, EngineAction};
pub use error::EngineError;
pub use events::EngineEvent;
pub use game::{
    GameList, ManagedGameDownscale, ManagedGameDownscales, game_targets_from_installed,
    load_game_list, load_managed_game_downscales, parse_game_list, parse_managed_game_downscales,
    write_managed_game_downscales,
};
pub use runtime::EngineRuntime;
pub use state::{EngineState, Reducer};
