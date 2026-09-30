//! Artifacts that are Unix-wide rather than Linux-specific — the same fixed formats also occur
//! on BSD and macOS. Deliberately not named `linux::` so a future module move stays a directory
//! move, not a rename of every public path.

pub mod utmp;
