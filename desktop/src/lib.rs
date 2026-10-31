//! Desktop session transport, independently testable without opening a window.
#![deny(unsafe_code)]

mod admission;
pub mod paths;
pub mod session;
pub use nullguard_worker::protocol;
