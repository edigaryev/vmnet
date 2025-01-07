mod ffi;
pub use ffi::vmnet::{Events, Status};

/// Interface modes and their supporting structures and enumerations.
pub mod mode;

/// Parameters that can be [retrieved from the interface](Interface::parameters()) or received from an [interface callback call](Interface::set_event_callback).
pub mod parameters;

mod error;
pub use error::Error;

/// A specialized [`Result`](https://doc.rust-lang.org/std/result/enum.Result.html) type
/// for operations involving [vmnet.framework](https://developer.apple.com/documentation/vmnet).
pub type Result<T> = std::result::Result<T, Error>;

mod interface;

/// Structures related to port forwarding functionality.
pub mod port_forwarding;

pub use interface::shared_interface_list;
pub use interface::{Interface, Options};
