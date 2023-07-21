mod ffi;
pub use ffi::vmnet::{Events, Status};

pub mod mode;

pub mod parameters;

mod error;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

mod interface;
pub use interface::shared_interface_list;
pub use interface::{Interface, Options};
