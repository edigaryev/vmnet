use crate::ffi::vmnet;

/// A specialized [`Error`](https://doc.rust-lang.org/std/error/trait.Error.html) type for errors involving [vmnet.framework](https://developer.apple.com/documentation/vmnet).
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("vmnet returned an error status: {0:?}")]
    VmnetErrorStatus(vmnet::Status),
    #[error("vmnet returned an unknown status: {0}")]
    VmnetUnknownStatus(u32),
    #[error("vmnet_start_interface() failed")]
    VmnetStartInterfaceFailed,
    #[error("vmnet_read() received no packets at this time")]
    VmnetReadNothing,
}
