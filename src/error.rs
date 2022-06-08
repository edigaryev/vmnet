use crate::ffi::vmnet;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("vmnet returned an error status")]
    VmnetErrorStatus(vmnet::Status),
    #[error("vmnet returned an unknown status: {0}")]
    VmnetUnknownStatus(u32),
    #[error("vmnet_start_interface() failed")]
    VmnetStartInterfaceFailed,
    #[error("vmnet_read() received no packets at this time")]
    VmnetReadNothing,
}
