use crate::error;
use crate::ffi::dispatch::DispatchQueueGlobalT;
use crate::ffi::xpc::XpcObjectT;
use bitflags::bitflags;
use libc::{iovec, size_t};
use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::ffi::c_void;
use std::os::raw::{c_char, c_int};

pub type InterfaceRef = *mut c_void;
pub type InterfaceEventT = u32;
pub type VmnetReturnT = u32;

#[repr(C)]
#[derive(Debug)]
pub struct vmpktdesc {
    pub vm_pkt_size: size_t,
    pub vm_pkt_iov: *mut iovec,
    pub vm_pkt_iovcnt: u32,
    pub vm_flags: u32,
}

#[link(name = "vmnet", kind = "framework")]
extern "C" {
    // Interface functions
    pub fn vmnet_start_interface(
        interface_desc: XpcObjectT,
        queue: DispatchQueueGlobalT,
        handler: *mut c_void,
    ) -> InterfaceRef;
    pub fn vmnet_interface_set_event_callback(
        interface: InterfaceRef,
        event_mask: InterfaceEventT,
        queue: DispatchQueueGlobalT,
        handler: *mut c_void,
    ) -> VmnetReturnT;
    pub fn vmnet_read(
        interface: InterfaceRef,
        packets: *mut vmpktdesc,
        pktcnt: *mut c_int,
    ) -> VmnetReturnT;
    pub fn vmnet_write(
        interface: InterfaceRef,
        packets: *mut vmpktdesc,
        pktcnt: *mut c_int,
    ) -> VmnetReturnT;
    pub fn vmnet_stop_interface(
        interface: InterfaceRef,
        queue: DispatchQueueGlobalT,
        handler: *mut c_void,
    ) -> VmnetReturnT;

    // Interface port forwarding functions
    pub fn vmnet_interface_add_ip_port_forwarding_rule(
        interface: InterfaceRef,
        protocol: u8,
        external_port: u16,
        address_family: u8,
        internal_address: *const c_void,
        internal_port: u16,
        handler: *mut c_void,
    ) -> VmnetReturnT;
    pub fn vmnet_interface_get_ip_port_forwarding_rules(
        interface: InterfaceRef,
        address_family: u8,
        handler: *mut c_void,
    ) -> VmnetReturnT;
    pub fn vmnet_ip_port_forwarding_rule_get_details(
        rule: XpcObjectT,
        protocol: *mut u8,
        external_port: *mut u16,
        address_family: u8,
        internal_address: *mut c_void,
        internal_port: *mut u16,
    ) -> VmnetReturnT;
    pub fn vmnet_interface_remove_ip_port_forwarding_rule(
        interface: InterfaceRef,
        protocol: u8,
        external_port: u16,
        address_family: u8,
        handler: *mut c_void,
    ) -> VmnetReturnT;

    // Utility functions
    pub fn vmnet_copy_shared_interface_list() -> XpcObjectT;

    // Mode selector
    pub static vmnet_operation_mode_key: *const c_char;

    // Generic options and parameters
    pub static vmnet_mac_address_key: *const c_char;
    pub static vmnet_allocate_mac_address_key: *const c_char;
    pub static vmnet_interface_id_key: *const c_char;
    pub static vmnet_max_packet_size_key: *const c_char;
    pub static vmnet_enable_checksum_offload_key: *const c_char;
    pub static vmnet_enable_isolation_key: *const c_char;
    pub static vmnet_enable_tso_key: *const c_char;

    // Host mode
    pub static vmnet_network_identifier_key: *const c_char;
    pub static vmnet_host_ip_address_key: *const c_char;
    pub static vmnet_host_ipv6_address_key: *const c_char;
    pub static vmnet_host_subnet_mask_key: *const c_char;

    // Bridged mode
    pub static vmnet_shared_interface_name_key: *const c_char;

    // Shared and host modes
    pub static vmnet_start_address_key: *const c_char;
    pub static vmnet_end_address_key: *const c_char;
    pub static vmnet_subnet_mask_key: *const c_char;
    pub static vmnet_mtu_key: *const c_char;

    // Shared mode
    pub static vmnet_nat66_prefix_key: *const c_char;

    // Event callback
    pub static vmnet_estimated_packets_available_key: *const c_char;
}

/// A status returned by the [vmnet.framework](https://developer.apple.com/documentation/vmnet).
#[derive(TryFromPrimitive)]
#[repr(u32)]
#[derive(Debug, Eq, PartialEq)]
pub enum Status {
    Success = 1000,
    Failure = 1001,
    MemFailure = 1002,
    InvalidArgument = 1003,
    SetupIncomplete = 1004,
    InvalidAccess = 1005,
    PacketTooBig = 1006,
    BufferExhausted = 1007,
    TooManyPackets = 1008,
    SharingServiceBusy = 1009,
}

impl Status {
    pub fn from_ffi(status: u32) -> Result<(), error::Error> {
        let status =
            Status::try_from(status).map_err(|_x| error::Error::VmnetUnknownStatus(status))?;

        match status {
            Status::Success => Ok(()),
            _ => Err(error::Error::VmnetErrorStatus(status)),
        }
    }
}

#[repr(u64)]
#[derive(IntoPrimitive)]
pub enum Mode {
    Host = 1000,
    Shared = 1001,
    Bridged = 1002,
}

bitflags! {
    /// Describes events received for a given [interface callback call](crate::Interface::set_event_callback).
    pub struct Events: u32 {
        const PACKETS_AVAILABLE = 1 << 0;
    }
}
