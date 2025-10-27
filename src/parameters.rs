use crate::ffi::vmnet::*;
use crate::ffi::xpc;
use crate::ffi::xpc::{XpcData, XpcObjectT};

use enum_iterator::{all, Sequence};
use lazy_static::lazy_static;

use std::collections::HashMap;
use std::ffi::CStr;

use std::os::raw::c_char;

use uuid::Uuid;
use vmnet_derive::Vmnet;

lazy_static! {
    static ref VMNET_KEY_TO_PARAMETER_KIND: HashMap<String, ParameterKind> = all::<ParameterKind>()
        .map(|parameter_kind| { (parameter_kind.vmnet_key(), parameter_kind) })
        .collect();
}

/// Dictionary of retrieved parameters.
pub struct Parameters {
    xdict: xpc::Dictionary,
}

/// A single parameter with its value.
#[derive(Debug, Vmnet)]
pub enum Parameter {
    #[vmnet(ffi = "vmnet_operation_mode_key")]
    OperationMode(u64),
    #[vmnet(ffi = "vmnet_mac_address_key")]
    MACAddress(String),
    #[vmnet(ffi = "vmnet_allocate_mac_address_key")]
    AllocateMACAddress(bool),
    #[vmnet(ffi = "vmnet_mtu_key")]
    MTU(u64),
    #[vmnet(ffi = "vmnet_interface_id_key")]
    InterfaceID(Uuid),
    #[vmnet(ffi = "vmnet_max_packet_size_key")]
    MaxPacketSize(u64),
    #[vmnet(ffi = "vmnet_read_max_packets_key")]
    ReadMaxPackets(u64),
    #[vmnet(ffi = "vmnet_write_max_packets_key")]
    WriteMaxPackets(u64),
    #[vmnet(ffi = "vmnet_enable_checksum_offload_key")]
    EnableChecksumOffload(bool),
    #[vmnet(ffi = "vmnet_enable_isolation_key")]
    EnableIsolation(bool),
    #[vmnet(ffi = "vmnet_enable_tso_key")]
    EnableTSO(bool),
    #[vmnet(ffi = "vmnet_network_identifier_key")]
    NetworkIdentifier(Uuid),
    #[vmnet(ffi = "vmnet_host_ip_address_key")]
    HostIPAddress(String),
    #[vmnet(ffi = "vmnet_host_ipv6_address_key")]
    HostIP6Address(String),
    #[vmnet(ffi = "vmnet_host_subnet_mask_key")]
    HostSubnetMask(String),
    #[vmnet(ffi = "vmnet_nat66_prefix_key")]
    NAT66Prefix(String),
    #[vmnet(ffi = "vmnet_shared_interface_name_key")]
    SharedInterfaceName(String),
    #[vmnet(ffi = "vmnet_start_address_key")]
    StartAddress(String),
    #[vmnet(ffi = "vmnet_end_address_key")]
    EndAddress(String),
    #[vmnet(ffi = "vmnet_subnet_mask_key")]
    SubnetMask(String),
    /// The estimated number of packets available to be read.
    #[vmnet(ffi = "vmnet_estimated_packets_available_key")]
    EstimatedPacketsAvailable(u64),
}

impl Parameters {
    pub(crate) fn from_xpc(xdict: XpcObjectT) -> Self {
        Parameters {
            xdict: unsafe { xpc::Dictionary::from_xpc(xdict) },
        }
    }

    pub fn get(&self, key: ParameterKind) -> Option<Parameter> {
        let xpc_data = self.xdict.get(key.vmnet_key())?;
        key.parse(xpc_data)
    }
}

impl From<&Parameters> for Vec<Parameter> {
    fn from(parameters: &Parameters) -> Self {
        let mut result = Vec::new();

        let dict: HashMap<String, XpcData> = parameters.xdict.clone().try_into().unwrap();

        for (key, value) in dict {
            if let Some(parameter_kind) = VMNET_KEY_TO_PARAMETER_KIND.get(&key.to_string()) {
                if let Some(value) = parameter_kind.parse(value) {
                    result.push(value);
                }
            }
        }

        result
    }
}
