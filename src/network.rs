use crate::ffi::vmnet::{self, NetworkRef, Status};
use crate::Result;
use objc2_core_foundation::{CFRetained, CFType};
use std::net::Ipv4Addr;
use std::ptr::NonNull;

/// Modes supported by explicit networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Mode {
    Host = 1000,
    Shared = 1001,
}

/// An owned native configuration for creating explicit networks.
pub struct NetworkConfiguration {
    handle: CFRetained<CFType>,
}

impl NetworkConfiguration {
    /// Creates a configuration with vmnet's defaults for the selected mode.
    pub fn new(mode: Mode) -> Result<Self> {
        let mut status = Status::Success as u32;
        let raw = unsafe { vmnet::vmnet_network_configuration_create(mode as u32, &mut status) };

        Status::from_ffi(status)?;

        // Take ownership of the native configuration
        let handle = unsafe { CFRetained::from_raw(NonNull::new(raw.cast()).unwrap()) };

        Ok(Self { handle })
    }

    /// Sets the IPv4 address and subnet mask used by the network.
    ///
    /// vmnet checks for overlaps and prevents colliding CIDRs across networks,
    /// but can miss overlaps with an existing larger subnet. To avoid for networks
    /// that you create, always set `address` to each subnet's first usable host address
    /// (subnet base address + 1).
    ///
    /// Networks created by other applications that don't follow this rule may still overlap.
    pub fn set_ipv4_subnet(&mut self, address: Ipv4Addr, mask: Ipv4Addr) -> Result<()> {
        let status = unsafe {
            vmnet::vmnet_network_configuration_set_ipv4_subnet(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
                &ipv4_to_native(address),
                &ipv4_to_native(mask),
            )
        };

        Status::from_ffi(status)?;

        Ok(())
    }

    /// Adds an IPv4 DHCP reservation for a guest's MAC address.
    pub fn add_dhcp_reservation(&mut self, mac_address: [u8; 6], address: Ipv4Addr) -> Result<()> {
        let status = unsafe {
            vmnet::vmnet_network_configuration_add_dhcp_reservation(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
                &mac_address,
                &ipv4_to_native(address),
            )
        };

        Status::from_ffi(status)?;

        Ok(())
    }
}

/// A reserved network to which multiple interfaces can attach.
pub struct Network {
    handle: CFRetained<CFType>,
}

impl Network {
    /// Reserves a network using a copy of the configuration.
    pub fn new(configuration: &NetworkConfiguration) -> Result<Self> {
        let mut status = Status::Success as u32;
        let raw = unsafe {
            vmnet::vmnet_network_create(
                CFRetained::as_ptr(&configuration.handle).as_ptr().cast(),
                &mut status,
            )
        };

        Status::from_ffi(status)?;

        // Take ownership of the native network
        let handle = unsafe { CFRetained::from_raw(NonNull::new(raw.cast()).unwrap()) };

        Ok(Self { handle })
    }

    pub(crate) fn as_raw(&self) -> NetworkRef {
        CFRetained::as_ptr(&self.handle).as_ptr().cast()
    }
}

fn ipv4_to_native(address: Ipv4Addr) -> libc::in_addr {
    // s_addr is stored in network byte order, regardless of host endianness
    libc::in_addr {
        s_addr: u32::from_ne_bytes(address.octets()),
    }
}

#[cfg(test)]
#[serial_test::serial]
mod tests {
    use super::*;

    #[test]
    fn overlapping_ipv4_subnets_are_rejected() {
        let mut first_configuration = NetworkConfiguration::new(Mode::Host).unwrap();
        first_configuration
            .set_ipv4_subnet(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 0, 0))
            .unwrap();
        let _first_network = Network::new(&first_configuration).unwrap();

        let mut second_configuration = NetworkConfiguration::new(Mode::Host).unwrap();
        second_configuration
            .set_ipv4_subnet(
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(255, 255, 255, 0),
            )
            .unwrap();

        assert!(Network::new(&second_configuration).is_err());
    }
}
