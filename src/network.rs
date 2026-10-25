use crate::ffi::vmnet::{self, NetworkRef, Status};
use crate::port_forwarding::{AddressFamily, Protocol};
use crate::{Error, Result};
use objc2_core_foundation::{CFRetained, CFType};
use std::net::{IpAddr, Ipv4Addr};
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

    /// Adds a port forwarding rule to the network.
    ///
    /// Rules must be added before the network is created:
    /// [`Interface::port_forwarding_rule_add`] can't add rules to an interface
    /// attached to a network. `internal_addr` must be inside the network's
    /// subnet; use [`set_ipv4_subnet`](Self::set_ipv4_subnet) and
    /// [`add_dhcp_reservation`](Self::add_dhcp_reservation) to give a guest a
    /// known address.
    ///
    /// [`Interface::port_forwarding_rule_add`]: crate::Interface::port_forwarding_rule_add
    pub fn add_port_forwarding_rule(
        &mut self,
        address_family: AddressFamily,
        protocol: Protocol,
        external_port: u16,
        internal_addr: IpAddr,
        internal_port: u16,
    ) -> Result<()> {
        let internal_addr_ffi = match (address_family, internal_addr) {
            (AddressFamily::Ipv4, IpAddr::V4(addr)) => Vec::from(addr.octets()),
            (AddressFamily::Ipv6, IpAddr::V6(addr)) => Vec::from(addr.octets()),
            _ => return Err(Error::AddressFamilyMismatch),
        };

        let status = unsafe {
            vmnet::vmnet_network_configuration_add_port_forwarding_rule(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
                protocol as u8,
                address_family as u8,
                internal_port,
                external_port,
                internal_addr_ffi.as_ptr().cast(),
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

    #[test]
    fn port_forwarding_rule_address_family_mismatch() {
        let mut configuration = NetworkConfiguration::new(Mode::Shared).unwrap();

        assert!(matches!(
            configuration.add_port_forwarding_rule(
                AddressFamily::Ipv6,
                Protocol::Tcp,
                2222,
                Ipv4Addr::new(192, 168, 0, 2).into(),
                22,
            ),
            Err(Error::AddressFamilyMismatch)
        ));
        assert!(matches!(
            configuration.add_port_forwarding_rule(
                AddressFamily::Ipv4,
                Protocol::Tcp,
                2222,
                "fd00::2".parse::<std::net::Ipv6Addr>().unwrap().into(),
                22,
            ),
            Err(Error::AddressFamilyMismatch)
        ));
    }
}
