use crate::ffi::vmnet::{self, NetworkRef, Status};
use crate::port_forwarding::{AddressFamily, Protocol};
use crate::{Error, Result};
use objc2_core_foundation::{CFRetained, CFType};
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

    /// Sets the external interface used by a shared network.
    pub fn set_external_interface(&mut self, interface_name: &CStr) -> Result<()> {
        let status = unsafe {
            vmnet::vmnet_network_configuration_set_external_interface(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
                interface_name.as_ptr(),
            )
        };

        Status::from_ffi(status)?;

        Ok(())
    }

    /// Disables IPv4 NAT on the network.
    pub fn disable_nat44(&mut self) {
        unsafe {
            vmnet::vmnet_network_configuration_disable_nat44(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
            )
        }
    }

    /// Disables IPv6 NAT on the network.
    pub fn disable_nat66(&mut self) {
        unsafe {
            vmnet::vmnet_network_configuration_disable_nat66(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
            )
        }
    }

    /// Disables the DHCP server on the network.
    pub fn disable_dhcp(&mut self) {
        unsafe {
            vmnet::vmnet_network_configuration_disable_dhcp(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
            )
        }
    }

    /// Disables the DNS proxy on the network.
    pub fn disable_dns_proxy(&mut self) {
        unsafe {
            vmnet::vmnet_network_configuration_disable_dns_proxy(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
            )
        }
    }

    /// Disables IPv6 router advertisements on the network.
    pub fn disable_router_advertisement(&mut self) {
        unsafe {
            vmnet::vmnet_network_configuration_disable_router_advertisement(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
            )
        }
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

    /// Sets the IPv6 prefix and prefix length used by the network.
    pub fn set_ipv6_prefix(&mut self, prefix: Ipv6Addr, prefix_length: u8) -> Result<()> {
        let prefix = libc::in6_addr {
            s6_addr: prefix.octets(),
        };

        let status = unsafe {
            vmnet::vmnet_network_configuration_set_ipv6_prefix(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
                &prefix,
                prefix_length,
            )
        };

        Status::from_ffi(status)?;

        Ok(())
    }

    /// Sets the maximum transmission unit (MTU) used by the network.
    pub fn set_mtu(&mut self, mtu: u32) -> Result<()> {
        let status = unsafe {
            vmnet::vmnet_network_configuration_set_mtu(
                CFRetained::as_ptr(&self.handle).as_ptr().cast(),
                mtu,
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

    /// Returns the reserved IPv4 address and subnet mask of the network.
    pub fn ipv4_subnet(&self) -> (Ipv4Addr, Ipv4Addr) {
        let mut address = libc::in_addr { s_addr: 0 };
        let mut mask = libc::in_addr { s_addr: 0 };

        unsafe { vmnet::vmnet_network_get_ipv4_subnet(self.as_raw(), &mut address, &mut mask) };

        (
            Ipv4Addr::from(address.s_addr.to_ne_bytes()),
            Ipv4Addr::from(mask.s_addr.to_ne_bytes()),
        )
    }

    /// Returns the reserved IPv6 prefix and prefix length of the network.
    pub fn ipv6_prefix(&self) -> (Ipv6Addr, u8) {
        let mut prefix = libc::in6_addr { s6_addr: [0; 16] };
        let mut prefix_length = 0;

        unsafe {
            vmnet::vmnet_network_get_ipv6_prefix(self.as_raw(), &mut prefix, &mut prefix_length)
        };

        (Ipv6Addr::from(prefix.s6_addr), prefix_length)
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
    fn set_external_interface() {
        // Select an explicit upstream interface instead of vmnet's routing-table default
        let mut configuration = NetworkConfiguration::new(Mode::Shared).unwrap();
        configuration.set_external_interface(c"en0").unwrap();

        // Verify that vmnet accepts the interface selection when starting the network
        let network = Network::new(&configuration).unwrap();
        crate::Interface::with_network(&network, crate::Options::default()).unwrap();
    }

    #[test]
    fn disable_services() {
        // Shared mode enables each of these services by default
        let cases = [
            (
                "disable_nat44",
                NetworkConfiguration::disable_nat44 as fn(&mut NetworkConfiguration),
            ),
            ("disable_nat66", NetworkConfiguration::disable_nat66),
            ("disable_dhcp", NetworkConfiguration::disable_dhcp),
            ("disable_dns_proxy", NetworkConfiguration::disable_dns_proxy),
            (
                "disable_router_advertisement",
                NetworkConfiguration::disable_router_advertisement,
            ),
        ];

        for (name, disable) in cases {
            // Use a fresh configuration so each case disables only one service
            let mut configuration = NetworkConfiguration::new(Mode::Shared)
                .unwrap_or_else(|error| panic!("{name}: configuration creation failed: {error}"));
            disable(&mut configuration);

            // Verify that vmnet accepts the setting when starting an interface
            let network = Network::new(&configuration)
                .unwrap_or_else(|error| panic!("{name}: network creation failed: {error}"));
            crate::Interface::with_network(&network, crate::Options::default())
                .unwrap_or_else(|error| panic!("{name}: interface startup failed: {error}"));
        }
    }

    #[test]
    fn set_ipv6_prefix() {
        // Use a prefix from the documentation range reserved by RFC 3849
        let prefix = "2001:db8::".parse::<Ipv6Addr>().unwrap();
        let mut configuration = NetworkConfiguration::new(Mode::Host).unwrap();
        configuration.set_ipv6_prefix(prefix, 64).unwrap();

        // Verify that the reserved network preserves both the address bytes and prefix length
        let network = Network::new(&configuration).unwrap();
        assert_eq!(network.ipv6_prefix(), (prefix, 64));
    }

    #[test]
    fn set_mtu() {
        // Choose an MTU that differs from vmnet's default of 1500
        let mut configuration = NetworkConfiguration::new(Mode::Host).unwrap();
        configuration.set_mtu(1400).unwrap();

        // Verify that an attached interface inherits the network's configured MTU
        let network = Network::new(&configuration).unwrap();
        let interface =
            crate::Interface::with_network(&network, crate::Options::default()).unwrap();
        assert!(matches!(
            interface
                .parameters()
                .get(crate::parameters::ParameterKind::MTU),
            Some(crate::parameters::Parameter::MTU(1400))
        ));
    }

    #[test]
    fn ipv4_subnet() {
        // Leave the subnet unset so vmnet reserves one using its defaults
        let configuration = NetworkConfiguration::new(Mode::Host).unwrap();
        let network = Network::new(&configuration).unwrap();
        let (address, mask) = network.ipv4_subnet();

        // The allocated subnet must be private and use vmnet's default /24 mask
        assert!(address.is_private());
        assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn ipv6_prefix() {
        // Leave the prefix unset so vmnet reserves a random ULA prefix
        let configuration = NetworkConfiguration::new(Mode::Host).unwrap();
        let network = Network::new(&configuration).unwrap();
        let (prefix, prefix_length) = network.ipv6_prefix();

        // Check the prefix type and length without depending on the randomly chosen address
        assert!(prefix.is_unique_local());
        assert!((1..=128).contains(&prefix_length));
    }

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
