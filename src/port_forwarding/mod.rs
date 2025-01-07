use num_enum::{IntoPrimitive, TryFromPrimitive};
use std::net::IpAddr;

/// Port forwarding rule.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rule {
    pub address_family: AddressFamily,
    pub protocol: Protocol,
    pub external_port: u16,
    pub addr: IpAddr,
    pub internal_port: u16,
}

/// Address family related to a port forwarding rule.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, IntoPrimitive, TryFromPrimitive)]
pub enum AddressFamily {
    Ipv4 = libc::AF_INET as u8,
    Ipv6 = libc::AF_INET6 as u8,
}

/// Protocol related to a port forwarding rule (e.g. TCP or UDP).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, IntoPrimitive, TryFromPrimitive)]
pub enum Protocol {
    Tcp = libc::IPPROTO_TCP as u8,
    Udp = libc::IPPROTO_UDP as u8,
}
