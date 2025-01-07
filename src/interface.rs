use crate::ffi::dispatch::{dispatch_get_global_queue, DispatchQueueGlobalT};
use crate::ffi::vmnet;
use crate::ffi::vmnet::{vmnet_copy_shared_interface_list, Events, InterfaceRef, Status};
use crate::ffi::xpc::{
    xpc_array_get_count, xpc_array_get_string, xpc_array_get_value, Dictionary, XpcData, XpcObjectT,
};
use crate::mode::Mode;
use crate::parameters::{Parameter, ParameterKind, Parameters};
use crate::Error;
use crate::Result;

use std::os::raw::c_int;

use crate::port_forwarding::{AddressFamily, Protocol, Rule};
use std::collections::HashMap;
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{ptr, sync};

/// A virtual network interface.
pub struct Interface {
    queue: DispatchQueueGlobalT,
    interface: InterfaceRef,
    parameters: Parameters,
    finalized: bool,
}

/// Options that are common to all interface modes.
#[derive(Debug, Default)]
pub struct Options {
    pub allocate_mac_address: Option<bool>,
    pub enable_checksum_offload: Option<bool>,
    pub enable_isolation: Option<bool>,
    pub enable_tso: Option<bool>,
    pub interface_id: Option<uuid::Uuid>,
}

impl From<Options> for Vec<Parameter> {
    fn from(options: Options) -> Self {
        let mut result = Vec::new();

        if let Some(enable_isolation) = options.enable_isolation {
            result.push(Parameter::EnableIsolation(enable_isolation));
        }

        if let Some(interface_id) = options.interface_id {
            result.push(Parameter::InterfaceID(interface_id));
        }

        result
    }
}

impl Interface {
    /// Creates a new interface in a specified mode and with the specified options.
    pub fn new(mode: Mode, options: Options) -> Result<Interface> {
        let queue = unsafe { dispatch_get_global_queue(0, 0) };

        let interface_settings: HashMap<String, XpcData> = {
            let mut interface_settings: Vec<Parameter> = mode.into();
            interface_settings.append(&mut options.into());

            interface_settings
                .into_iter()
                .map(|x| (ParameterKind::from(&x).vmnet_key(), XpcData::from(x)))
                .collect()
        };
        let interface_settings = Dictionary::from(interface_settings);

        let (tx, rx) = sync::mpsc::sync_channel(1);
        let block = block::ConcreteBlock::new(
            move |status: vmnet::VmnetReturnT, interface_desc: XpcObjectT| {
                tx.send((status, Parameters::from_xpc(interface_desc)))
                    .unwrap();
            },
        );
        let block = block.copy();

        let interface = unsafe {
            vmnet::vmnet_start_interface(
                interface_settings.to_xpc(),
                queue,
                &*block as *const _ as *mut _,
            )
        };

        if interface.is_null() {
            return Err(Error::VmnetStartInterfaceFailed);
        }

        let (status, parameters) = rx.recv().unwrap();

        Status::from_ffi(status)?;

        Ok(Interface {
            queue,
            interface,
            parameters,
            finalized: false,
        })
    }

    /// Retrieves interface parameters (for example, an [assigned gateway IP address](crate::parameters::ParameterKind::StartAddress) or an [MTU](crate::parameters::ParameterKind::MTU)) that are available only after the interface is created.
    pub fn parameters(&self) -> &Parameters {
        &self.parameters
    }

    /// Schedules a callback to be executed when events for the specified interface are received.
    pub fn set_event_callback<F>(&mut self, events: Events, cb: F) -> Result<()>
    where
        F: Fn(Events, &Parameters) + 'static,
    {
        let block =
            block::ConcreteBlock::new(move |events: vmnet::InterfaceEventT, xdict: XpcObjectT| {
                let params = Parameters::from_xpc(xdict);
                cb(Events::from_bits_truncate(events), &params);
            });
        let block = block.copy();

        let status = unsafe {
            vmnet::vmnet_interface_set_event_callback(
                self.interface,
                events.bits(),
                self.queue,
                &*block as *const _ as *mut _,
            )
        };

        Status::from_ffi(status)
    }

    /// Removes the event callback scheduled by a call to [`set_event_callback()`](Interface::set_event_callback()).
    pub fn clear_event_callback(&mut self) -> Result<()> {
        let status = unsafe {
            vmnet::vmnet_interface_set_event_callback(
                self.interface,
                Events::all().bits(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };

        Status::from_ffi(status)
    }

    /// Attempts to read a single packet from the interface.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut pktdesc = vmnet::vmpktdesc {
            vm_pkt_size: iov.iov_len,
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };
        let mut pktcnt: c_int = 1;

        let status = unsafe { vmnet::vmnet_read(self.interface, &mut pktdesc, &mut pktcnt) };
        Status::from_ffi(status)?;

        if pktcnt == 0 {
            return Err(Error::VmnetReadNothing);
        }

        Ok(pktdesc.vm_pkt_size)
    }

    /// Attempts to write a single packet to the interface.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut pktdesc = vmnet::vmpktdesc {
            vm_pkt_size: iov.iov_len,
            vm_pkt_iov: &mut iov,
            vm_pkt_iovcnt: 1,
            vm_flags: 0,
        };
        let mut pktcnt: c_int = 1;

        let status = unsafe { vmnet::vmnet_write(self.interface, &mut pktdesc, &mut pktcnt) };
        Status::from_ffi(status)?;

        Ok(pktdesc.vm_pkt_size)
    }

    /// Add a new port forwarding rule on an interface.
    pub fn port_forwarding_rule_add(
        &mut self,
        address_family: AddressFamily,
        protocol: Protocol,
        external_port: u16,
        addr: IpAddr,
        internal_port: u16,
    ) -> Result<()> {
        let (tx, rx) = sync::mpsc::sync_channel(1);
        let block = block::ConcreteBlock::new(move |status: vmnet::VmnetReturnT| {
            tx.send(status).unwrap();
        });
        let block = block.copy();

        let addr_ffi = match addr {
            IpAddr::V4(addr) => Vec::from(addr.octets()),
            IpAddr::V6(addr) => Vec::from(addr.octets()),
        };

        let status = unsafe {
            vmnet::vmnet_interface_add_ip_port_forwarding_rule(
                self.interface,
                protocol as u8,
                external_port,
                address_family as u8,
                addr_ffi.as_ptr().cast(),
                internal_port,
                &*block as *const _ as *mut _,
            )
        };
        Status::from_ffi(status)?;

        Status::from_ffi(rx.recv().unwrap())
    }

    /// List port forwarding rules on an interface.
    pub fn port_forwarding_rules(&mut self, address_family: AddressFamily) -> Result<Vec<Rule>> {
        let (tx, rx) = sync::mpsc::sync_channel(1);
        let block = block::ConcreteBlock::new(move |xpc_object: XpcObjectT| {
            let mut result = Vec::new();

            if xpc_object.is_null() {
                tx.send(Ok(result)).unwrap();

                return;
            }

            for i in 0..unsafe { xpc_array_get_count(xpc_object) } {
                let rule = unsafe { xpc_array_get_value(xpc_object, i) };

                let mut protocol: u8 = 0;
                let mut external_port: u16 = 0;
                let mut internal_address: Vec<u8> = match address_family {
                    AddressFamily::Ipv4 => vec![0; 4],
                    AddressFamily::Ipv6 => vec![0; 16],
                };
                let mut internal_port: u16 = 0;

                let status = unsafe {
                    vmnet::vmnet_ip_port_forwarding_rule_get_details(
                        rule,
                        &mut protocol,
                        &mut external_port,
                        address_family.into(),
                        internal_address.as_mut_ptr() as *mut libc::c_void,
                        &mut internal_port,
                    )
                };
                if let Err(error) = Status::from_ffi(status) {
                    tx.send(Err(error)).unwrap();

                    return;
                }

                let addr: IpAddr = match address_family {
                    AddressFamily::Ipv4 => {
                        let buf: [u8; 4] = internal_address.as_slice().try_into().unwrap();
                        Ipv4Addr::from(buf).into()
                    }
                    AddressFamily::Ipv6 => {
                        let buf: [u8; 16] = internal_address.as_slice().try_into().unwrap();
                        Ipv6Addr::from(buf).into()
                    }
                };

                result.push(Rule {
                    address_family,
                    protocol: protocol.try_into().unwrap(),
                    external_port,
                    addr,
                    internal_port,
                });
            }

            tx.send(Ok(result)).unwrap();
        });
        let block = block.copy();

        let status = unsafe {
            vmnet::vmnet_interface_get_ip_port_forwarding_rules(
                self.interface,
                address_family as u8,
                &*block as *const _ as *mut _,
            )
        };
        Status::from_ffi(status)?;

        rx.recv().unwrap()
    }

    /// Remove an existing port forwarding rule on an interface.
    pub fn port_forwarding_rule_remove(
        &mut self,
        address_family: AddressFamily,
        protocol: Protocol,
        external_port: u16,
    ) -> Result<()> {
        let (tx, rx) = sync::mpsc::sync_channel(1);
        let block = block::ConcreteBlock::new(move |status: vmnet::VmnetReturnT| {
            tx.send(status).unwrap();
        });
        let block = block.copy();

        let status = unsafe {
            vmnet::vmnet_interface_remove_ip_port_forwarding_rule(
                self.interface,
                protocol as u8,
                external_port,
                address_family as u8,
                &*block as *const _ as *mut _,
            )
        };
        Status::from_ffi(status)?;

        Status::from_ffi(rx.recv().unwrap())
    }

    /// Stops the interface, allowing to catch errors (compared to [`drop()`](Interface::drop()),
    /// which will simply ignore any errors).
    pub fn finalize(&mut self) -> Result<()> {
        let (tx, rx) = sync::mpsc::sync_channel(1);
        let block = block::ConcreteBlock::new(move |status: vmnet::VmnetReturnT| {
            tx.send(status).unwrap();
        });
        let block = block.copy();

        let status = unsafe {
            vmnet::vmnet_stop_interface(self.interface, self.queue, &*block as *const _ as *mut _)
        };
        Status::from_ffi(status)?;

        let status = rx.recv().unwrap();
        Status::from_ffi(status)?;

        self.finalized = true;

        Ok(())
    }
}

impl Drop for Interface {
    fn drop(&mut self) {
        if !self.finalized {
            let _ = self.finalize();
        }
    }
}

/// Retrieves a list of interfaces for use in [`Bridged`](Mode::Bridged) mode.
///
/// See [official Apple's documentation](https://developer.apple.com/documentation/vmnet/3152677-vmnet_copy_shared_interface_list) for more details.
pub fn shared_interface_list() -> Vec<String> {
    let mut result: Vec<String> = Vec::new();

    let shared_interface_list = unsafe { vmnet_copy_shared_interface_list() };
    let shared_interface_count = unsafe { xpc_array_get_count(shared_interface_list) };

    for i in 0..shared_interface_count {
        let c_string_ptr = unsafe { xpc_array_get_string(shared_interface_list, i) };
        let string_value = unsafe { CStr::from_ptr(c_string_ptr) }
            .to_string_lossy()
            .to_string();
        result.push(string_value);
    }

    result
}

#[cfg(test)]
mod tests {
    use crate::interface::shared_interface_list;
    use crate::mode::host::{
        Configuration, IP6Configuration, IPConfiguration, ManualConfiguration,
    };
    use crate::mode::{Bridged, Host, Mode, Shared};
    use crate::parameters::{Parameter, ParameterKind};
    use crate::port_forwarding::{AddressFamily, Protocol, Rule};
    use crate::{Events, Interface, Options};
    use hexdump::hexdump;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::sync;

    #[test]
    fn bridged_simple() {
        let bridged_config = Bridged {
            shared_interface_name: "en0".to_string(),
        };
        let mut iface = Interface::new(Mode::Bridged(bridged_config), Default::default()).unwrap();
        iface.finalize().unwrap();
    }

    #[test]
    fn host_simple() {
        let mut iface = Interface::new(Mode::Host(Default::default()), Default::default()).unwrap();
        iface.finalize().unwrap();
    }

    #[test]
    fn host_network_identifier() {
        let host_config = Host {
            configuration: Some(Configuration::Manual(ManualConfiguration {
                network_identifier: uuid::Uuid::new_v4(),
                ip_configuration: Some(IPConfiguration {
                    address: "214.0.0.1".to_string(),
                    subnet_mask: "255.255.255.0".to_string(),
                }),
                ip6_configuration: Some(IP6Configuration {
                    address: "1337::1".to_string(),
                }),
            })),
            ..Default::default()
        };

        let mut first_iface =
            Interface::new(Mode::Host(host_config.clone()), Options::default()).unwrap();
        let mut second_iface =
            Interface::new(Mode::Host(host_config.clone()), Options::default()).unwrap();

        let first_addr = smoltcp::wire::EthernetAddress([0x02, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
        let second_addr = smoltcp::wire::EthernetAddress([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        let mut buf: [u8; 1514] = [0; 1514];
        let mut frame = smoltcp::wire::EthernetFrame::new_unchecked(&mut buf);
        let repr = smoltcp::wire::EthernetRepr {
            src_addr: first_addr,
            dst_addr: second_addr,
            ethertype: smoltcp::wire::EthernetProtocol::Arp,
        };
        repr.emit(&mut frame);
        let n = first_iface
            .write(&frame.as_ref()[..repr.buffer_len()])
            .unwrap();
        println!("wrote {} bytes to the second interface", n);
        hexdump(&buf[..n]);

        loop {
            let mut buf: [u8; 1514] = [0; 1514];
            if let Ok(n) = second_iface.read(&mut buf) {
                let frame = smoltcp::wire::EthernetFrame::new_checked(&buf[..n]).unwrap();
                if frame.src_addr() == first_addr && frame.dst_addr() == second_addr {
                    println!("received {} bytes from the first interface", n);
                    hexdump(&buf[..n]);
                    break;
                } else {
                    println!("received something else ({} bytes)", n);
                    hexdump(&buf[..n]);
                }
            }
        }

        first_iface.finalize().unwrap();
        second_iface.finalize().unwrap();
    }

    #[test]
    fn shared_simple() {
        let mut iface =
            Interface::new(Mode::Shared(Default::default()), Default::default()).unwrap();
        iface.finalize().unwrap();
    }

    #[test]
    fn blocking_event_callback() {
        let mut iface =
            Interface::new(Mode::Shared(Default::default()), Default::default()).unwrap();

        // Barriers that are easy to split into two owners
        let (callback_ready_tx, callback_ready_rx) = sync::mpsc::sync_channel(0);
        let (event_cleared_tx, event_cleared_rx) = sync::mpsc::sync_channel(0);

        // Problematic callback that hangs at the time
        // we call clear_event_callback()
        iface
            .set_event_callback(Events::PACKETS_AVAILABLE, move |_, _| {
                callback_ready_tx.send(()).unwrap();
                event_cleared_rx.recv().unwrap();
            })
            .unwrap();

        // Wait for the callback to be scheduled
        callback_ready_rx.recv().unwrap();

        // De-schedule callback
        iface.clear_event_callback().unwrap();

        // Now let the callback finish
        event_cleared_tx.send(()).unwrap();

        // Ensure that we can finalize() without hangs
        iface.finalize().unwrap();
    }

    #[test]
    fn test_retrieve_shared_interfaces() {
        assert!(shared_interface_list().contains(&"en0".to_string()));
    }

    #[test]
    fn port_forwarding() {
        // Create an interface
        let mut iface =
            Interface::new(Mode::Shared(Shared::default()), Default::default()).unwrap();

        // Figure out interface's end address
        // that we'll use for port forwarding
        let Some(Parameter::EndAddress(end_address)) =
            iface.parameters().get(ParameterKind::EndAddress)
        else {
            panic!("failed to retrieve interface's end address");
        };

        let addr: IpAddr = Ipv4Addr::from_str(end_address.as_str()).unwrap().into();

        // Remove a non-existent rule
        assert!(iface
            .port_forwarding_rule_remove(AddressFamily::Ipv4, Protocol::Tcp, 2222)
            .is_err());

        // Configure port forwarding
        iface
            .port_forwarding_rule_add(AddressFamily::Ipv4, Protocol::Tcp, 2222, addr, 22)
            .unwrap();
        iface
            .port_forwarding_rule_add(AddressFamily::Ipv4, Protocol::Tcp, 8080, addr, 80)
            .unwrap();
        assert_eq!(
            vec![
                Rule {
                    address_family: AddressFamily::Ipv4,
                    protocol: Protocol::Tcp,
                    external_port: 2222,
                    addr,
                    internal_port: 22,
                },
                Rule {
                    address_family: AddressFamily::Ipv4,
                    protocol: Protocol::Tcp,
                    external_port: 8080,
                    addr,
                    internal_port: 80,
                },
            ],
            iface.port_forwarding_rules(AddressFamily::Ipv4).unwrap(),
        );

        // Remove a non-existent rule
        assert!(iface
            .port_forwarding_rule_remove(AddressFamily::Ipv4, Protocol::Tcp, 4242)
            .is_err());

        // Remove the second rule
        iface
            .port_forwarding_rule_remove(AddressFamily::Ipv4, Protocol::Tcp, 8080)
            .unwrap();
        assert_eq!(
            vec![Rule {
                address_family: AddressFamily::Ipv4,
                protocol: Protocol::Tcp,
                external_port: 2222,
                addr,
                internal_port: 22,
            }],
            iface.port_forwarding_rules(AddressFamily::Ipv4).unwrap(),
        );

        // Remove the remaining first rule
        iface
            .port_forwarding_rule_remove(AddressFamily::Ipv4, Protocol::Tcp, 2222)
            .unwrap();
        assert_eq!(
            Vec::<Rule>::new(),
            iface.port_forwarding_rules(AddressFamily::Ipv4).unwrap(),
        );

        iface.finalize().unwrap();
    }
}
