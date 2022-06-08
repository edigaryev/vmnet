use crate::ffi::vmnet;
use crate::mode::common::SubnetOptions;
use crate::parameters::Parameter;

#[derive(Debug, Default, Clone)]
pub struct Host {
    pub configuration: Option<Configuration>,
    pub mtu: Option<u64>,
}

impl From<Host> for Vec<Parameter> {
    fn from(host: Host) -> Self {
        let mut result = vec![Parameter::OperationMode(vmnet::Mode::Host as u64)];

        if let Some(configuration) = host.configuration {
            result.append(&mut configuration.into());
        }

        if let Some(mtu) = host.mtu {
            result.push(Parameter::MTU(mtu));
        }

        result
    }
}

#[derive(Debug, Clone)]
pub enum Configuration {
    Manual(ManualConfiguration),
    Automatic(SubnetOptions),
}

impl From<Configuration> for Vec<Parameter> {
    fn from(configuration: Configuration) -> Self {
        match configuration {
            Configuration::Manual(manual_config) => manual_config.into(),
            Configuration::Automatic(automatic_config) => automatic_config.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManualConfiguration {
    pub network_identifier: uuid::Uuid,
    pub ip_configuration: Option<IPConfiguration>,
    pub ip6_configuration: Option<IP6Configuration>,
}

#[derive(Debug, Clone)]
pub struct IPConfiguration {
    pub address: String,
    pub subnet_mask: String,
}

#[derive(Debug, Clone)]
pub struct IP6Configuration {
    pub address: String,
}

impl From<ManualConfiguration> for Vec<Parameter> {
    fn from(manual_configuration: ManualConfiguration) -> Self {
        let mut result = vec![Parameter::NetworkIdentifier(
            manual_configuration.network_identifier,
        )];

        if let Some(ip_configuration) = manual_configuration.ip_configuration {
            result.push(Parameter::HostIPAddress(ip_configuration.address));
            result.push(Parameter::HostSubnetMask(ip_configuration.subnet_mask));
        }

        if let Some(ip6_configuration) = manual_configuration.ip6_configuration {
            result.push(Parameter::HostIP6Address(ip6_configuration.address));
        }

        result
    }
}
