use crate::ffi::vmnet;
use crate::mode::common::SubnetOptions;
use crate::parameters::Parameter;

#[derive(Debug, Default, Clone)]
pub struct Shared {
    pub subnet_options: Option<SubnetOptions>,
    pub nat66_prefix: Option<String>,
    pub mtu: Option<u64>,
}

impl From<Shared> for Vec<Parameter> {
    fn from(shared: Shared) -> Self {
        let mut result = vec![Parameter::OperationMode(vmnet::Mode::Shared as u64)];

        if let Some(subnet_options) = shared.subnet_options {
            result.append(&mut subnet_options.into())
        }

        if let Some(nat66_prefix) = shared.nat66_prefix {
            result.push(Parameter::NAT66Prefix(nat66_prefix));
        }

        if let Some(mtu) = shared.mtu {
            result.push(Parameter::MTU(mtu))
        }

        result
    }
}
