use crate::parameters::Parameter;

#[derive(Debug, Clone)]
pub struct SubnetOptions {
    pub start_address: String,
    pub end_address: String,
    pub subnet_mask: String,
}

impl From<SubnetOptions> for Vec<Parameter> {
    fn from(subnet_options: SubnetOptions) -> Self {
        vec![
            Parameter::StartAddress(subnet_options.start_address),
            Parameter::EndAddress(subnet_options.end_address),
            Parameter::SubnetMask(subnet_options.subnet_mask),
        ]
    }
}
