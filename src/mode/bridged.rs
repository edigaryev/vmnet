use crate::ffi::vmnet::Mode;
use crate::parameters::Parameter;

#[derive(Debug, Clone)]
pub struct Bridged {
    pub shared_interface_name: String,
}

impl From<Bridged> for Vec<Parameter> {
    fn from(bridged: Bridged) -> Self {
        vec![
            Parameter::OperationMode(Mode::Bridged.into()),
            Parameter::SharedInterfaceName(bridged.shared_interface_name),
        ]
    }
}
