use crate::ffi::vmnet::Mode;
use crate::parameters::Parameter;

/// Interface mode that allows attaching to an already existing network interface.
#[derive(Debug, Clone)]
pub struct Bridged {
    /// Interface to attach to.
    ///
    /// To get a list of valid interfaces for this field use the
    /// [`shared_interface_list()`](crate::interface::shared_interface_list) function.
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
