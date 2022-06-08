pub mod common;

pub mod bridged;
pub use bridged::Bridged;

pub mod host;
pub use host::Host;

pub mod shared;
pub use shared::Shared;

use crate::parameters::Parameter;

#[derive(Debug, Clone)]
pub enum Mode {
    Host(Host),
    Shared(Shared),
    Bridged(Bridged),
}

impl From<Mode> for Vec<Parameter> {
    fn from(mode: Mode) -> Self {
        match mode {
            Mode::Host(host) => host.into(),
            Mode::Shared(shared) => shared.into(),
            Mode::Bridged(bridged) => bridged.into(),
        }
    }
}
