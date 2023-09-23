/// Structs that are common to more than one mode.
pub mod common;

/// Structs describing the [`Bridged`](bridged::Bridged) mode.
pub mod bridged;
pub use bridged::Bridged;

/// Structs and enumerations describing the [`Host`](host::Host) mode.
pub mod host;
pub use host::Host;

/// Structs describing the [`Shared`](shared::Shared) (or NAT) mode.
pub mod shared;
pub use shared::Shared;

use crate::parameters::Parameter;

/// Enumeration of all possible modes in which the interface can be instantiated.
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
