use crate::ffi::xpc::{
    _xpc_type_bool, _xpc_type_string, _xpc_type_uint64, _xpc_type_uuid, xpc_bool_get_value,
    xpc_get_type, xpc_string_get_string_ptr, xpc_uint64_get_value, xpc_uuid_get_bytes, XpcObjectT,
};
use std::ffi::CStr;

#[derive(Debug, Clone, PartialEq)]
pub enum XpcData {
    Uint64(u64),
    String(String),
    Bool(bool),
    Uuid(uuid::Uuid),
}

impl XpcData {
    pub unsafe fn from_xpc_value(value: XpcObjectT) -> Option<Self> {
        let xpc_type = xpc_get_type(value);

        if xpc_type == &_xpc_type_bool {
            let bool_value = xpc_bool_get_value(value);
            Some(Self::Bool(bool_value))
        } else if xpc_type == &_xpc_type_string {
            let c_string_ptr = xpc_string_get_string_ptr(value);
            let string_value = CStr::from_ptr(c_string_ptr).to_string_lossy().to_string();
            Some(Self::String(string_value))
        } else if xpc_type == &_xpc_type_uint64 {
            let u64_value = xpc_uint64_get_value(value);
            Some(Self::Uint64(u64_value))
        } else if xpc_type == &_xpc_type_uuid {
            let uuid_ptr = xpc_uuid_get_bytes(value);
            let uuid_slice = std::slice::from_raw_parts(uuid_ptr, 16);
            Some(Self::Uuid(uuid::Uuid::from_slice(uuid_slice).unwrap()))
        } else {
            None
        }
    }
}

impl From<bool> for XpcData {
    fn from(val: bool) -> Self {
        XpcData::Bool(val)
    }
}

impl From<u64> for XpcData {
    fn from(val: u64) -> Self {
        XpcData::Uint64(val)
    }
}

impl From<String> for XpcData {
    fn from(val: String) -> Self {
        XpcData::String(val)
    }
}

impl From<uuid::Uuid> for XpcData {
    fn from(val: uuid::Uuid) -> Self {
        XpcData::Uuid(val)
    }
}
