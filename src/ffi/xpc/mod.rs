mod dictionary;
pub use dictionary::Dictionary;

mod xpc_data;
pub use xpc_data::XpcData;

use std::ffi::{c_int, c_void};

use std::os::raw::{c_char, c_uchar};

pub type XpcObjectT = *mut c_void;
pub type XpcTypeT = *const c_void;

extern "C" {
    pub fn xpc_get_type(object: XpcObjectT) -> *const XpcTypeT;

    pub static _xpc_type_bool: XpcTypeT;
    pub static _xpc_type_uint64: XpcTypeT;
    pub static _xpc_type_string: XpcTypeT;
    pub static _xpc_type_uuid: XpcTypeT;

    pub fn xpc_bool_get_value(xbool: XpcObjectT) -> bool;
    pub fn xpc_uint64_get_value(xuint: XpcObjectT) -> u64;
    pub fn xpc_string_get_string_ptr(xstring: XpcObjectT) -> *const c_char;
    pub fn xpc_uuid_get_bytes(xuuid: XpcObjectT) -> *const c_uchar;

    pub fn xpc_array_get_count(xarray: XpcObjectT) -> c_int;
    pub fn xpc_array_get_string(xarray: XpcObjectT, index: c_int) -> *const c_char;
    pub fn xpc_array_get_value(xarray: XpcObjectT, index: c_int) -> XpcObjectT;
}

extern "C" {
    pub fn xpc_dictionary_create_empty() -> XpcObjectT;

    pub fn xpc_dictionary_apply(xdict: XpcObjectT, applier: *mut c_void) -> bool;
    pub fn xpc_dictionary_get_value(xdict: XpcObjectT, key: *const c_char) -> XpcObjectT;

    pub fn xpc_dictionary_set_bool(xdict: XpcObjectT, key: *const c_char, value: bool);
    pub fn xpc_dictionary_set_uint64(xdict: XpcObjectT, key: *const c_char, value: u64);
    pub fn xpc_dictionary_set_string(xdict: XpcObjectT, key: *const c_char, value: *const c_char);
    pub fn xpc_dictionary_set_uuid(xdict: XpcObjectT, key: *const c_char, value: *const c_uchar);

    pub fn xpc_retain(object: XpcObjectT) -> XpcObjectT;
    pub fn xpc_release(object: XpcObjectT);
}
