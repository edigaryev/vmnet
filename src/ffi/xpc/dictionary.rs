use crate::ffi::xpc::{
    xpc_dictionary_apply, xpc_dictionary_create_empty, xpc_dictionary_get_value,
    xpc_dictionary_set_bool, xpc_dictionary_set_string, xpc_dictionary_set_uint64,
    xpc_dictionary_set_uuid, xpc_release, xpc_retain, XpcData, XpcObjectT,
};
use block2::RcBlock;
use objc2::encode::{Encode, Encoding};
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::rc::Rc;

#[repr(transparent)]
#[derive(Clone, Copy)]
struct CBool(bool);

impl CBool {
    const TRUE: Self = Self(true);
    const FALSE: Self = Self(false);
}

// SAFETY: `xpc_dictionary_applier_t` returns C `bool`[1], which preprocesses
// to C99 `_Bool`[2]; objc2 recommends using a transparent wrapper around
// `bool` in this case[3].
//
// [1]: grep xpc_dictionary_applier_t "$(xcrun --show-sdk-path)/usr/include/xpc/xpc.h"
// [2]: grep '#define bool' "$(xcrun clang -print-resource-dir)/include/stdbool.h"
// [3]: https://docs.rs/objc2/latest/objc2/runtime/struct.Bool.html
unsafe impl Encode for CBool {
    const ENCODING: Encoding = Encoding::Bool;
}

pub struct Dictionary {
    xdict: XpcObjectT,
}

impl Dictionary {
    pub fn new() -> Self {
        Dictionary {
            xdict: unsafe { xpc_dictionary_create_empty() },
        }
    }

    pub unsafe fn from_xpc(xdict: XpcObjectT) -> Self {
        Dictionary {
            xdict: xpc_retain(xdict),
        }
    }

    pub unsafe fn to_xpc(&self) -> XpcObjectT {
        self.xdict
    }

    pub fn get(&self, key: String) -> Option<XpcData> {
        let key_ = CString::new(key).unwrap();
        let key = key_.as_ptr();

        let xpc_value = unsafe { xpc_dictionary_get_value(self.xdict, key) };
        if xpc_value.is_null() {
            return None;
        }

        unsafe { XpcData::from_xpc_value(xpc_value) }
    }

    pub fn set(&mut self, key: String, value: XpcData) {
        let key_ = CString::new(key).unwrap();
        let key = key_.as_ptr();

        match value {
            XpcData::Uint64(value) => unsafe { xpc_dictionary_set_uint64(self.xdict, key, value) },
            XpcData::String(value) => {
                let c_string = CString::new(value).unwrap();
                unsafe { xpc_dictionary_set_string(self.xdict, key, c_string.as_ptr()) }
            }
            XpcData::Bool(value) => unsafe { xpc_dictionary_set_bool(self.xdict, key, value) },
            XpcData::Uuid(value) => unsafe {
                xpc_dictionary_set_uuid(self.xdict, key, value.as_bytes().as_ptr())
            },
        };
    }
}

impl Default for Dictionary {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Dictionary {
    fn clone(&self) -> Self {
        Dictionary {
            xdict: unsafe { xpc_retain(self.xdict) },
        }
    }
}

impl Drop for Dictionary {
    fn drop(&mut self) {
        unsafe { xpc_release(self.xdict) }
    }
}

impl From<HashMap<String, XpcData>> for Dictionary {
    fn from(from: HashMap<String, XpcData>) -> Self {
        let mut result = Dictionary::new();

        for (key, value) in from {
            result.set(key, value);
        }

        result
    }
}

impl TryFrom<Dictionary> for HashMap<String, XpcData> {
    type Error = ();

    fn try_from(value: Dictionary) -> Result<Self, Self::Error> {
        let result = Rc::new(RefCell::new(HashMap::new()));
        let result_weak = Rc::downgrade(&result);

        let block: RcBlock<dyn Fn(*const c_char, XpcObjectT) -> CBool> =
            RcBlock::new(move |key: *const c_char, value: XpcObjectT| -> CBool {
                let key = unsafe { CStr::from_ptr(key).to_string_lossy().to_string() };

                let value = match unsafe { XpcData::from_xpc_value(value) } {
                    Some(value) => value,
                    None => return CBool::FALSE,
                };

                result_weak
                    .upgrade()
                    .unwrap()
                    .borrow_mut()
                    .insert(key, value);

                CBool::TRUE
            });

        let ret = unsafe { xpc_dictionary_apply(value.xdict, RcBlock::as_ptr(&block).cast()) };
        if !ret {
            return Err(());
        }

        Ok(Rc::try_unwrap(result).unwrap().into_inner())
    }
}
