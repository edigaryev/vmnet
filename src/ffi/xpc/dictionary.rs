use crate::ffi::xpc::{
    xpc_dictionary_apply, xpc_dictionary_create_empty, xpc_dictionary_get_value,
    xpc_dictionary_set_bool, xpc_dictionary_set_string, xpc_dictionary_set_uint64,
    xpc_dictionary_set_uuid, xpc_release, xpc_retain, XpcData, XpcObjectT,
};
use block::ConcreteBlock;
use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::rc::Rc;

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

        let block = ConcreteBlock::new(move |key: *const c_char, value: XpcObjectT| -> bool {
            let key = unsafe { CStr::from_ptr(key).to_string_lossy().to_string() };

            let value = match unsafe { XpcData::from_xpc_value(value) } {
                Some(value) => value,
                None => return false,
            };

            result_weak
                .upgrade()
                .unwrap()
                .borrow_mut()
                .insert(key, value);

            true
        });
        let block = block.copy();

        let ret = unsafe { xpc_dictionary_apply(value.xdict, &*block as *const _ as *mut _) };
        if !ret {
            return Err(());
        }

        Ok(Rc::try_unwrap(result).unwrap().into_inner())
    }
}
