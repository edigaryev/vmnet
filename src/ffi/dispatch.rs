use std::ffi::c_void;

pub type DispatchQueueGlobalT = *mut c_void;

extern "C" {
    pub fn dispatch_get_global_queue(identifier: isize, flags: usize) -> DispatchQueueGlobalT;
}
