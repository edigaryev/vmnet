use crate::ffi::vmnet::vmpktdesc;
use std::ptr::null_mut;

/// Holds multiple packet descriptors to avoid unnecessary allocations
/// on each [`Interface::read_batch()`](crate::Interface::read_batch)
/// and [`Interface::write_batch()`](crate::Interface::write_batch) calls.
pub struct Batch {
    _iovecs: Vec<libc::iovec>,
    pub(crate) pktdescs: Vec<vmpktdesc>,
}

impl Batch {
    /// Preallocates a batch of size `count` which holds the packet descriptors.
    ///
    /// These packet descriptors are used internally by [`Interface::read_batch()`](crate::Interface::read_batch)
    /// and [`Interface::write_batch()`](crate::Interface::write_batch).
    ///
    /// Note that you'll only be able to receive or send as many packets
    /// as preallocated in a batch.
    pub fn preallocate(count: usize) -> Batch {
        let mut _iovecs = vec![
            libc::iovec {
                iov_base: null_mut(),
                iov_len: 0,
            };
            count
        ];

        let pktdescs = _iovecs
            .iter_mut()
            .map(|iovec| vmpktdesc {
                vm_pkt_size: iovec.iov_len,
                vm_pkt_iov: iovec,
                vm_pkt_iovcnt: 1,
                vm_flags: 0,
            })
            .collect();

        Batch { _iovecs, pktdescs }
    }

    /// Retrieves packet sizes received after calling the [`Interface::read_batch()`](crate::Interface::read_batch).
    ///
    /// Note that since a [`Batch`] abstraction lacks any information about the number of packets received,
    /// use [`Iterator::take()`](Iterator::take) on the returned iterator in order to limit it
    /// to only useful items.
    pub fn packet_sizes(&self) -> impl Iterator<Item = usize> + use<'_> {
        self.pktdescs.iter().map(|pktdesc| pktdesc.vm_pkt_size)
    }

    /// Given a slice of buffers used for a call to [`Interface::read_batch()`](crate::Interface::read_batch),
    /// returns an iterator over mutable slices derived from the provided buffers, where each slice is limited
    /// to the corresponding received packet length.
    ///
    /// This method is based on [`Batch::packet_sizes()`](Batch::packet_sizes) and is provided for convenience.
    ///
    /// Note that since a [`Batch`] abstraction lacks any information about the number of packets received,
    /// use [`Iterator::take()`](Iterator::take) on the returned iterator in order to limit it
    /// to only useful items.
    pub fn packet_sized_bufs<'a, B>(
        &self,
        bufs: &'a [B],
    ) -> impl Iterator<Item = &'a [u8]> + use<'a, '_, B>
    where
        B: AsRef<[u8]>,
    {
        self.packet_sizes()
            .zip(bufs)
            .map(|(packet_size, buf)| &buf.as_ref()[..packet_size])
    }
}
