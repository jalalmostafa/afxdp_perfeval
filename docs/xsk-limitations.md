# XSK Limitations and Notes

- UMEM chunk size is between 2048 and 4096 (PAGE_SIZE) => no support for jumbo frames
- UMEM chunk size is power of 2
- Rings (FQ - CQ - RX - TX) sizes are only power of 2
- Number of sockets on ONE queue per umem is power of 2? => XSKs on one `xsk_buff_pool` is power of 2 ?
- Multithreading on one socket is not possible (fill and completion rings are one-producer/one-consumer rings)
- One umem per (nic, queueid) tuple (required for zero-copy; not implemented for copy)
- No flags should be specified to the XSK with `XDP_SHARED_UMEM` (create first socket as usual - no `XDP_SHARED_UMEM` - and 2nd socket and others should ONLY have `XDP_SHARED_UMEM`)
