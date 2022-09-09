# XSK Limitations

- Number of sockets per umem is power of 2?
- Multithreading on one socket is not possible (fill and completion rings are one-producer/one-consumer rings)
- One umem per (nic, queueid) tuple (required for zero-copy; not implemented for copy)
