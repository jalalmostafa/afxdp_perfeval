#! /bin/python3
import socket
import time
import sys
USHORT_MAX = 65535

if __name__ == '__main__':
    size = int(sys.argv[1])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        i = 0
        msg = ''
        while True:
            try:
                seq = (i % USHORT_MAX).to_bytes(2, 'little', signed=False)
                msg = 'a' * (size - 2)
                payload = seq + msg.encode('ascii')
                print(payload)
                i += 1
                sock.sendto(payload, ('192.168.1.20', 5000))
            except socket.timeout:
                print(msg, 'timed out')
