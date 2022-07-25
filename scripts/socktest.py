import socket as sock
import sys
import time

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Incorrect number of args')

    dst = sys.argv[1]
    many = int(sys.argv[2])
    i = 0

    with sock.socket(family=sock.AF_INET, type=sock.SOCK_DGRAM, proto=0) as sck:
        dst_addr = (dst, 5000) 
        while many != i:
            sck.sendto(b'123123123123', dst_addr)
            time.sleep(0.1)
            i += 1