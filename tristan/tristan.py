#! /bin/python3
import sys
import socket
import math
import sys


class TristanBoard:
    CYCLE_TIME = 3.1e-9  # in nanoseconds

    # 4 uint32 streamPort r/w [15:0]
    # 5 uint32 M_period r/w send packet every ... in 322.265625 MHz ticks 0
    # 6 uint32 N_size r/w packet length in bytes 0
    # 7 uint32 RunControl r/w bit0

    def __init__(self, port=5000, ip='192.168.1.100', ):
        self.port = port
        self.ip = ip

    def setup(self, txport, pktlen, linkspeed):
        mtu_size = pktlen + 18 + 20 + 8  # eth hdr and CRC + IP hdr + UDP hdr
        period = mtu_size / (linkspeed * 1e9 / 8)
        self.setupx(txport, pktlen, period)

    def setupx(self, txport, pktlen, period):
        self._write_reg(4, txport)
        port_rs = self._read_reg(4)
        print(f'TX Port: Requested={txport}, Set={port_rs}')

        cycles = math.ceil(period / TristanBoard.CYCLE_TIME)
        self._write_reg(5, cycles)
        cycles_rs = self._read_reg(5)
        print(f'TX Period: Requested={cycles}, Set={cycles_rs}')

        self._write_reg(6, pktlen)
        pktlen_rs = self._read_reg(6)
        print(f'TX Pkt Length: Requested={pktlen}, Set={pktlen_rs}')

    def start(self):
        self._write_reg(7, 1)
        pktlen_rs = self._read_reg(7)
        if pktlen_rs == 1:
            print('Board Started!')
        else:
            print(f'Board Not Started! Returned={pktlen_rs}')

    def stop(self):
        self._write_reg(7, 0)
        pktlen_rs = self._read_reg(7)
        if pktlen_rs == 0:
            print('Board Stopped!')
        else:
            print(f'Board Error! Returned={pktlen_rs}')

    def query_all(self):
        port = self._read_reg(4)
        period = self._read_reg(5)
        pktlen = self._read_reg(6)
        running = self._read_reg(7)

        print(dict(port=port, period=period, pktlen=pktlen, running=running))

    def _write_reg(self, reg, value):
        return self._write_to_device(f'w{reg:08X}_{value:08X}')

    def _read_reg(self, reg):
        hexval = self._read_from_device(f'r{reg:08X}')
        return int(hexval, 16) if hexval is not None else None

    def _write_to_device(self, msg):
        print(msg)
        msg = msg.encode('ascii')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            return sock.sendto(msg, (self.ip, self.port))

    def _read_from_device(self, msg):
        msg_binary = msg.encode('ascii')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            try:
                sock.sendto(msg_binary, (self.ip, self.port))
                resp_data, _ = sock.recvfrom(1024)
                return resp_data.decode('ascii')[:8]
            except socket.timeout:
                print(msg, 'timed out')
                return None


def help():
    print('tristan.py setup txport pktlen linkspeed')
    print('tristan.py start')
    print('tristan.py stop')


if __name__ == '__main__':
    args = sys.argv
    if len(args) < 2:
        help()
        sys.exit()

    tristan = TristanBoard()
    cmd = args[1]
    if cmd == 'start':
        if len(args) == 5:
            tristan.stop()
            txport = int(args[2])
            pktlen = int(args[3])
            linkspeed = int(args[4])
            tristan.setup(txport, pktlen, linkspeed)
        tristan.start()
    elif cmd == 'startx':
        if len(args) == 5:
            tristan.stop()
            txport = int(args[2])
            pktlen = int(args[3])
            period = float(args[4])
            tristan.setupx(txport, pktlen, period)
        tristan.start()
    elif cmd == 'stop':
        tristan.stop()
    elif cmd == 'setup' and len(args) == 5:
        txport = int(args[2])
        pktlen = int(args[3])
        linkspeed = int(args[4])
        tristan.setup(txport, pktlen, linkspeed)
    elif cmd == 'setupx' and len(args) == 5:
        txport = int(args[2])
        pktlen = int(args[3])
        period = float(args[4])
        tristan.setupx(txport, pktlen, period)
    elif cmd == 'query':
        tristan.query_all()
    else:
        help()
        sys.exit()