#! /bin/python3
import sys
import socket
import math
import sys
import time


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

    def setupx(self, txport, pktlen, period, nbpkts):
        ports = txport.split('-')
        try:
            ports = list(map(lambda x: int(x), ports))
            start_txport = ports[0]

            self._write_reg(4, start_txport)
            port_rs = self._read_reg(4, custom_port=start_txport)
            print(f'Start TX Port: Requested={start_txport}, Set={port_rs}')
            
            if len(ports) == 2:
                end_txport = ports[1]
                port_rs = None
                if start_txport > end_txport:
                    print('Start Port cannot be larger than end port')
                    return

                self._write_reg(10, end_txport)
                port_rs = self._read_reg(10, custom_port=end_txport)
                print(f'End TX Port: Requested={end_txport}, Set={port_rs}')

        except Exception as e:
            print(e)
            return
        

        cycles = math.ceil(period / TristanBoard.CYCLE_TIME)
        self._write_reg(5, cycles)
        cycles_rs = self._read_reg(5)
        print(f'TX Period: Requested={cycles}, Set={cycles_rs}')

        self._write_reg(6, pktlen)
        pktlen_rs = self._read_reg(6)
        print(f'TX Pkt Length: Requested={pktlen}, Set={pktlen_rs}')

        self._set_nb_packets(nbpkts)
        nbpkts_rs = self._get_nb_packets()
        print(f'Number Pkt: Requested={nbpkts}, Set={nbpkts_rs}')

    def _set_nb_packets(self, nbpackets):
        reg8value = nbpackets & 0xFFFFFFFF
        reg9value = (nbpackets >> 32) & 0xFFFFFFFF

        self._write_reg(8, reg8value)
        self._write_reg(9, reg9value)

    def _get_nb_packets(self,):
        reg8value = self._read_reg(8)
        reg9value = self._read_reg(9)

        if reg8value is None or reg9value is None:
            return None

        return reg8value | ((reg9value << 32) & 0xFFFFFFFF00000000)

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

    def _read_reg(self, reg, custom_port=None):
        hexval = self._read_from_device(f'r{reg:08X}', custom_port=custom_port)
        return int(hexval, 16) if hexval is not None else None

    def _write_to_device(self, msg):
        print(msg)
        msg = msg.encode('ascii')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            return sock.sendto(msg, (self.ip, self.port))

    def _read_from_device(self, msg, custom_port: int = None):
        msg_binary = msg.encode('ascii')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            try:
                sock.sendto(
                    msg_binary, (self.ip, self.port if custom_port is None else custom_port))
                resp_data, _ = sock.recvfrom(1024)
                return resp_data.decode('ascii')[:8]
            except socket.timeout:
                print(msg, 'timed out')
                return None


def help():
    print('tristan.py setup txport pktlen linkspeed nbpkts')
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
            txport = args[2]
            pktlen = int(args[3])
            linkspeed = int(args[4])
            tristan.setup(txport, pktlen, linkspeed)
        tristan.start()
    elif cmd == 'startx':
        if len(args) == 6:
            tristan.stop()
            txport = args[2]
            pktlen = int(args[3])
            period = float(args[4])
            nbpkts = int(args[5])
            tristan.setupx(txport, pktlen, period, nbpkts)
        tristan.start()
        secs = math.ceil(period * nbpkts)
        print('Sleeping for...', secs)
        time.sleep(secs)
    elif cmd == 'stop':
        tristan.stop()
    elif cmd == 'setup' and len(args) == 5:
        txport = args[2]
        pktlen = int(args[3])
        linkspeed = int(args[4])
        tristan.setup(txport, pktlen, linkspeed)
    elif cmd == 'setupx' and len(args) == 6:
        txport = args[2]
        pktlen = int(args[3])
        period = float(args[4])
        nbpkts = int(args[5])
        tristan.setupx(txport, pktlen, period, nbpkts)
    elif cmd == 'query':
        tristan.query_all()
    else:
        help()
        sys.exit()
