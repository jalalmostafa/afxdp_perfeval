#! /bin/python3
import sys
import socket
import math
import sys
import time


class TristanBoard:
    CYCLE_TIME = 3.1e-9  # in nanoseconds

    def __init__(self, port=5001, ip='192.168.1.100', ):
        self.port = port
        self.ip = ip

    def _set_txports(self, txport_str):
        ports = txport_str.split('-')
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

    def _set_threshold(self, threshold):
        self._write_reg_raw(5, threshold)
        threshold_rs = self._read_reg(5)
        print(f'Trigger Threshold: Requested={threshold}, Set={threshold_rs}')

    def _set_pktlen(self, pktlen):
        self._write_reg(6, pktlen)
        pktlen_rs = self._read_reg(6)
        print(f'TX Pkt Length: Requested={pktlen}, Set={pktlen_rs}')

    def _set_nchnls(self, chnl):
        if chnl is None:
            return
        self._write_reg(7, chnl)
        chnl_rs = self._read_reg(7)
        print(f'Histogram Channels: Requested={chnl}, Set={chnl_rs}')

    def _set_nb_packets(self, nbpackets):
        reg8value = nbpackets & 0xFFFFFFFF
        reg9value = (nbpackets >> 32) & 0xFFFFFFFF

        self._write_reg(8, reg8value)
        self._write_reg(9, reg9value)
        nbpkts_rs = self._get_nb_packets()
        print(f'Number Pkt: Requested={nbpackets}, Set={nbpkts_rs}')

    def _get_nb_packets(self,):
        reg8value = self._read_reg(8)
        reg9value = self._read_reg(9)

        if reg8value is None or reg9value is None:
            return None

        return reg8value | ((reg9value << 32) & 0xFFFFFFFF00000000)

    def setup(self, txport, threshold, nbpkts, pktlen=None, nchnls=None):
        self._set_txports(txport)  # reg 4 and 10
        self._set_threshold(threshold)  # reg 5
        if pktlen is not None:
            self._set_pktlen(pktlen)  # reg 6
        if nchnls is not None:
            self._set_nchnls(nchnls)  # reg 7
        self._set_nb_packets(nbpkts)  # reg 8 and 9

    def start(self, hist_on='const', upstream=True):
        run_cmd = 0b001
        if hist_on == 'seq':
            run_cmd = run_cmd | 0b010

        if upstream:
            run_cmd = run_cmd | 0b100

        self._write_reg(11, run_cmd)
        run_rs = self._read_reg(11)
        if run_rs != 0:
            print(f'Board Started with value={run_cmd:08X}')
        else:
            print(f'Board Not Started! Returned={run_cmd:08X}')

    def stop(self):
        self._write_reg(11, 0)
        run_rs = self._read_reg(11)
        if run_rs == 0:
            print('Board Stopped!')
        else:
            if run_rs is None:
                print(f'Board Error! Returned=None')
            else:
                print(f'Board Error! Returned={run_rs:08X}')

    def _write_reg(self, reg, value):
        return self._write_to_device(f'w{reg:08X}_{value:08X}')

    def _write_reg_raw(self, reg, raw_value):
        return self._write_to_device(f'w{reg:08X}_{raw_value}')

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
    print('tristan.py start-all <txports> <pktlen> <threshold> <nchannels> <nbpkts>')
    print('tristan.py start-hist <txports> <threshold> <nchannels> <nbpkts>')
    print('tristan.py start-upstream <txports> <pktlen> <threshold> <nbpkts>')
    print('tristan.py query <reg-number>')
    print('tristan.py stop')


if __name__ == '__main__':
    args = sys.argv
    if len(args) < 2:
        help()
        sys.exit()

    tristan = TristanBoard()
    cmd, tristan_args = args[1], args[2:]

    if cmd in ('start-all', 'start',) and len(tristan_args) == 5:
        tristan.stop()
        txport = tristan_args[0]
        pktlen = int(tristan_args[1])
        threshold = tristan_args[2]
        nchannels = int(tristan_args[3])
        npkts = int(tristan_args[4])
        tristan.setup(txport, threshold, npkts,
                      pktlen=pktlen, nchnls=nchannels)
        tristan.start()
    elif cmd == 'start-hist' and len(tristan_args) == 4:
        tristan.stop()
        txport = tristan_args[0]
        threshold = int(tristan_args[1])
        nchannels = int(tristan_args[2])
        npkts = int(tristan_args[3])
        tristan.setup(txport, threshold, npkts, nchnls=nchannels)
        tristan.start()
    elif cmd == 'start-upstream' and len(tristan_args) == 4:
        tristan.stop()
        txport = tristan_args[0]
        pktlen = int(tristan_args[1])
        threshold = int(tristan_args[2])
        npkts = int(tristan_args[3])
        tristan.setup(txport, threshold, npkts, pktlen=pktlen)
        tristan.start()
    elif cmd in ('query', 'q',) and len(tristan_args) == 1:
        regnu = int(tristan_args[0])
        print('Register', regnu, '=', tristan._read_reg(regnu))
    elif cmd == 'stop' and len(tristan_args) == 0:
        tristan.stop()
    else:
        help()
