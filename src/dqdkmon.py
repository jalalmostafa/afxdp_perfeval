#! /bin/python3

import signal
import sys
import subprocess
import pandas as pd
import datetime


def perf_stat(pid, kernel='/home/jalal/linux-6.0.5'):
    return subprocess.Popen([f'{kernel}/tools/perf/perf',
                             'stat', '-d', '-d', '-d', '-p', str(pid)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def pidstat():
    return subprocess.Popen(['/usr/bin/pidstat', '-h', '-H', '-G', 'dqdk|softirq', '-t', '1'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def parse_dqdk(out):
    pdata = {}
    lines = out.split('Average Stats:')[1].split('\n')
    for l in lines:
        if not l:
            continue
        key, value = l.strip().split(':')
        pdata[key.strip()] = [float(value.strip())]
    return pd.DataFrame(data=pdata)


def parse_perfstat(out):
    def _parse_s1(s1):
        s1data = s1.split()
        if '<not counted>' in s1:
            _, _, key, _ = s1data
            return key, '<not counted>'
        elif '<not supported>' in s1:
            _, _, key = s1data
            return key, '<not supported>'
        elif len(s1data) == 2:
            value, key = s1data
            return key, value.replace(',', '')
        elif len(s1data) == 3:
            value, unit, key = s1data
            return key, value.replace(',', '') + unit
        else:
            raise Exception(f'Not Handled: {s1}')
    lines = out.split('\n')
    pdata = {}
    for l in lines:
        if not l or 'Performance counter stats' in l or 'seconds time elapsed' in l \
                or 'seconds user' in l or 'seconds sys' in l:
            continue
        brokenl = l.split('#')
        s1 = brokenl[0].strip()
        if s1:
            k, v = _parse_s1(s1)
            pdata[k] = [v]
    return pd.DataFrame(data=pdata)


def parse_pidstat(out):
    lines = out.split('\n')
    keys = None
    pdata = {}
    for l in lines:
        if not l or 'Linux' in l or 'Average' in l:
            continue
        
        if 'Time' in l:
            if len(pdata) == 0:
                keys = l.split()[1:]
                pdata = {k: [] for k in keys}
            continue

        if 'softirq' in l:
            if '|__' in l:
                continue

            values = l.split()
            for i, v in enumerate(values):
                k = keys[i]
                pdata[k].append(v)
        elif 'dqdk' in l:
            values = l.split()
            for i, v in enumerate(values):
                k = keys[i]
                if k == 'Command':
                    v = v if '|__' not in v else '%s-%s' % (
                        v.replace('|__', ''), values[3])

                pdata[k].append(v)
        else:
            raise Exception(f'Not handled: {l}')

    return pd.DataFrame(data=pdata)


def merge_dqdk_perf(dqdk, perf):
    return pd.concat([dqdk, perf], axis=1)


def parse_all(dqdk_out, perf_out, pidstat_out):
    dqdk_df = parse_dqdk(dqdk_out.decode('ascii'))
    perf_df = parse_perfstat(perf_out.decode('ascii'))
    pidstat_df = parse_pidstat(pidstat_out.decode('ascii'))

    ts = datetime.datetime.now()
    df = merge_dqdk_perf(dqdk_df, perf_df)
    dqdkperf_file = f'./dqdk-perf-{ts}.csv'
    df.to_csv(dqdkperf_file)
    pidstat_file = f'./dqdk-pidstat-{ts}.csv'
    pidstat_df.to_csv(pidstat_file)


if __name__ == '__main__':
    dqdk = subprocess.Popen(['./dqdk', ] + sys.argv[1:],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    perf = perf_stat(dqdk.pid)
    pstat = pidstat()

    dqdk.wait()
    pstat.send_signal(signal.SIGTERM)
    perf.wait()

    (dqdk_stdout, dqdk_stderr) = dqdk.communicate()
    (perf_stdout, perf_stderr) = perf.communicate()
    (pstat_stdout, pstat_stderr) = pstat.communicate()

    parse_all(dqdk_stdout, perf_stderr, pstat_stdout)
