#! /bin/python3
import locale

if __name__ == '__main__':
    locale.setlocale(locale.LC_ALL, 'en_US.utf8')
    f = open('./ethtool.log')
    lines = f.readlines()[2:]
    esum = 0
    linenbs = []
    for idx, line in enumerate(lines):
        if line.startswith('PPS'):
            continue

        ldata = int(line.split('|')[2].strip())
        if ldata != 0:
            esum += ldata
            linenbs.append((idx + 1))

    print('Out-of-Buffer:', locale.format_string("%d", esum, grouping=True))
    print('Number of Incidents:', len(linenbs))
    print('Line Numbers:', ','.join(map(str, linenbs)))
    print('First OOB after:', 'NA' if len(linenbs) == 0 else str(int(linenbs[0] / 2)), 'seconds')
