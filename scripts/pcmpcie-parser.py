#! /bin/python3
import glob
import sys
import re


def file_parser(filename, socket=None):
    file = open(filename)
    lines = iter(file.readlines())
    samples = 0
    avg_readb, avg_writeb = 0, 0

    def sample_parser(l1, l2=None):
        readb1, writeb1 = l1.split(',')[6:]
        readb2, writeb2 = l2.split(',')[6:] if l2 is not None else (0, 0)
        return int(readb1) + int(readb2), int(writeb1) + int(writeb2)

    for line in lines:
        if 'Skt,' in line:
            continue

        if socket and not line.startswith(str(socket)):
            continue

        l2 = next(lines) if socket is None else None
        readb, writeb = sample_parser(line, l2=l2)
        if socket and readb == 0 and writeb == 0:
            continue
        samples += 1
        avg_readb += readb
        avg_writeb += writeb

    file.close()
    return (avg_readb / samples), (avg_writeb / samples)


def alphanumeric_sort(x):
    return ''.join([format(int(x), '05d') if x.isdigit()
                   else x for x in re.split(r'(\d+)', x)])


if __name__ == '__main__':
    pattern = sys.argv[1]
    socket = sys.argv[2] if len(sys.argv) == 3 else None
    files = glob.glob(pattern)
    print(len(files), 'files detected for', pattern)
    for file in sorted(files, key=alphanumeric_sort):
        readb, writeb = file_parser(file, socket=socket)
        print(file, ',', round(readb / 1e6, 2), ',', round(writeb / 1e6, 2),)
