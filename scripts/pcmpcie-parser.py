#! /bin/python3
import glob
import sys


def file_parser(filename):
    file = open(filename)
    lines = iter(file.readlines())
    samples = 0
    avg_readb, avg_writeb = 0, 0

    def sample_parser(l1, l2):
        readb1, writeb1 = l1.split(',')[6:]
        readb2, writeb2 = l2.split(',')[6:]
        return int(readb1) + int(readb2), int(writeb1) + int(writeb2)

    for line in lines:
        if 'Skt,' in line:
            continue

        readb, writeb = sample_parser(line, next(lines))
        samples += 1
        avg_readb += readb
        avg_writeb += writeb

    return (avg_readb / samples), (avg_writeb / samples)


if __name__ == '__main__':
    pattern = sys.argv[1]
    files = glob.glob(pattern)
    print(len(files), 'files detected for', pattern)
    for file in sorted(files, key=len):
        readb, writeb = file_parser(file)
        print(file, 'Avg. Read PCIe Bandwidth (MB/s):', round(readb / 1e6, 2),
              'Avg. Write PCIe Bandwidth (MB/s):', round(writeb / 1e6, 2))
