# Performance Measures

## RX_DROP - 64Byte

| DQDK Command                                                                 | Frames per sec        |
| ---------------------------------------------------------------------------- | --------------------- |
| sudo ./dqdk -i enp2s0np0 -q 4 -w -b 2048 -p rtc                              | 14.22M +-             |
| sudo ./dqdk -i enp2s0np0 -q 4 -w -b 2048 -s 4                                | 11.87M +-             |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100                            | 38.01M +-             |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100 -p rtc                     | 45.42M +-             |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100 -p rtc -a 57,58,59,60      | 47.29M +-             |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100 -s 4                       | 27.40M +- (under bug) |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100 -s 4 -p rtc                | 15.15M +- (under bug) |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100 -s 4 -p rtc -a 57,58,59,60 | 11.58M +- (under bug) |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100 -s 4                       | 38.23M +- (fixed bug) |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100 -s 4 -p rtc                | 44.39M +- (fixed bug) |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100 -s 4 -p rtc -a 57,58,59,60 | 46.46M +- (fixed bug) |

## TX_ONLY - 64Byte

| DQDK Command                                                                   | Frames per sec        |
| ------------------------------------------------------------------------------ | --------------------- |
| sudo ./dqdk -B txonly -i enp2s0np0 -q 4 -w -b 64 -p rtc                        | 22.84M +-             |
| sudo ./dqdk -B txonly -i enp2s0np0 -q 4-7 -w -b 64 -p rtc                      | 58.35M +-             |
| sudo ./dqdk -B txonly -i enp2s0np0 -q 4-7 -w -b 64 -p rtc -a 57,58,59,60       | 59.03M +-             |
| sudo ./dqdk -i enp2s0np0 -B txonly -q 4-7 -w -b 64 -s 4 -p rtc                 |        +- (under bug) |
| sudo ./dqdk -i enp2s0np0 -B txonly -q 4-7 -w -b 64 -s 4 -p rtc -a 57,58,59,60  |        +- (under bug) |
| sudo ./dqdk -i enp2s0np0 -B txonly -q 4-7 -w -b 64 -s 4 -p rtc                 | 58.08M +- (fixed bug) |
| sudo ./dqdk -i enp2s0np0 -B txonly -q 4-7 -w -b 64 -s 4 -p rtc -a 57,58,59,60  | 59.25M +- (fixed bug) |

## UDP

| DQDK Command                                                            | Frames per sec |
| ----------------------------------------------------------------------- | -------------- |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100 -p rtc -a 58,59,60,61 | 20.23M         |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100                       |  7.07M         |
