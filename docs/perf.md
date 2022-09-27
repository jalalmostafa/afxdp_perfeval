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
| sudo ./dqdk -B txonly -i enp2s0np0 -q 4-7 -w -b 64 -s 4 -p rtc                 |        +- (under bug) |
| sudo ./dqdk -B txonly -i enp2s0np0 -q 4-7 -w -b 64 -s 4 -p rtc -a 57,58,59,60  |        +- (under bug) |
| sudo ./dqdk -B txonly -i enp2s0np0 -q 4-7 -w -b 64 -s 4 -p rtc                 | 58.08M +- (fixed bug) |
| sudo ./dqdk -B txonly -i enp2s0np0 -q 4-7 -w -b 64 -s 4 -p rtc -a 57,58,59,60  | 59.25M +- (fixed bug) |

## L2FWD - 64Byte

| DQDK Command                                                                   | Frames per sec        |
| ------------------------------------------------------------------------------ | --------------------- |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4 -w -b 2048 -p rtc                       |  9.25M +-             |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4 -w -b 2048 -s 4                         |  6.41M +-             |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4-7 -w -b 2048                            |  9.95M +-             |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4-7 -w -b 2048 -p rtc                     | 21.36M +-             |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4-7 -w -b 2048 -p rtc -a 57,58,59,60      | 21.35M +-             |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4-7 -w -b 2048 -s 4                       |        +- (under bug) |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4-7 -w -b 2048 -s 4 -p rtc                |        +- (under bug) |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4-7 -w -b 2048 -s 4 -p rtc -a 57,58,59,60 |        +- (under bug) |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4-7 -w -b 2048 -s 4                       |  9.84M +- (fixed bug) |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4-7 -w -b 2048 -s 4 -p rtc                | 19.42M +- (fixed bug) |
| sudo ./dqdk -B l2fwd -i enp2s0np0 -q 4-7 -w -b 2048 -s 4 -p rtc -a 57,58,59,60 | 21.44M +- (fixed bug) |

## UDP

| DQDK Command                                                            | Frames per sec |
| ----------------------------------------------------------------------- | -------------- |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100 -p rtc -a 58,59,60,61 | 20.23M         |
| sudo ./dqdk -i enp2s0np0 -q 4-7 -w -b 2048 -d 100                       |  7.07M         |
