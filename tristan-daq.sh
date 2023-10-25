#! /bin/bash
NIC=$1
Q=2
if [ "$NIC" == "" ]; then
    echo "NIC Name is not specified"
    echo "$0 <NIC>"
    exit
fi

shift

source scripts/mlx5-optimize.sh $NIC $Q
ethtool -N $NIC rx-flow-hash udp4 fn


INTR_STRING=$(cat /proc/interrupts | grep mlx5 | head -${Q} | awk '{printf "%s%s", sep, substr($1, 1, length($1)-1); sep=","} END{print ""}')
if [ $Q -eq 1 ]; then
    Q_STRING=0
else
    Q_STRING=0-$(($Q - 1))
fi

# echo "python3 ./tristan-scripts/tristan-board.py setupx $*"
# python3 ./tristan-scripts/tristan-board.py setupx $*
scripts/mlx5-rx-dbg.sh enp2s0np0 | tee log.log &

pushd src
CMD="./dqdk -i $NIC -q 0 -b 2048 -A 57 -G -B"
echo "Executing DQDK Command is: $CMD"

$CMD
popd

pkill mlx5-rx-dbg.sh
