#! /bin/bash
NIC=$1
Q=1
if [ "$NIC" == "" ]; then
    echo "NIC Name is not specified"
    echo "$0 <NIC>"
    exit
fi

source scripts/mlx5-optimize.sh $NIC $Q

INTR_STRING=$(cat /proc/interrupts | grep mlx5 | head -${Q} | awk '{printf "%s%s", sep, substr($1, 1, length($1)-1); sep=","} END{print ""}')
if [ $Q -eq 1 ]; then
    Q_STRING=0
else
    Q_STRING=0-$(($Q - 1))
fi
pushd src
CMD="./dqdk -i $NIC -q $Q_STRING -b 2048 -A $INTR_STRING -G -B"
echo "Executing DQDK Command is: $CMD"

$CMD

popd
