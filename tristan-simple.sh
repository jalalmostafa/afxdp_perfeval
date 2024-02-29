#! /bin/bash
NIC=enp132s0np0
CHNLS=$1
THRSH=$2
TIME=$3

function usage()
{
    echo "Usage: $0 <channels-number> <trigger-threshold-hex> <approx-runtime>"
    echo "e.g. $0 10 000001 3"
    exit
}

if [[ "$CHNLS" == "" || "$THRSH" == "" || "$TIME" == "" ]]; then
    echo "Missing Arguments"
    usage
fi

if [[ "$EUID" != "0" ]]; then
    echo "Run this with sudo"
    exit
fi

function cleanup()
{
    echo "Cleaning up..."
    kill -s SIGINT `pidof dqdk`
    xdp-loader unload --all $NIC
}

function trap_sigintr()
{
    cleanup
    exit
}

# trapping the SIGINT signal
trap trap_sigintr SIGINT

DIR=`dirname $0`
TRISTAN_LOG=tristan.log
stdbuf -oL -eL ${DIR}/tristan-daq.sh $NIC histo > ${TRISTAN_LOG} 2>&1 &

echo "Waiting for DQDK to stabilize..."
while true; do
    LAST_LINE=`tail -n1 ${TRISTAN_LOG}`
    if [[ "${LAST_LINE:0:11}" == "[INFO] IRQ(" ]]; then
        break
    else
        sleep 1
    fi
done

sleep 2
echo "DQDK is now stable!"
NBPKTS=$((50000 * $TIME))
# echo "DQDK should receive $NBPKTS packets for an approx. duration of $TIME seconds (maybe a little bit more)"
python3 ${DIR}/tristan-scripts/tristan-hist.py start-all 5002-5003 3392 $THRSH $CHNLS $NBPKTS

echo "Doing DAQ..."
sleep $(($TIME + 1))

echo "Finished DAQ! Cleaning up and exit..."
cleanup

echo "Results:"
echo "Number of Received Packets:" $(grep "Received Packets" $TRISTAN_LOG | tail -1 | awk '{print $3}')
RCVD_HIST_EVTS=$(grep "TRISTAN Hist Events" $TRISTAN_LOG | tail -1 | awk '{print $4}')
echo "Number of Received Histogram Events: $RCVD_HIST_EVTS"
LOST_HIST_EVTS=$(grep "TRISTAN Hist Lost Events" $TRISTAN_LOG | tail -1 | awk '{print $5}')
echo "Number of Lost Histogram Events: $LOST_HIST_EVTS"
echo "Approximate Events per second: $(echo "($RCVD_HIST_EVTS - $LOST_HIST_EVTS) / $TIME" | bc)"
