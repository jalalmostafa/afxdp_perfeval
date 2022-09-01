#! /bin/bash

if [[ "$1" != "" ]]; then
    NIC=$1
else
    echo "Please provide the network interface you'd like to monitor."
    echo "example: $0 eth0"
    exit 1
fi

combined=`ethtool -l $1 | tail -1 | awk '{print $2}'`

case $combined in
    1)
    ethtool -N $1 flow-type ip4 action 1
    ;;

    2)
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.1 action 2
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.2 action 2
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.3 action 3
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.4 action 3
    ;;

    3)
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.1 action 3
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.2 action 4
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.3 action 5
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.4 action 3
    ;;

    4)
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.1 action 4
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.2 action 5
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.3 action 6
    ethtool -N $1 flow-type ip4 src-ip 192.168.10.4 action 7
    ;;
esac
