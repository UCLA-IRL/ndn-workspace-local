#!/bin/bash --posix
# nfdc strategy set / /localhost/nfd/strategy/multicast
hosts=("suns.cs.ucla.edu" "wundngw.wustl.edu" "neu.testbed.named-data.net" "titan.cs.memphis.edu" "hobo.cs.arizona.edu")
i=0
while [ $i -ne 1 ]
do
    i=$(($i+1))
    j=0
    while [ $j -ne 5 ]
    do
        export NODE_ID=$(($i*5+$j-5))
        export HOST=${hosts[$j]}
        echo $NODE_ID
        echo $HOST
        deno task sync_test &
        j=$(($j+1))
    done
    sleep 1
done
