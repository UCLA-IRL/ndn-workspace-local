#!/bin/bash --posix
# nfdc strategy set / /localhost/nfd/strategy/multicast
i=0
while [ $i -ne 10 ]
do
    i=$(($i+1))
    export NODE_ID=$i
    deno task sync_test &
    sleep 1
done
