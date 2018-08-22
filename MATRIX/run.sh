#!/usr/bin/env bash

parties=()
while IFS= read -r line || [[ -n "${line}" ]]; do
    l=`echo ${line} | cut -d'=' -f2`
    parties+=(${l})
done < parties.conf

idx= ${1}
addr=${parties[0]}

cd ../build/bin
./innerproduct_test -r ${idx} -a ${addr}