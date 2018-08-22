#!/usr/bin/env bash

parties=()
while IFS= read -r line || [[ -n "${line}" ]]; do
    l=`echo ${line} | cut -d'=' -f2`
    parties+=(${l})
done < parties.conf

idx=${parties[${1}]}

cd ../build/bin
./innerproduct_test -r ${1} -a ${idx} -p 8000