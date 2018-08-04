#!/bin/bash
CLIENT=/home/hwlee/mctls/evaluation/client_server/wclient
NATION=$1

cd /home/hwlee/mctls/evaluation/client_server
for j in {1..100} #trial number
do
  echo 'mb'${NATION}
  ${CLIENT} -c spp -s 1 -r 1 -w 0 -f index.html -o 3 -a -b 100 -l /home/hwlee/log/mb_${NATION}_mctls/mb_${NATION}_mctls.csv
  sleep 0.5
done


