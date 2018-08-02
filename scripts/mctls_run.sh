#!/bin/bash
SERVER=/home/dist/openssl-mctls/evaluation/client_server/wserver
MBOX=/home/dist/openssl-mctls/evaluation/client_server/mbox
CLIENT=/home/dist/openssl-mctls/evaluation/client_server/wclient

p_arr=(4433 8422 8423 8424 8425 8426 8427 8428 8429 8430 8431 8432 8433 8434 8435 8436 8437)

${SERVER} -c ssl -o 3 -s uni &
${MBOX} -c ssl -a localhost:${p_arr[0]} -p ${p_arr[1]} -m localhost:${p_arr[1]} &
${MBOX} -c ssl -a localhost:${p_arr[1]} -p ${p_arr[2]} -m localhost:${p_arr[2]} &
${MBOX} -c ssl -a localhost:${p_arr[2]} -p ${p_arr[3]} -m localhost:${p_arr[3]} &
${MBOX} -c ssl -a localhost:${p_arr[3]} -p ${p_arr[4]} -m localhost:${p_arr[4]} &
${MBOX} -c ssl -a localhost:${p_arr[4]} -p ${p_arr[5]} -m localhost:${p_arr[5]} &
${MBOX} -c ssl -a localhost:${p_arr[5]} -p ${p_arr[6]} -m localhost:${p_arr[6]} &
${MBOX} -c ssl -a localhost:${p_arr[6]} -p ${p_arr[7]} -m localhost:${p_arr[7]} &
${MBOX} -c ssl -a localhost:${p_arr[7]} -p ${p_arr[8]} -m localhost:${p_arr[8]} &
${MBOX} -c ssl -a localhost:${p_arr[8]} -p ${p_arr[9]} -m localhost:${p_arr[9]} &
${MBOX} -c ssl -a localhost:${p_arr[9]} -p ${p_arr[10]} -m localhost:${p_arr[10]} &
${MBOX} -c ssl -a localhost:${p_arr[10]} -p ${p_arr[11]} -m localhost:${p_arr[11]} &
${MBOX} -c ssl -a localhost:${p_arr[11]} -p ${p_arr[12]} -m localhost:${p_arr[12]} &
${MBOX} -c ssl -a localhost:${p_arr[12]} -p ${p_arr[13]} -m localhost:${p_arr[13]} &
${MBOX} -c ssl -a localhost:${p_arr[13]} -p ${p_arr[14]} -m localhost:${p_arr[14]} &
${MBOX} -c ssl -a localhost:${p_arr[14]} -p ${p_arr[15]} -m localhost:${p_arr[15]} &
${MBOX} -c ssl -a localhost:${p_arr[15]} -p ${p_arr[16]} -m localhost:${p_arr[16]} &
rm -rf a.txt b.txt proxyList

for i in {1..17}
do
  echo $i > a.txt
  echo localhost:${p_arr[($i-1)]} >> a.txt
  tail -n +2 proxyList > b.txt
  cat a.txt b.txt > proxyList

  for j in {1..100} #trial number
  do
    echo 'mb'$i
    mkdir -p /home/dist/data/mctls/csv_data/mb_${i}_mctls
    ${CLIENT} -s 1 -r i -w 0 -f index.html -o 3 -a -c ssl -b 100 -l /home/dist/data/mctls/csv_data/mb_${i}_mctls/mb_${i}_mctls.csv
  done
done

pkill mbox
pkill wserver

