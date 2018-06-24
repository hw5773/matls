#!/bin/bash
#rm -f /home/kjchoi/client_log_accum.txt
touch /home/kjchoi/client_log.txt

#for i in {1..100}
URL=$1
PORT=$2
ADDR=${URL}:${PORT}
NUM=$3
LOG_FILE=output_${NUM}.log
DIRECTORY=/home/kjchoi/log/mb_${NUM}_write

[ -d ${DIRECTORY} ] || mkdir ${DIRECTORY}

FILE=${DIRECTORY}/mb_${NUM}_write.csv
touch ${FILE}

#for i in {1..100}
for i in {1..100}
do
   echo ${i}:${FILE}
   ~/chromium/src/out/Client/chrome --headless ${ADDR} --dump-dom >> /home/kjchoi/log/${LOG_FILE}
   cat /home/kjchoi/client_log.txt >> ${FILE}
done
echo 'done'
rm -f /home/kjchoi/client_log.txt
