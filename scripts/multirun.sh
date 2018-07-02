#!/bin/bash
#rm -f /home/mmlab/client_log_accum.txt
touch /home/mmlab/client_log.txt

#for i in {1..100}
URL=$1
PORT=$2
ADDR=${URL}:${PORT}
NUM=$3
LOG_FILE=output_${NUM}.log
DIRECTORY=/home/mmlab/log/mb_${NUM}_read

[ -d ${DIRECTORY} ] || mkdir ${DIRECTORY}

FILE=${DIRECTORY}/mb_${NUM}_read.csv
touch ${FILE}

#for i in {1..100}
for i in {1..100}
do
   echo ${i}:${FILE}
   ~/chromium/src/out/Client/chrome --headless ${ADDR} --dump-dom >> /home/mmlab/log/${LOG_FILE}
   cat /home/mmlab/client_log.txt >> ${FILE}
done
echo 'done'
rm -f /home/mmlab/client_log.txt
