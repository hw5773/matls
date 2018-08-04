#!/bin/bash
#rm -f /home/mmlab/client_log_accum.txt

#for i in {1..100}
URL=$1
PORT=$2
ADDR=${URL}:${PORT}
NATION=$3
DIRECTORY=/home/hwlee/log/mb_${NATION}_read
LOG_FILE=${DIRECTORY}/mb_${NATION}_read.csv

[ -d ${DIRECTORY} ] || mkdir ${DIRECTORY}

FILE=${DIRECTORY}/mb_${NATION}_read.csv
touch ${FILE}

cd /home/hwlee/matls/apps

for i in {1..100}
do
   echo ${i}:${FILE}
   make cstart HOST=${URL} PORT=${PORT} LOG_FILE=${LOG_FILE}
   sleep 0.5
done
echo 'done'
