#!/bin/bash
#rm -f /home/mmlab/client_log_accum.txt

#for i in {1..100}
URL=$1
PORT=$2
ADDR=${URL}:${PORT}
NUM=$3
DIRECTORY=/home/hwlee/log/mb_${NUM}_write
LOG_FILE=${DIRECTORY}/mb_${NUM}_write.csv

[ -d ${DIRECTORY} ] || mkdir ${DIRECTORY}

#for i in {1..100}
cd /home/hwlee/matls/apps
for i in {1..100}
do
   echo ${i}:${FILE}
   make cstart HOST=${URL} PORT=${PORT} LOG_FILE=${LOG_FILE}
   sleep 1
done
echo 'done'
