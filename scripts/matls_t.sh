#!/bin/bash
#rm -f /home/mmlab/client_log_accum.txt

#for i in {1..100}
URL=$1
PORT=$2
ADDR=${URL}:${PORT}
NUM=$3
DIRECTORY=/home/dist/data/tcp/csv_data/mb_${NUM}_tcp
LOG_FILE=${DIRECTORY}/mb_${NUM}_tcp.csv

[ -d ${DIRECTORY} ] || mkdir ${DIRECTORY}

#for i in {1..100}
cd /home/dist/matls/apps
for i in {1..100}
do
   echo ${i}:${FILE}
   make ctcp PORT=${PORT} LOG_FILE=${LOG_FILE}
   sleep 1.5
done
echo 'done'
