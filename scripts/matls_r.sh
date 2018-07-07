#!/bin/bash
#rm -f /home/mmlab/client_log_accum.txt

#for i in {1..100}
URL=$1
PORT=$2
ADDR=${URL}:${PORT}
NUM=$3
DIRECTORY=/home/dist/log/mb_${NUM}_read
LOG_FILE=${DIRECTORY}/mb_${NUM}_read.csv

[ -d ${DIRECTORY} ] || mkdir ${DIRECTORY}

FILE=${DIRECTORY}/mb_${NUM}_read.csv
touch ${FILE}

#for i in {1..100}
cd /home/dist/matls/apps
for i in {1..100}
do
   echo ${i}:${FILE}
   make cstart PORT=${PORT} LOG_FILE=${LOG_FILE}
done
echo 'done'
