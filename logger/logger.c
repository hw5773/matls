#include "logger.h"

FILE *fp;
char *filename;
unsigned long log_time[10000];
int log_type[10000];
char *log_tag[10000];
int i=0;

int log_init(char *filen){

	filename = filen;

	fp = fopen(filename, "w");

	if(fp == NULL)
		printf("Cannot open file\n");

	return 1;

}
void write_to_file(){

	for(int j=0; j<i; j++){
		fprintf(fp, "%lu, %d, %s\n", log_time[j], log_type[j], log_tag[j]);
	}
}
unsigned long getMicroSecond(){

	struct timeval tv;
	gettimeofday(&tv, NULL);
	return 1000000*(tv.tv_sec) + tv.tv_usec;
}
void insertLog(int var, char *tag){

	log_time[i] = getMicroSecond();
	log_type[i] = var;
	log_tag[i] = tag;
	i++;
}

