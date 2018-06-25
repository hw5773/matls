#include "internal.h"

namespace bssl {

FILE *fp;
char *filename;
unsigned long log_time[10000];
int log_type[10000];
char *log_tag[10000];
int i=0;

int LOGGING = 1;
int WRITE_TO_STDOUT = 0;

int log_init(const char *filen){

  if (!LOGGING) return 1;

  filename = (char *)filen;

  fp = fopen(filename, "w");
  if (WRITE_TO_STDOUT) fp = stdout;

  if(fp == NULL)
    printf("Cannot open file\n");

  return 1;

}
void write_to_file(){

  if (!LOGGING) return;
  if (fp == NULL) return;

  for(int j=0; j<i; j++){
    fprintf(fp, "%lu, %d, %s\n", log_time[j], log_type[j], log_tag[j]);
  }
}
unsigned long getMicroSecond(){

  if (!LOGGING) return 1;

  struct timeval tv;
  gettimeofday(&tv, NULL);
  return 1000000*(tv.tv_sec) + tv.tv_usec;
}
void insertLog(int var, const char* tag){

  if (!LOGGING) return;

  log_time[i] = getMicroSecond();
  log_type[i] = var;
  log_tag[i] = (char *)tag;
  i++;
}

void log_close(){

  if (!LOGGING) return;
  if (WRITE_TO_STDOUT) return;
  if (fp == NULL) return;

  fclose(fp);
  fp = NULL;
}

} // namespace bssl

void insertLogChromium(int var, const char* tag){
  bssl::insertLog(var, tag);
}

