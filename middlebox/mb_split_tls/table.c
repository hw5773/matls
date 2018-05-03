#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "table.h"
#include "../common/logs.h"

int init_forward_table(unsigned char *filename)
{
  FILE *fp = fopen(filename, "r");
  unsigned char name[MAX_NAME_LENGTH], ip[INET_ADDRSTRLEN];
  int port;

  table = (struct forward_table *)malloc(sizeof(struct forward_table));
  table->num_of_entries = 0;

  while (!feof(fp))
  {
    fscanf(fp, "%s %s %d\n", name, ip, &port);
    printf("%s (%lu), %s (%lu), %d\n", name, strlen(name), ip, strlen(ip), port);
    if (insert_entry(name, (int) strlen(name), ip, (int) strlen(ip), port) < 0) goto err;
  }

  return 1;
err:
  MA_LOG("Error happended in initializing the forward table"); 
  return -1;
}

int insert_entry(unsigned char *name, int nlen, unsigned char *ip, int ilen, int port)
{
  int index = table->num_of_entries;
  table->forward_names[index] = (unsigned char *)malloc(nlen);
  table->forward_ips[index] = (unsigned char *)malloc(ilen);

  memcpy(table->forward_names[index], name, nlen);
  memcpy(table->forward_ips[index], ip, ilen);
  table->name_lengths[index] = nlen;
  table->ip_lengths[index] = ilen;
  table->forward_ports[index] = port;

  table->num_of_entries += 1;
}

int find_by_name(unsigned char *buf, int len)
{
  int i, ret = -1;

  for (i=0; i<table->num_of_entries-1; i++)
  {
    if (!strncmp(buf, table->forward_names[i], len))
      ret = i;
  }

  return ret;
}

unsigned char *get_ip_by_index(int index, int *len)
{
  *len = table->ip_lengths[index];
  return table->forward_ips[index];
}

int get_port_by_index(int index)
{
  return table->forward_ports[index];
}

void free_forward_table(void)
{
  int i, last = table->num_of_entries;
  for (i=0; i<last; i++)
  {
    free(table->forward_names[i]);
    free(table->forward_ips[i]);
  }

  free(table);
}
