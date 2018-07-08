#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include "table.h"
#include "logger.h"
#include "logs.h"
#include "common.h"

#define FAIL    -1
#define BUF_SIZE 1024
#define MAX_CLNT_SIZE 1000
#define MAX_THREADS 100

int open_listener(int port);
void *mb_run(void *data);
int get_total_length(char *buf, int rcvd);
int get_thread_index(void);
int connect_to_server_side(char *buf, int *server);

int modification;
pthread_t threads[MAX_THREADS];

struct info
{
  int sock;
};

// Origin Server Implementation
int main(int count, char *strings[])
{  
	int server, client, rc, tidx = 0, i, server_side;
	char *portnum, *forward_file;
  void *status;
  pthread_attr_t attr;

	if ( count != 4 )
	{
		printf("Usage: %s <portnum> <forward_file> <modification>\n", strings[0]);
		exit(0);
	}

	portnum = strings[1];
  forward_file = strings[2];
  modification = atoi(strings[3]);

  init_forward_table(forward_file);
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	while (1)
	{
    client = accept(server, (struct sockaddr *)&addr, &len);

    if (client < 0)
    {
      MA_LOG("error in accept");
      exit(EXIT_FAILURE);
    }

    struct info *info = (struct info *)malloc(sizeof(struct info));
    info->sock = client;
    /////
    tidx = get_thread_index();
    MA_LOG1d("Create thread with index", tidx);
    /////
    rc = pthread_create(&threads[tidx], &attr, mb_run, info);

    if (rc < 0)
    {
      MA_LOG("error in pthread create");
      exit(EXIT_FAILURE);
    }

    pthread_attr_destroy(&attr);

    rc = pthread_join(threads[tidx], &status);

    if (rc)
    {
      MA_LOG1d("error in join", rc);
      return 1;
    }
    close(client);
	}

  free_forward_table();
	close(server);          /* close server socket */

	return 0;
}

void *mb_run(void *data)
{
  MA_LOG("start server loop\n");
  struct info *info;
  int client, server, ret, rcvd, sent, fd, tot_len = -1, head_len = -1, body_len = -1;
  unsigned char buf[BUF_SIZE];
  unsigned long start, end;

  char modified[134] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 70\r\n"
    "\r\n"
    "<html><title>Test</title><body><h1>Test Bob's Page!</h1></body></html>";
  int modified_len = strlen(modified);

  info = (struct info *)data;
  client = info->sock;
  start = get_current_microseconds();

  rcvd = read(client, buf, BUF_SIZE);
  connect_to_server_side(buf, &server);

  MA_LOG1d("Received from Client-side", rcvd);
  MA_LOG1s("Message from Client-side", buf);

  sent = write(server, buf, rcvd);
  MA_LOG1d("Sent to Server-side", sent);

  do {
    rcvd = read(server, buf, BUF_SIZE);
    MA_LOG1d("Received from Server-side", rcvd);
    MA_LOG1s("Message", buf);
      
    if (modification)
      sent = write(client, modified, modified_len);
    else
      sent = write(client, buf, rcvd);

    MA_LOG1d("Sent to Client-side", sent);

    if (tot_len < 0)
    {
      if (modification)
        tot_len = get_total_length((char *)modified, modified_len);
      else
        tot_len = get_total_length(buf, rcvd);
    }

    MA_LOG1d("Total Length", tot_len);
    tot_len -= rcvd;

    if (tot_len <= 0)
      break;
  } while(1);

  end = get_current_microseconds();
  MA_LOG1lu("Middlebox Execution Time", end - start);
  close(server);
}

int connect_to_server_side(char *buf, int *server)
{
  unsigned char *tok1, *tok2, hostname[256], *ip;
  int index, port;

  tok1 = strstr(buf, "Host:");
  tok1 += 6;
  tok2 = strstr(tok1, "\r\n\r\n");
  memcpy(hostname, tok1, tok2 - tok1);
  hostname[tok2-tok1] = 0;

  index = find_by_name(hostname, strlen(hostname));
  ip = get_ip_by_index(index);
  port = get_port_by_index(index);

  *server = open_connection(ip, port);

  return 1;
}

int get_total_length(char *buf, int rcvd)
{
  int tot_len, head_len, body_len, index, tok_len, mrlen, len;
  const char *clen = "Content-Length";
  char *token = NULL;
  char val[4];

  head_len = strstr(buf, "\r\n\r\n") - buf + 4;
  MA_LOG1d("Header Length", head_len);
  
  token = strtok(buf, "\n");

  while (token)
  {
    tok_len = strlen(token);
    index = strstr(token, ":") - token;

    if (strncmp(token, clen, index - 1) == 0)
    {
      memcpy(val, token + index + 1, tok_len - index - 1);
      body_len = atoi(val);
      MA_LOG1d("Body Length", body_len);
      break;
    }

    token = strtok(NULL, "\n");
  }

  tot_len = head_len + body_len;

  return tot_len;
}

int open_listener(int port)
{   int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);

  /////
  //int flag = 1;
  //setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
  /////
	
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, MAX_CLNT_SIZE) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

int get_thread_index(void)
{
  int i, ret = -1;

  for (i=0; i<MAX_THREADS; i++)
    if (!threads[i])
    {
      ret = i;
      break;
    }

  return ret;
}
