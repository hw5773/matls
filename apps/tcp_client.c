#include "logger.h"
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
#include <pthread.h>
#include "logs.h"

#define FAIL    -1
#define BUF_SIZE 1024

void *run(void *data);
int open_connection(const char *hostname, int port);
const char *hostname, *portnum;
log_t time_log[20];

// Client Prototype Implementation
int main(int count, char *strings[])
{   
  if ( count != 5 )
  {
    printf("usage: %s <hostname> <portnum> <num of threads> <log file>\n", strings[0]);
    exit(0);
  }

	int i, rc, num_of_threads;
	const char *fname = strings[4];

	num_of_threads = atoi(strings[3]);

	pthread_t thread[num_of_threads];
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	void *status;

  hostname = strings[1];
  portnum = strings[2];

	INITIALIZE_LOG(time_log);

	unsigned long start, end;

	start = get_current_microseconds();
	for (i=0; i<num_of_threads; i++)
	{
		rc = pthread_create(&thread[i], &attr, run, NULL);

		if (rc)
		{
			printf("ERROR: return code from pthread_create: %d\n", rc);
			return 1;
		}
	}

	pthread_attr_destroy(&attr);

	for (i=0; i<num_of_threads; i++)
	{
		rc = pthread_join(thread[i], &status);

		if (rc)
		{
			printf("ERROR: return code from pthread_join: %d\n", rc);
			return 1;
		}
	}
	end = get_current_microseconds();

	printf("TOTAL TIME: %lu us\n", end - start);

	FINALIZE(time_log, fname);    

  return 0;
}

void *run(void *data)
{	
	int server, sent, rcvd;
  unsigned char buf[BUF_SIZE];
  const char *request = 
    "GET / HTTP/1.1\r\n"
    "Host: www.matls.com\r\n\r\n";
  int request_len = strlen(request);

	server = open_connection(hostname, atoi(portnum));

  struct timeval tv;
  gettimeofday( &tv, 0 );

	unsigned long hs_start, hs_end;
  
  RECORD_LOG(time_log, CLIENT_FETCH_HTML_START);
  sent = write(server, request, request_len);
  MA_LOG1s("Request", request);
  rcvd = read(server, buf, BUF_SIZE);
  RECORD_LOG(time_log, CLIENT_FETCH_HTML_END);
  INTERVAL(time_log, CLIENT_FETCH_HTML_START, CLIENT_FETCH_HTML_END);
	buf[rcvd] = 0;
  MA_LOG1s("Response", buf);
  MA_LOG1d("Rcvd Length", rcvd);
        
	close(server);         /* close socket */
}

int open_connection(const char *hostname, int port)
{   
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;
            
  if ( (host = gethostbyname(hostname)) == NULL )
  {
    perror(hostname);
    abort();
  }
    
  sd = socket(PF_INET, SOCK_STREAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  RECORD_LOG(time_log, CLIENT_TCP_CONNECT_START);    
  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
  {
    close(sd);
    perror(hostname);
    abort();
  }
  RECORD_LOG(time_log, CLIENT_TCP_CONNECT_END);
  INTERVAL(time_log, CLIENT_TCP_CONNECT_START, CLIENT_TCP_CONNECT_END);
         
  return sd;
}

