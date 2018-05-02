/**
 * @file common.c
 * @author Hyunwoo Lee
 * @date May 1 2018
 * @brief The function implementations
 */

#include "common.h"

int open_connection(const char *hostname, int port)
{   int sd;
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
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
         close(sd);
         perror(hostname);
         abort();
    }
         return sd;
}

