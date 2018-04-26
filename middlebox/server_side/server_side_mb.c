/**
 * @file server_side_mb.c
 * @author Hyunwoo Lee
 * @date 25 Apr 2018
 * @brief The server side middlebox application
 */

#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "server_side_mb.h"

#define PORT    5678
#define CERTIFICATE "  alice_ecc.crt"
#define PRIVKEY "alice_ecc.key"
#define CACERT  "/etc/ssl/certs"

int main(int argc, char *argv[])
{
  int port, i, n;
  int client_side_sock, server_side_sock, fd, maxi;
  int nready, revents;
  struct sockaddr_in serv_addr, peer_addr;
  struct pollfd client[MAX_CLNT_SIDE];
  struct client_info info[MAX_CLNT_SIDE];
  socklen_t peer_addr_len;
  char *cert, *priv, *capath;
  char buf[DEFAULT_BUF_SIZE];

  if (argc == 1)
  {
    port = PORT;
    cert = CERTIFICATE;
    priv = PRIVKEY;
    capath = capath;
  }
  else if (argc == 5)
  {
    port = atoi(argv[1]);
    cert = argv[2];
    priv = argv[3];
    capath = argv[4];
  }
  else
  {
    printf("Usage: ./server_side_mb <port> <server cert file> <private key file> <CA cert path>");
    exit(EXIT_FAILURE);
  }

  client_side_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (client_side_sock < 0)
  {
    perror("socket generation failed\n");
    exit(EXIT_FAILURE);
  }

  int enable = 1;
  if (setsockopt(client_side_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
  {
    perror("setsockopt(SO_REUSEADDR) failed\n");
    exit(EXIT_FAILURE);
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(port);

  if (bind(client_side_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    perror("bind error");
    exit(EXIT_FAILURE);
  }

  if (listen(client_side_sock, MAX_CLNT_SIDE) < 0)
  {
    perror("listen error");
    exit(EXIT_FAILURE);
  }

  peer_addr_len = sizeof(peer_addr);
  client[0].fd = client_side_sock;
  client[0].events = POLLIN;

  for (i=1; i<MAX_CLNT_SIDE; i++)
  {
    client[i].fd = -1;
  }
  maxi = 0;

  if (ssl_init(cert, priv, capath) == FAILURE)
  {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  while (1)
  {
    MA_LOG1d("Waiting for next connection on port", port);

    nready = poll(client, maxi + i, 1000);

    if (nready <= 0)
      continue;
    else
      MA_LOG1d("nready", nready);

    // accept TCP connection
    if (client[0].revents & POLLIN)
    {
      fd = accept(client_side_sock, (struct sockaddr *)&peer_addr, &peer_addr_len);
      if (fd < 0)
      {
        perror("client socket error");
        exit(EXIT_FAILURE);
      }
      MA_LOG1d("client accpeted", fd);

      for (i=1; i<MAX_CLNT_SIDE; i++)
      {
        if (client[i].fd < 0)
        {
          client[i].fd = fd;
          break;
        }
      }

      if (i >= MAX_CLNT_SIDE)
      {
        close(fd);
        perror("too many clients");
      }

      if (i > maxi)
        maxi = i;

      if (ssl_client_init(&(client[i]), (struct sockaddr *)&peer_addr, peer_addr_len, &(info[i])) == FAILURE)
        continue;

      if (--nready <= 0)
        continue;
    }

    // polling and I/O operation
    for (i=1; i<=maxi; i++)
    {
      if (client[i].fd < 0)
        continue;

      MA_LOG1d("socket", i);
      if (client[i].revents & POLLIN)
      {
        MA_LOG("POLLIN");
        do_sock_read(&info[i]);
      }

      if (client[i].revents & POLLOUT)
      {
        MA_LOG("POLLOUT");
        do_sock_write(&info[i]);
      }

      //ssl_io_operation(&info[i]);
    }
  }
  return 0;
}
      
