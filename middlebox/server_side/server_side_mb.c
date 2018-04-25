/**
 * @file server_side_mb.c
 * @author Hyunwoo Lee
 * @date 25 Apr 2018
 * @brief The server side middlebox application
 */

#include <arpa/inet.h>
#include <poll.h>
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
  int port;
  int client_side_sock, server_side_sock, client;
  int nready, revents;
  struct sockaddr_in serv_addr, peer_addr;
  struct pollfd fdset[2];
  socklen_t peer_addr_len;
  char *cert, *priv, *capath;
  char ip[INET_ADDRSTRLEN];

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
  memset(&fdset, 0, sizeof(fdset));

  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  ssl_init(cert, priv, capath);

  while (1)
  {
    MA_LOG1d("Waiting for next connection on port", port);

    client = accept(client_side_sock, (struct sockaddr *)&peer_addr, &peer_addr_len);
    if (client < 0)
      perror("client socket error");

    struct client_info info;
    ssl_client_init(&info);
    info.fd = client;

    fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;
#ifdef PULLRDHUP
    fdset[i].events |= POLLRDHUP;
#endif

    while (1)
    {
      fdset[1].events &= ~POLLOUT;
      fdset[1].events |= (ssl_client_want_write(&info) ? POLLOUT : 0);

      nready = poll(&fdset[0], 2, -1);

      if (nready == 0)
        continue;

      revents = fdset[1].revents;
      if (revents & POLLIN)
        if (do_sock_read(&info) == -1)
          break;
      if (revents & POLLOUT)
        if (do_sock_write(&info) == -1)
          break;
      if (revents & (POLLERR | POLLHUP | POLLNVAL))
        break;

#ifdef POLLRDHUP
      if (revents & POLLRDHUP)
        break;
#endif

      if (fdset[0].revents & POLLIN)
        do_stdin_read(&info);

      if (info.encrypt_len > 0)
        do_encrypt(&info);
    }

    close(fdset[1].fd);
    ssl_client_cleanup(&info);
  }

  return 0;
}
      
