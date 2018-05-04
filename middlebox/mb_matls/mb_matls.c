#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "mssl.h"
#include "table.h"
#include "../common/logs.h"

struct connection_info
{
  int port;
  char *cert;
  char *priv;
  char *capath;
  char *forward_file;
} cinfo;

void *status;
void *main_loop(void *data);

int main(int argc, char **argv)
{
  int port, i, rc, tidx;
  char *cert, *priv, *capath, *forward_file;

  if (argc == 1)
  {
    port = 5555;
    cert = DEFAULT_CERT;
    priv = DEFAULT_PRIV;
    capath = DEFAULT_CA_PATH;
    forward_file = DEFAULT_FORWARD_FILE;
  }
  else if (argc == 6)
  {
    port = atoi(argv[1]);
    cert = argv[2];
    priv = argv[3];
    capath = argv[4];
    forward_file = argv[5];
  }

  cinfo.port = port;
  cinfo.cert = cert;
  cinfo.priv = priv;
  cinfo.capath = capath;
  cinfo.forward_file = forward_file;

  init_forward_table(forward_file);
  init_thread_config();

  MA_LOG("before start pthread create");
  rc = pthread_create(&threads[tidx], &attr, main_loop, &cinfo);
  MA_LOG1d("pthread create result", rc);
  if (rc < 0)
  {
    MA_LOG("error in pthread create");
    exit(EXIT_FAILURE);
  }

  pthread_attr_destroy(&attr);

  for (i=0; i<MAX_THREADS; i++)
  {
    rc = pthread_join(threads[i], &status);

    if (rc)
    {
      MA_LOG("error in join");
      return 1;
    }
  }

  free_forward_table();

  return 0;
}

void *main_loop(void *data)
{
  MA_LOG("start main loop");
  char str[INET_ADDRSTRLEN];
  struct connection_info *cinfo;
  cinfo = (struct connection_info *)data;

  int servfd = socket(AF_INET, SOCK_STREAM, 0);
  if (servfd < 0)
    die("socket()");

  int enable = 1;
  if (setsockopt(servfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
    die("setsockopt(SO_REUSEADDR)");

  /* Specify socket address */
  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(cinfo->port);

  if (bind(servfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    die("bind()");

  if (listen(servfd, MAX_CLNT_SIZE) < 0)
    die("listen()");

  int clientfd;
  struct sockaddr_in peeraddr;
  socklen_t peeraddr_len = sizeof(peeraddr);

  struct pollfd fdset[MAX_CLNT_SIZE];
  memset(&fdset, 0, sizeof(fdset));

  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  ssl_init(cinfo->cert, cinfo->priv);

  while (1) {
    MA_LOG1d("waiting for next connection on port", cinfo->port);

    clientfd = accept(servfd, (struct sockaddr *)&peeraddr, &peeraddr_len);
    if (clientfd < 0)
      die("accept()");

    ssl_client_init(&client);
    client.fd = clientfd;

    inet_ntop(peeraddr.sin_family, &peeraddr.sin_addr, str, INET_ADDRSTRLEN);
    printf("new connection from %s:%d\n", str, ntohs(peeraddr.sin_port));

    fdset[1].fd = clientfd;
    fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;

    while (1) {
      fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;
      fdset[1].events &= ~POLLOUT;
      fdset[1].events |= (ssl_client_want_write(&client)? POLLOUT : 0);

      int nready = poll(&fdset[0], MAX_CLNT_SIZE + 1, -1);

      if (nready == 0)
        continue;

      int revents = fdset[1].revents;
      if (revents & POLLIN)
      {
        if (do_sock_read() == -1)
          break;
      }

      if (revents & POLLOUT)
      {
        if (client.write_len > 0)
          if (do_sock_write() == -1)
            break;
      }

      if (revents & (POLLERR | POLLHUP | POLLNVAL))
        break;

      if (client.encrypt_len > 0)
        do_encrypt();
    }

    close(fdset[1].fd);
    ssl_client_cleanup(&client);
  }

}
