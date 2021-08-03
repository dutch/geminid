/*
 * Copyright (C) 2021 Chris Lamberson <chris@lamberson.online>.
 *
 * This file is part of geminid.
 *
 * geminid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * geminid is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with geminid.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include "config.h"
#include "gettext.h"
#include "daemon.h"
#include "parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define ERROR_MAX 128
#define MAX_EVENTS 10

#define _(String) gettext(String)

int
boundsocket(const char *port)
{
  int res, fd, yes;
  struct addrinfo hints, *info, *p;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((res = getaddrinfo(NULL, port, &hints, &info)) != 0) {
    syslog(LOG_ERR, "getaddrinfo: %s", gai_strerror(res));
    exit(EXIT_FAILURE);
  }

  yes = 1;

  for (p = info; p; p = p->ai_next) {
    if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      syslog(LOG_DEBUG, "socket: %s", strerror(errno));
      continue;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      syslog(LOG_ERR, "setsockopt: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }

    if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
      syslog(LOG_DEBUG, "bind: %s", strerror(errno));
      close(fd);
      continue;
    }

    break;
  }

  freeaddrinfo(info);

  if (!p) {
    syslog(LOG_ERR, "error binding socket");
    exit(EXIT_FAILURE);
  }

  return fd;
}

void
acceptproc(int fd, SSL_CTX *ctx)
{
  int nevs, connfd, nbytes;
  struct epoll_event evs[MAX_EVENTS];
  SSL *ssl;
  char buf[1024];
  struct parse_context urictx;
  struct uriparts uri;

  for (;;) {
    if ((nevs = epoll_wait(fd, evs, MAX_EVENTS, -1)) == -1) {
      if (errno == EINTR)
        continue;
      /* error */
    }

    while (nevs --> 0) {
      if ((connfd = accept(evs[nevs].data.fd, NULL, NULL)) == -1) {
        /* error */
      }

      ssl = SSL_new(ctx);
      SSL_set_fd(ssl, connfd);
      SSL_accept(ssl);
      nbytes = SSL_read(ssl, buf, 1024);
      buf[nbytes] = '\0';
      parse_uri(&urictx, buf, &uri);
      syslog(LOG_NOTICE, "scheme = '%s'", uri.scheme);
      SSL_shutdown(ssl);
      SSL_free(ssl);

      close(connfd);
    }
  }
}

void
prefork(int fd, SSL_CTX *ctx, pid_t *pids, int npids)
{
  pid_t pid;

  while (npids --> 0) {
    switch ((pid = fork())) {
    case -1:
      syslog(LOG_ERR, "fork: %s", strerror(errno));
      exit(EXIT_FAILURE);

    case 0:
      acceptproc(fd, ctx);
      return;
    }

    pids[npids] = pid;
  }
}

int
main(int argc, char **argv)
{
  int ret, bg, dry, verb, ch, sockfd, backlog, epfd, connepfd, sigfd, nevs;
  sigset_t blockset;
  pid_t *pids;
  char errbuf[ERROR_MAX], *cfgpath;
  struct parse_context cfgctx;
  struct config cfg;
  struct epoll_event evs[MAX_EVENTS];
  struct signalfd_siginfo ssi;
  FILE *somaxconn;
  SSL_CTX *sslctx;

  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE, LOCALEDIR);
  textdomain(PACKAGE);

  ret = EXIT_FAILURE;
  bg = 1;
  cfgpath = strdup(SYSCONFDIR "/geminid.conf");
  dry = 0;
  verb = 0;

  while ((ch = getopt(argc, argv, "df:nv")) != -1) {
    switch (ch) {
    case 'd':
      bg = 0;
      break;

    case 'f':
      free(cfgpath);
      cfgpath = strdup(optarg);
      break;

    case 'n':
      dry = 1;
      break;

    case 'v':
      verb = 1;
      break;
    }
  }

  if (bg) {
    if (daemonize(RUNSTATEDIR "/geminid.pid", errbuf, ERROR_MAX) == -1) {
      fprintf(stderr, "%s\n", errbuf);
      goto done;
    }
  }

  openlog("geminid", bg ? 0 : LOG_PERROR, 0);
  setlogmask(LOG_UPTO(verb ? LOG_DEBUG : LOG_ERR));

  cfg.port = strdup("1965");
  cfg.jobs = 1;
  cfg.certificate = NULL;
  cfg.private_key = NULL;
  cfg.root = strdup("/var/gmiroot");

  parse_config(&cfgctx, cfgpath, &cfg);

  if (dry) {
    ret = EXIT_SUCCESS;
    goto done;
  }

  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  sslctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_set_min_proto_version(sslctx, TLS1_2_VERSION);
  SSL_CTX_set_ecdh_auto(sslctx, 1);
  SSL_CTX_use_certificate_file(sslctx, cfg.certificate, SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(sslctx, cfg.private_key, SSL_FILETYPE_PEM);

  sockfd = boundsocket(cfg.port);

  if (!(somaxconn = fopen("/proc/sys/net/core/somaxconn", "r"))) {
    syslog(LOG_ERR, "fopen: %s", strerror(errno));
    goto done;
  }

  if (fscanf(somaxconn, "%d", &backlog) == EOF) {
    syslog(LOG_ERR, "fscanf: %s", strerror(errno));
    goto done;
  }

  fclose(somaxconn);

  if (listen(sockfd, backlog) == -1) {
    syslog(LOG_ERR, "listen: %s", strerror(errno));
    goto done;
  }

  syslog(LOG_NOTICE, _("listening"));

  if ((epfd = epoll_create1(0)) == -1) {
    syslog(LOG_ERR, "epoll_create1: %s", strerror(errno));
    goto done;
  }

  if ((connepfd = epoll_create1(0)) == -1) {
    syslog(LOG_ERR, "epoll_create1: %s", strerror(errno));
    goto done;
  }

  evs[0].events = EPOLLIN | EPOLLEXCLUSIVE;
  evs[0].data.fd = sockfd;

  if (epoll_ctl(connepfd, EPOLL_CTL_ADD, sockfd, evs) == -1) {
    syslog(LOG_ERR, "epoll_ctl: %s", strerror(errno));
    goto done;
  }

  sigemptyset(&blockset);
  sigaddset(&blockset, SIGINT);
  sigaddset(&blockset, SIGTERM);
  sigaddset(&blockset, SIGHUP);
  sigaddset(&blockset, SIGUSR1);

  if ((sigfd = signalfd(-1, &blockset, SFD_NONBLOCK)) == -1) {
    syslog(LOG_ERR, "signalfd: %s", strerror(errno));
    goto done;
  }

  evs[0].events = EPOLLIN | EPOLLET;
  evs[0].data.fd = sigfd;

  if (epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, evs) == -1) {
    syslog(LOG_ERR, "epoll_ctl: %s", strerror(errno));
    goto done;
  }

  pids = malloc(sizeof(pid_t) * cfg.jobs);
  prefork(connepfd, sslctx, pids, cfg.jobs);

  if (sigprocmask(SIG_BLOCK, &blockset, NULL) == -1) {
    syslog(LOG_ERR, "sigprocmask: %s", strerror(errno));
    goto done;
  }

  for (;;) {
    if ((nevs = epoll_wait(epfd, evs, MAX_EVENTS, -1)) == -1) {
      if (errno == EINTR)
        continue;

      syslog(LOG_ERR, "epoll_wait: %s", strerror(errno));
      goto done;
    }

    while (nevs --> 0) {
      if (evs[nevs].data.fd == sigfd) {
        for (;;) {
          if (read(sigfd, &ssi, sizeof(struct signalfd_siginfo)) == -1) {
            if (errno == EAGAIN)
              break;

            syslog(LOG_ERR, "read: %s", strerror(errno));
            goto done;
          }

          switch (ssi.ssi_signo) {
          case SIGINT:
          case SIGTERM:
            syslog(LOG_WARNING, _("received '%s', exiting"), strsignal(ssi.ssi_signo));
            while (cfg.jobs --> 0)
              kill(pids[cfg.jobs], SIGKILL);
            goto done;

          case SIGHUP:
          case SIGUSR1:
            syslog(LOG_WARNING, "received '%s', reloading config files", strsignal(ssi.ssi_signo));
            while (cfg.jobs --> 0) {
              kill(pids[cfg.jobs], SIGKILL);
              waitpid(pids[cfg.jobs], NULL, 0);
            }
            parse_config(&cfgctx, cfgpath, &cfg);
            pids = malloc(sizeof(pid_t) * cfg.jobs);
            prefork(connepfd, sslctx, pids, cfg.jobs);
            break;
          }
        }
      }
    }
  }

done:
  if (bg && unlink(RUNSTATEDIR "/geminid.pid") == -1) {
    syslog(LOG_ERR, "unlink: %s", strerror(errno));
    return EXIT_FAILURE;
  }

  return ret;
}
