#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

#define ERROR_MAX 128
#define TEXT_MAX 128
#define KEY_MAX 128
#define MAX_EVENTS 10
#define PIDFILE "geminid.pid"
#define CONFIGFILE "geminid.conf"

#define EQUALS 1
#define EOL 2
#define STRING 3

struct config
{
  char *port;
  int jobs;
  char *certificate;
  char *private_key;
};

FILE *in;
char nextch;
char text[TEXT_MAX];
size_t textlen;

void
secondchild(int fd, int errfd, size_t errlen)
{
  int pidfd;
  char *errbuf;
  FILE *pidfile;

  errbuf = malloc(errlen);

  if (!freopen("/dev/null", "r", stdin)) {
    snprintf(errbuf, errlen, "freopen: %s", strerror(errno));
    write(errfd, errbuf, errlen);
    exit(EXIT_FAILURE);
  }

  if (!freopen("/dev/null", "w", stdout)) {
    snprintf(errbuf, errlen, "freopen: %s", strerror(errno));
    write(errfd, errbuf, errlen);
    exit(EXIT_FAILURE);
  }

  if (!freopen("/dev/null", "w", stderr)) {
    snprintf(errbuf, errlen, "freopen: %s", strerror(errno));
    write(errfd, errbuf, errlen);
    exit(EXIT_FAILURE);
  }

  umask(0);

  if (chdir("/") == -1) {
    snprintf(errbuf, errlen, "chdir: %s", strerror(errno));
    write(errfd, errbuf, errlen);
    exit(EXIT_FAILURE);
  }

  if ((pidfd = open(RUNSTATEDIR "/" PIDFILE, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)) == -1) {
    snprintf(errbuf, errlen, "open: %s", strerror(errno));
    write(errfd, errbuf, errlen);
    exit(EXIT_FAILURE);
  }

  if (!(pidfile = fdopen(pidfd, "w"))) {
    snprintf(errbuf, errlen, "fdopen: %s", strerror(errno));
    write(errfd, errbuf, errlen);
    exit(EXIT_FAILURE);
  }

  fprintf(pidfile, "%ld\n", (long)getpid());
  fclose(pidfile);
  close(pidfd);

  free(errbuf);
  write(fd, "\0", 1);
}

void
firstchild(int fd, int errfd, size_t errlen)
{
  char *errbuf;

  errbuf = malloc(errlen);

  if (setsid() == -1) {
    snprintf(errbuf, errlen, "setsid: %s", strerror(errno));
    write(errfd, errbuf, errlen);
    exit(EXIT_FAILURE);
  }

  switch (fork()) {
  case -1:
    close(fd);
    snprintf(errbuf, errlen, "fork: %s", strerror(errno));
    write(errfd, errbuf, errlen);
    exit(EXIT_FAILURE);

  case 0:
    secondchild(fd, errfd, errlen);
    break;

  default:
    exit(EXIT_SUCCESS);
  }

  free(errbuf);
}

int
daemonize(char *err, size_t errlen)
{
  int i, fds[2], errfds[2];
  struct rlimit rlim;
  sigset_t set;
  fd_set fdset;

  if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
    snprintf(err, errlen, "getrlimit: %s", strerror(errno));
    return -1;
  }

  while (rlim.rlim_cur --> 3) {
    if (close(rlim.rlim_cur) == -1) {
      if (errno == EBADF)
        continue;

      snprintf(err, errlen, "close: %s", strerror(errno));
      return -1;
    }
  }

  sigfillset(&set);

  for (i = 1; i < _NSIG; ++i) {
    if (!sigismember(&set, i))
      continue;

    if (signal(i, SIG_DFL) == SIG_ERR) {
      if (i == SIGKILL || i == SIGSTOP)
        continue;

      snprintf(err, errlen, "signal: %s", strerror(errno));
      return -1;
    }
  }

  sigemptyset(&set);

  if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
    snprintf(err, errlen, "sigprocmask: %s", strerror(errno));
    return -1;
  }

  if (pipe(fds) == -1) {
    snprintf(err, errlen, "pipe: %s", strerror(errno));
    return -1;
  }

  if (pipe(errfds) == -1) {
    snprintf(err, errlen, "pipe: %s", strerror(errno));
    return -1;
  }

  switch (fork()) {
  case -1:
    close(fds[0]);
    close(fds[1]);
    close(errfds[0]);
    close(errfds[1]);
    snprintf(err, errlen, "fork: %s", strerror(errno));
    return -1;

  case 0:
    close(fds[0]);
    close(errfds[0]);
    firstchild(fds[1], errfds[1], errlen);
    break;

  default:
    close(fds[1]);
    close(errfds[1]);
    FD_ZERO(&fdset);
    FD_SET(fds[0], &fdset);
    FD_SET(errfds[0], &fdset);

    if (select(50, &fdset, NULL, NULL, NULL) == -1) {
      snprintf(err, errlen, "select: %s", strerror(errno));
      return -1;
    }

    if (FD_ISSET(fds[0], &fdset))
      exit(EXIT_SUCCESS);

    if (FD_ISSET(errfds[0], &fdset)) {
      read(errfds[0], err, errlen);
      return -1;
    }

    exit(EXIT_SUCCESS);
  }

  return 0;
}

int
lex(void)
{
  textlen = 0;

  if (nextch == '\n') {
    text[textlen++] = nextch;
    text[textlen] = '\0';
    nextch = fgetc(in);
    return EOL;
  }

  while (isspace(nextch))
    nextch = fgetc(in);

  if (nextch == '=') {
    text[textlen++] = nextch;
    text[textlen] = '\0';
    nextch = fgetc(in);
    return EQUALS;
  }

  if (isgraph(nextch)) {
    do text[textlen++] = nextch;
    while (!isspace(nextch = fgetc(in)));
    text[textlen] = '\0';
    return STRING;
  }

  return 0;
}

void
config_set(struct config *c)
{
  int type;
  char *key, *value;

  if ((type = lex()) != STRING) {
    syslog(LOG_ERR, "expected key, got '%s'", text);
    exit(EXIT_FAILURE);
  }

  key = strdup(text);

  if ((type = lex()) != EQUALS) {
    syslog(LOG_ERR, "expected '=', got '%s'", text);
    exit(EXIT_FAILURE);
  }

  if ((type = lex()) != STRING) {
    syslog(LOG_ERR, "expected value, got '%s'", text);
    exit(EXIT_FAILURE);
  }

  value = strdup(text);

  if ((type = lex()) != EOL) {
    syslog(LOG_ERR, "expected EOL, got '%s'", text);
    exit(EXIT_FAILURE);
  }

  if (strcmp(key, "port") == 0) {
    free(c->port);
    c->port = strdup(value);
    syslog(LOG_DEBUG, "port = '%s'", c->port);
  } else if (strcmp(key, "jobs") == 0) {
    c->jobs = atoi(value);
    syslog(LOG_DEBUG, "jobs = %d", c->jobs);
  } else if (strcmp(key, "certificate") == 0) {
    free(c->certificate);
    c->certificate = strdup(value);
    syslog(LOG_DEBUG, "certificate = '%s'", c->certificate);
  } else if (strcmp(key, "private_key") == 0) {
    free(c->private_key);
    c->private_key = strdup(value);
    syslog(LOG_DEBUG, "private_key = '%s'", c->private_key);
  } else {
    syslog(LOG_ERR, "unknown key '%s'", key);
    exit(EXIT_FAILURE);
  }

  free(value);
  free(key);
}

void
parse_config(const char *confpath, struct config *c)
{
  if (!(in = fopen(confpath, "r"))) {
    syslog(LOG_ERR, "fopen: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  nextch = fgetc(in);

  while (!feof(in))
    config_set(c);

  fclose(in);
}

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

void *
inaddr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET)
    return &((struct sockaddr_in *)sa)->sin_addr;
  return &((struct sockaddr_in6 *)sa)->sin6_addr;
}

void
acceptproc(int epfd)
{
  int nevs, connfd;
  socklen_t sinsz;
  struct epoll_event evs[MAX_EVENTS];
  struct sockaddr_storage addr;
  char addrstr[INET6_ADDRSTRLEN];

  for (;;) {
    if ((nevs = epoll_wait(epfd, evs, MAX_EVENTS, -1)) == -1)
      syslog(LOG_ERR, "epoll_wait: %s", strerror(errno));

    while (nevs --> 0) {
      sinsz = sizeof(struct sockaddr_storage);

      if ((connfd = accept4(evs[nevs].data.fd, (struct sockaddr *)&addr, &sinsz, SOCK_NONBLOCK)) == -1)
        syslog(LOG_ERR, "accept4: %s", strerror(errno));

      inet_ntop(addr.ss_family, inaddr((struct sockaddr *)&addr), addrstr, INET6_ADDRSTRLEN);
      syslog(LOG_NOTICE, "accepted connection from %s", addrstr);
      close(evs[nevs].data.fd);
    }
  }
}

void
prefork(int epfd, pid_t *forks, int nforks)
{
  pid_t pid;

  while (nforks --> 0) {
    switch ((pid = fork())) {
    case -1:
      syslog(LOG_ERR, "fork: %s", strerror(errno));
      exit(EXIT_FAILURE);

    case 0:
      acceptproc(epfd);
      return;
    }

    forks[nforks] = pid;
  }
}

int
main(int argc, char **argv)
{
  int ret, bg, dry, verb, ch, sockfd, epfd, connepfd, sigfd, nevs;
  sigset_t blockset;
  pid_t *pids;
  char errbuf[ERROR_MAX], *confpath;
  struct config c;
  struct epoll_event evs[MAX_EVENTS];
  struct signalfd_siginfo ssi;

  ret = EXIT_FAILURE;
  bg = 1;
  confpath = strdup(SYSCONFDIR "/" CONFIGFILE);
  dry = 0;
  verb = 0;

  while ((ch = getopt(argc, argv, "df:nv")) != -1) {
    switch (ch) {
    case 'd':
      bg = 0;
      break;

    case 'f':
      free(confpath);
      confpath = strdup(optarg);
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
    if (daemonize(errbuf, ERROR_MAX) == -1) {
      fprintf(stderr, "%s\n", errbuf);
      goto done;
    }
  }

  openlog("geminid", bg ? 0 : LOG_PERROR, 0);
  setlogmask(LOG_UPTO(verb ? LOG_DEBUG : LOG_ERR));

  c.port = strdup("1965");
  c.jobs = 1;
  c.certificate = NULL;
  c.private_key = NULL;

  parse_config(confpath, &c);

  if (dry) {
    ret = EXIT_SUCCESS;
    goto done;
  }

  sockfd = boundsocket(c.port);

  if (listen(sockfd, MAX_EVENTS) == -1) {
    syslog(LOG_ERR, "listen: %s", strerror(errno));
    goto done;
  }

  syslog(LOG_NOTICE, "listening");

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

  pids = malloc(sizeof(pid_t) * c.jobs);
  prefork(connepfd, pids, c.jobs);

  if (sigprocmask(SIG_BLOCK, &blockset, NULL) == -1) {
    syslog(LOG_ERR, "sigprocmask: %s", strerror(errno));
    goto done;
  }

  for (;;) {
    if ((nevs = epoll_wait(epfd, evs, MAX_EVENTS, -1)) == -1) {
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
            syslog(LOG_WARNING, "received '%s', exiting", strsignal(ssi.ssi_signo));
            while (c.jobs --> 0)
              kill(pids[c.jobs], SIGKILL);
            goto done;

          case SIGHUP:
          case SIGUSR1:
            syslog(LOG_WARNING, "received '%s', reloading config files", strsignal(ssi.ssi_signo));
            while (c.jobs --> 0) {
              kill(pids[c.jobs], SIGKILL);
              waitpid(pids[c.jobs], NULL, 0);
            }
            parse_config(confpath, &c);
            pids = malloc(sizeof(pid_t) * c.jobs);
            prefork(connepfd, pids, c.jobs);
            break;
          }
        }
      }
    }
  }

done:
  if (bg && unlink(RUNSTATEDIR "/" PIDFILE) == -1) {
    syslog(LOG_ERR, "unlink: %s", strerror(errno));
    return EXIT_FAILURE;
  }

  return ret;
}
