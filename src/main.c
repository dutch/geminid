#define _XOPEN_SOURCE 500
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/epoll.h>
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

  if (!(pidfile = fopen(RUNSTATEDIR "/" PIDFILE, "w"))) {
    snprintf(errbuf, errlen, "fopen: %s", strerror(errno));
    write(errfd, errbuf, errlen);
    exit(EXIT_FAILURE);
  }

  fprintf(pidfile, "%ld\n", (long)getpid());
  fclose(pidfile);

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

  for (i = SIGRTMIN; i < SIGRTMAX; ++i) {
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

int
main(int argc, char **argv)
{
  int bg, dry, verb, ch, sockfd, connfd;
  socklen_t sinsz;
  char errbuf[ERROR_MAX], addrstr[INET6_ADDRSTRLEN], *confpath;
  struct config c;
  struct sockaddr_storage addr;

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
      return EXIT_FAILURE;
    }
  }

  openlog("geminid", bg ? 0 : LOG_PERROR, 0);
  setlogmask(LOG_UPTO(verb ? LOG_DEBUG : LOG_ERR));

  c.port = strdup("1965");
  c.jobs = 1;
  c.certificate = NULL;
  c.private_key = NULL;

  parse_config(confpath, &c);

  if (dry)
    return EXIT_SUCCESS;

  sockfd = boundsocket(c.port);

  if (listen(sockfd, MAX_EVENTS) == -1) {
    syslog(LOG_ERR, "listen: %s", strerror(errno));
    return EXIT_FAILURE;
  }

  syslog(LOG_NOTICE, "listening");

  for (;;) {
    sinsz = sizeof(struct sockaddr_storage);

    if ((connfd = accept(sockfd, (struct sockaddr *)&addr, &sinsz)) == -1) {
      syslog(LOG_ERR, "accept: %s", strerror(errno));
      continue;
    }

    inet_ntop(addr.ss_family, inaddr((struct sockaddr *)&addr), addrstr, INET6_ADDRSTRLEN);
    syslog(LOG_NOTICE, "accepted connection from %s", addrstr);
    close(connfd);
  }

  return EXIT_SUCCESS;
}
