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
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>

#define ERROR_MAX 128
#define TEXT_MAX 128
#define KEY_MAX 128
#define PIDFILE "geminid.pid"
#define CONFIGFILE "geminid.conf"

#define EQUALS 1
#define EOL 2
#define STRING 3

struct config
{
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

int
config_set(struct config *c, char *err, size_t errlen)
{
  int type;
  char *key, *value;

  if ((type = lex()) != STRING) {
    snprintf(err, errlen, "expected key, got '%s'", text);
    return 1;
  }

  key = strdup(text);

  if ((type = lex()) != EQUALS) {
    snprintf(err, errlen, "expected '=', got '%s'", text);
    return 1;
  }

  if ((type = lex()) != STRING) {
    snprintf(err, errlen, "expected value, got '%s'", text);
    return 1;
  }

  value = strdup(text);

  if ((type = lex()) != EOL) {
    snprintf(err, errlen, "expected EOL, got '%s'", text);
    return 1;
  }

  if (strcmp(key, "certificate") == 0) {
    c->certificate = strdup(value);
  } else if (strcmp(key, "private_key") == 0) {
    c->private_key = strdup(value);
  } else {
    snprintf(err, errlen, "unknown key '%s'", key);
    return 1;
  }

  free(value);
  free(key);

  return 0;
}

int
main(int argc, char **argv)
{
  int bg, dry, verb, ch;
  char errbuf[ERROR_MAX], *confpath;
  struct config c;

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

  if (!(in = fopen(confpath, "r"))) {
    syslog(LOG_ERR, "fopen: %s", strerror(errno));
    return EXIT_FAILURE;
  }

  nextch = fgetc(in);

  while (!feof(in)) {
    if (config_set(&c, errbuf, ERROR_MAX) == 1) {
      syslog(LOG_ERR, errbuf);
      return EXIT_FAILURE;
    }
  }

  syslog(LOG_DEBUG, "certificate = '%s'", c.certificate);
  syslog(LOG_DEBUG, "private_key = '%s'", c.private_key);

  if (dry)
    goto done;

done:
  closelog();

  return EXIT_SUCCESS;
}
