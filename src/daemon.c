#define _GNU_SOURCE

#include "daemon.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

static void
secondchild(int fd, const char *path, int errfd, size_t errlen)
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

  if ((pidfd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)) == -1) {
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

static void
firstchild(int fd, const char *path, int errfd, size_t errlen)
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
    secondchild(fd, path, errfd, errlen);
    break;

  default:
    exit(EXIT_SUCCESS);
  }

  free(errbuf);
}

int
daemonize(const char *path, char *err, size_t errlen)
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
    firstchild(fds[1], path, errfds[1], errlen);
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
