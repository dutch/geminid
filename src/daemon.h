#ifndef DAEMON_H
#define DAEMON_H

#include <stddef.h>

int daemonize(const char *path, char *err, size_t errlen);

#endif
