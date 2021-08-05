#ifndef PARSE_H
#define PARSE_H

#include <stdio.h>

#define EQUALS 1
#define EOL 2
#define STRING 3
#define SEPARATOR 4
#define SLASH 5

struct parse_context
{
  FILE *in;
  char nextch;
  char *pch;
  char text[128];
  size_t textlen;
};

struct config
{
  char *port;
  int jobs;
  char *certificate;
  char *private_key;
  char *root;
};

struct uriparts
{
  char *scheme;
  char *domain;
  char *path;
};

void parse_config(struct parse_context *ctx, const char *path, struct config *cfg);
void parse_uri(struct parse_context *ctx, const char *str, struct uriparts *uri);

#endif
