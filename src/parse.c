#define _GNU_SOURCE

#include "parse.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <ctype.h>

static int
lex_config(struct parse_context *ctx)
{
  ctx->textlen = 0;

  if (ctx->nextch == '\n') {
    ctx->text[ctx->textlen++] = ctx->nextch;
    ctx->text[ctx->textlen] = '\0';
    ctx->nextch = fgetc(ctx->in);
    return EOL;
  }

  while (isspace(ctx->nextch))
    ctx->nextch = fgetc(ctx->in);

  if (ctx->nextch == '=') {
    ctx->text[ctx->textlen++] = ctx->nextch;
    ctx->text[ctx->textlen] = '\0';
    ctx->nextch = fgetc(ctx->in);
    return EQUALS;
  }

  if (isgraph(ctx->nextch)) {
    do ctx->text[ctx->textlen++] = ctx->nextch;
    while (!isspace(ctx->nextch = fgetc(ctx->in)));
    ctx->text[ctx->textlen] = '\0';
    return STRING;
  }

  return 0;
}

static int
lex_uri(struct parse_context *ctx)
{
  if (isgraph(*ctx->pch)) {
    do ctx->text[ctx->textlen++] = *ctx->pch;
    while (*(++ctx->pch) != ':');
    ctx->text[ctx->textlen] = '\0';
    return STRING;
  }

  return 0;
}

static void
config_set(struct parse_context *ctx, struct config *cfg)
{
  int type;
  char *key, *value;

  if ((type = lex_config(ctx)) != STRING) {
    syslog(LOG_ERR, "expected key, got '%s'", ctx->text);
    exit(EXIT_FAILURE);
  }

  key = strdup(ctx->text);

  if ((type = lex_config(ctx)) != EQUALS) {
    syslog(LOG_ERR, "expected '=', got '%s'", ctx->text);
    exit(EXIT_FAILURE);
  }

  if ((type = lex_config(ctx)) != STRING) {
    syslog(LOG_ERR, "expected value, got '%s'", ctx->text);
    exit(EXIT_FAILURE);
  }

  value = strdup(ctx->text);

  if ((type = lex_config(ctx)) != EOL) {
    syslog(LOG_ERR, "expected EOL, got '%s'", ctx->text);
    exit(EXIT_FAILURE);
  }

  if (strcmp(key, "port") == 0) {
    free(cfg->port);
    cfg->port = strdup(value);
    syslog(LOG_DEBUG, "port = '%s'", cfg->port);
  } else if (strcmp(key, "jobs") == 0) {
    cfg->jobs = atoi(value);
    syslog(LOG_DEBUG, "jobs = %d", cfg->jobs);
  } else if (strcmp(key, "certificate") == 0) {
    free(cfg->certificate);
    cfg->certificate = strdup(value);
    syslog(LOG_DEBUG, "certificate = '%s'", cfg->certificate);
  } else if (strcmp(key, "private_key") == 0) {
    free(cfg->private_key);
    cfg->private_key = strdup(value);
    syslog(LOG_DEBUG, "private_key = '%s'", cfg->private_key);
  } else if (strcmp(key, "root") == 0) {
    free(cfg->root);
    cfg->root = strdup(value);
    syslog(LOG_DEBUG, "root = '%s'", cfg->root);
  } else {
    syslog(LOG_ERR, "unknown key '%s'", key);
    exit(EXIT_FAILURE);
  }

  free(value);
  free(key);
}

static void
uri_set(struct parse_context *ctx, struct uriparts *uri)
{
  int type;

  if ((type = lex_uri(ctx)) != STRING) {
    syslog(LOG_ERR, "expected scheme, got '%s'", ctx->text);
    exit(EXIT_FAILURE);
  }

  uri->scheme = strdup(ctx->text);
}

void
parse_config(struct parse_context *ctx, const char *path, struct config *cfg)
{
  if (!(ctx->in = fopen(path, "r"))) {
    syslog(LOG_ERR, "fopen: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  ctx->nextch = fgetc(ctx->in);

  while (!feof(ctx->in))
    config_set(ctx, cfg);

  fclose(ctx->in);
}

void
parse_uri(struct parse_context *ctx, const char *str, struct uriparts *uri)
{
  ctx->pch = &str[0];
  uri_set(ctx, uri);
}
