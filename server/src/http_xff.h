#ifndef HTTP_XFF_H
#define HTTP_XFF_H

#include "util_streambuf.h"

int http_xff;

int http_header_xff_process(struct streambuf_iov_st *iov, const char *ipstr);

#endif

