#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "util_streambuf.h"
#include "util_misc.h"
#include "http_xff.h"

#define	TOKEN "X-FORWARDED-FOR: "


int http_header_xff_process(struct streambuf_iov_st *iov, const char *ipstr)
{
	register int i;
	int token_h;

	if (iov->len<6) {
		return EINVAL;
	}

	// expand memory
	if (iov->memlen < iov->pos + iov->len+ strlen(ipstr)+strlen(TOKEN)+3) {
		iov->memlen += strlen(ipstr)+strlen(TOKEN)+3;
		iov->mem = realloc(iov->mem, iov->memlen);
	}

	// Skip line 0
	for (i=0;i<iov->len;++i) {
		if (iov->mem[i]=='\n') {
			break;
		}
	}
	if (i==iov->len) {
		// Header is incomplete.
		return EINVAL;
	}

	token_h = i+1;
	while (token_h<iov->len) {
		if (	(token_h <= iov->len-1 && memcmp(iov->mem+token_h, "\n", 1)==0) ||
				(token_h <= iov->len-2 && memcmp(iov->mem+token_h, "\r\n", 2)==0)) {
//			fprintf(stderr, "End of header\n");
			// End of header
			break;
		}
		if (unlikely(strncasecmp(iov->mem+token_h, TOKEN, strlen(TOKEN))==0)) {
//			fprintf(stderr, "Found exsisting XFF\n");
			// Found an exsisting XFF
			for (i=token_h;i<iov->len;++i) {
				if (iov->mem[i]=='\r' || iov->mem[i]=='\n') {
					memmove(iov->mem+i+strlen(", ")+strlen(ipstr), iov->mem+i, iov->len-i);
					memcpy(iov->mem+i,		", ",	strlen(", "));
					memcpy(iov->mem+i+2,	ipstr,	strlen(ipstr));
					iov->len += strlen(ipstr)+2;
					return 0;
				}
			}
			token_h=i+1;
		} else {
//			fprintf(stderr, "Ignoring header line\n");
			for (i=token_h;i<iov->len;++i) {
				if (iov->mem[i]=='\n') {
					token_h=i+1;
					break;
				}
			}
		}
	}
	// No exsisting XFF found.
//	fprintf(stderr, "No exsisting XFF found.\n");
	memmove(iov->mem+token_h+strlen(TOKEN)+strlen(ipstr)+strlen("\r\n"), iov->mem+token_h, iov->len-i);
	memcpy(iov->mem+token_h,								TOKEN, strlen(TOKEN));
	memcpy(iov->mem+token_h+strlen(TOKEN),					ipstr, strlen(ipstr));
	memcpy(iov->mem+token_h+strlen(TOKEN)+strlen(ipstr),	"\r\n", strlen("\r\n"));
	iov->len += strlen(TOKEN)+strlen(ipstr)+strlen("\r\n");
	return 0;
}

#ifdef UNIT_TEST

static void dump_iov(struct streambuf_iov_st *iov)
{
	int i;
	for (i=iov->pos;i<iov->pos+iov->len;++i) {
		if (iov->mem[i]=='\r') {
			printf("\\r");
		} else if (iov->mem[i]=='\n') {
			printf("\\n\n");
		} else {
			putchar(iov->mem[i]);
		}
	}
}

#define ADDR	"123.123.123.123"

static struct ut_set_t {
	const char *input, *output;
} ut_test_set[] = {
	{
		"GET / HTTP/1.1\r\n\r\nkskhfiudhfuisdyhasuyddfs",
		"GET / HTTP/1.1\r\nX-FORWARD-FOR: " ADDR "\r\n\r\nkskhfiudhfuisdyhasuyddfs"
	},
	{
		"GET / HTTP/1.1\r\n\r\nkskhfiudhfuisdyhasuyddfs",
		"GET / HTTP/1.1\r\nX-FORWARD-FOR: " ADDR "\r\n\r\nkskhfiudhfuisdyhasuyddfs"
	},
	{
		"GET / HTTP/1.1\r\nK1: V1\r\n\r\nkskhfiudhfuisdyhasuyddfs",
		"GET / HTTP/1.1\r\nK1: V1\r\nX-FORWARD-FOR: " ADDR "\r\n\r\nkskhfiudhfuisdyhasuyddfs"
	},
	{
		"GET / HTTP/1.1\r\nK1: V1\r\nX-FORWARD-FOR: 1.2.3.4\r\nK2: V2\r\n\r\nasdasd",
		"GET / HTTP/1.1\r\nK1: V1\r\nX-FORWARD-FOR: 1.2.3.4, " ADDR "\r\nK2: V2\r\n\r\nasdasd"
	},
	{NULL, NULL}
};

int
main()
{
	int i, err;
	struct streambuf_iov_st iov;

	for (i=0; ut_test_set[i].input!=NULL; ++i) {
		iov.mem = strdup(ut_test_set[i].input);
		iov.memlen = strlen(ut_test_set[i].input);
		iov.len = strlen(ut_test_set[i].input);
		iov.pos = 0;

		//printf("Before:\n");
		//dump_iov(&iov);
		//printf("\n===================\n");

		if ((err=http_header_xff_process(&iov, ADDR))==0) {
			if (memcmp(iov.mem, ut_test_set[i].output, strlen(ut_test_set[i].output))!=0) {
				printf("Case %d ERROR!\n", i);
				printf("Input = %s\n", ut_test_set[i].input);
				printf("Expect = %s\n", ut_test_set[i].output);
				printf("Output:\n");
				dump_iov(&iov);
				printf("\n");
			} else {
				printf("Case %d PASSED\n", i);
			}
		} else {
			printf("Returned %s\n", strerror(err));
		}
		free(iov.mem);
	}
	return 0;
}
#endif
