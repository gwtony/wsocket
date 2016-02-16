#ifndef STREAMBUF_H
#define STREAMBUF_H

typedef void streambuf_t;

struct streambuf_iov_st {
    char *mem;
	size_t memlen;
    size_t len, pos;
};
struct streambuf_iov_st *streambuf_iov_alloc(size_t len);
struct streambuf_iov_st *streambuf_iov_construct(void *ptr, size_t len);
void streambuf_iov_free(struct streambuf_iov_st *);

streambuf_t *streambuf_new(size_t softlimit, size_t hardlimit);
int streambuf_delete(streambuf_t*);

int streambuf_read(streambuf_t *, struct streambuf_iov_st **);
int streambuf_read_nb(streambuf_t *, struct streambuf_iov_st **);

int streambuf_unread(streambuf_t *, struct streambuf_iov_st *);

/* Ret: 0		:	OK
 * 		EAGAIN	:	Should not write again.
 * 		ENOMEM	:	Really full.
 */
int streambuf_write(streambuf_t *, struct streambuf_iov_st *);
int streambuf_write_nb(streambuf_t *, struct streambuf_iov_st *);

ssize_t streambuf_send(int fd, streambuf_t *buf);

size_t streambuf_nr_bytes(streambuf_t *);

int streambuf_write_wouldblock(streambuf_t *);

#endif

