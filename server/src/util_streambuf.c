#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "ds_stack.h"
#include "ds_llist.h"
#include "util_streambuf.h"

//#define	MAXSHIFT	0

//static ds_stack_t	*mem_cache[MAXSHIFT];
static ds_stack_t	*iov_cache;

static pthread_once_t init_once = PTHREAD_ONCE_INIT;

struct streambuf_st {
	llist_t *ringbuf;
	size_t h_limit, s_limit, nr_bytes;
	pthread_mutex_t mut;
	pthread_cond_t cond;
};

static void mutex_unlock(void *p)
{
	pthread_mutex_t *mut = p;
	pthread_mutex_unlock(mut);
}

static void destroy_cache(void)
{
	void *mem;
//	int i;
//	for (i=0;i < MAXSHIFT;++i) {
//		while ((mem=(void*)stack_pop_nb(mem_cache[i]))!=NULL) {
//			free(mem);
//		}
//	}
	while ((mem=(void*)stack_pop_nb(iov_cache))!=NULL) {
		free(mem);
	}
	stack_delete(iov_cache);
}

static void init_cache(void)
{
/*	int i;

	for (i=0;i < MAXSHIFT;++i) {
		mem_cache[i] = stack_new(10240);
	}*/
	iov_cache = stack_new(10240);
	atexit(destroy_cache);
}
/*
static inline int cache_slot(int len)
{
	int slot;

	slot = len>>10;
	if (slot>MAXSHIFT) {
		slot = MAXSHIFT;
	}
	return slot;
}*/

struct streambuf_iov_st *streambuf_iov_construct(void *ptr, size_t len)
{
	struct streambuf_iov_st *iov;

	iov = (void*)stack_pop_nb(iov_cache);
	if (iov==NULL) {
		iov = malloc(sizeof(*iov));
	}
	if (iov==NULL) {
		return NULL;
	}
	iov->mem = ptr;
	iov->memlen = len;
	iov->len = len;
	iov->pos = 0;

	return iov;
}

struct streambuf_iov_st *streambuf_iov_alloc(size_t len)
{
/*
	void *mem;
	int size;
	if (len<=BUFMAX) {
		size = 1024<<cache_slot(len);
		mem = (void*)stack_pop_nb(mem_cache[cache_slot(len)]);
		if (mem==NULL) {
			mem = malloc(size);
		}
	} else {
		size = len;
		mem = malloc(size);
	}
	if (mem==NULL) {
		return NULL;
	}
*/
	return streambuf_iov_construct(malloc(len), len);
}

struct streambuf_iov_st *streambuf_iov_merge(struct streambuf_iov_st *iov1, struct streambuf_iov_st *iov2)
{
	int len = iov1->memlen + iov2->len;

	iov1->mem = realloc(iov1->mem, len);
	if (iov1->mem == NULL) {
		return NULL;
	}

	memcpy(iov1->mem + iov1->memlen, iov2->mem + iov2->pos, iov2->len);
	iov1->memlen = len;
	iov1->len += iov2->len;

	return iov1;
}

void streambuf_iov_free(struct streambuf_iov_st *iov)
{
/*	if (iov->memlen <= BUFMAX) {
		if (stack_push_nb(mem_cache[cache_slot(iov->memlen)], (intptr_t)iov->mem)!=0) {
			free(iov->mem);
		}
	} else {
		free(iov->mem);
	} */
	free(iov->mem);
	if (stack_push_nb(iov_cache, (intptr_t)iov)!=0) {
		free(iov);
	}
}

streambuf_t *streambuf_new(size_t h_limit)
{
	struct streambuf_st *buf;

	pthread_once(&init_once, init_cache);

	buf = malloc(sizeof(*buf));
	if (h_limit < BUFVOL_MAX) {
		buf->ringbuf = llist_new(BUFVOL_MAX * 2);
	} else {
		buf->ringbuf = llist_new(h_limit * 2);
	}
	buf->h_limit = h_limit;
	buf->nr_bytes = 0;
	pthread_mutex_init(&buf->mut, NULL);
	pthread_cond_init(&buf->cond, NULL);
	return buf;
}

int streambuf_delete(streambuf_t *p)
{
	struct streambuf_iov_st *iov;
	struct streambuf_st *buf=p;

	if (buf->nr_bytes > 0) {
		while (streambuf_read_nb(p, &iov) ==0) {
			streambuf_iov_free(iov);
		}
	}
	pthread_mutex_destroy(&buf->mut);
	pthread_cond_destroy(&buf->cond);
	llist_delete(buf->ringbuf);
	free(buf);
	return 0;
}

size_t streambuf_setvolume(streambuf_t *p, size_t volume)
{
	struct streambuf_st *buf=p;
	pthread_mutex_lock(&buf->mut);
	pthread_cleanup_push(mutex_unlock, &buf->mut);
	if (volume<BUFVOL_MIN) {
		volume = BUFVOL_MIN;
	} else if (volume>BUFVOL_MAX) {
		volume = BUFVOL_MAX;
	}
	buf->h_limit = volume;
	pthread_cleanup_pop(1);
	return volume;
}

int streambuf_read(streambuf_t *p, struct streambuf_iov_st **iovp)
{
	struct streambuf_st *buf=p;
	struct streambuf_iov_st *iov;

	pthread_mutex_lock(&buf->mut);
	pthread_cleanup_push(mutex_unlock, &buf->mut);
	while (buf->nr_bytes == 0) {
		pthread_cond_wait(&buf->cond, &buf->mut);
	}
	llist_fetch_head(buf->ringbuf, (void**)&iov);
	*iovp = iov;
	buf->nr_bytes -= iov->len;
	pthread_cond_signal(&buf->cond);
	pthread_cleanup_pop(1);
	return 0;
}
int streambuf_read_nb(streambuf_t *p, struct streambuf_iov_st **iovp)
{
	int ret=0;
	struct streambuf_st *buf=p;
	struct streambuf_iov_st *iov;

	pthread_mutex_lock(&buf->mut);
	pthread_cleanup_push(mutex_unlock, &buf->mut);
	if (buf->nr_bytes == 0) {
		ret = EAGAIN;
		goto quit;
	}
	llist_fetch_head(buf->ringbuf, (void**)&iov);
	*iovp = iov;
	buf->nr_bytes -= iov->len;
	pthread_cond_signal(&buf->cond);
quit:
	pthread_cleanup_pop(1);
	return ret;
}

int streambuf_unread(streambuf_t *p, struct streambuf_iov_st *iov)
{
	struct streambuf_st *buf=p;

	pthread_mutex_lock(&buf->mut);
	pthread_cleanup_push(mutex_unlock, &buf->mut);
	llist_prepend(buf->ringbuf, iov);
	buf->nr_bytes += iov->len;
	pthread_cond_signal(&buf->cond);
	pthread_cleanup_pop(1);
	return 0;
}

int streambuf_write(streambuf_t *p, struct streambuf_iov_st *iov)
{
	int ret=0;
	struct streambuf_st *buf=p;

	pthread_mutex_lock(&buf->mut);
	pthread_cleanup_push(mutex_unlock, &buf->mut);
	while (buf->nr_bytes >= buf->h_limit) {
		pthread_cond_wait(&buf->cond, &buf->mut);
	}
	llist_append(buf->ringbuf, iov);
	buf->nr_bytes += iov->len;
	pthread_cond_signal(&buf->cond);
	pthread_cleanup_pop(1);
	return ret;
}
int streambuf_write_nb(streambuf_t *p, struct streambuf_iov_st *iov)
{
	int ret=0;
	struct streambuf_st *buf=p;

	pthread_mutex_lock(&buf->mut);
	pthread_cleanup_push(mutex_unlock, &buf->mut);
	if (buf->nr_bytes >= buf->h_limit) {
		ret = ENOMEM;
		goto quit;
	}
	llist_append(buf->ringbuf, iov);
	buf->nr_bytes += iov->len;
	pthread_cond_signal(&buf->cond);
quit:
	pthread_cleanup_pop(1);
	return ret;
}

#if 0
size_t streambuf_recv_to(int fd, streambuf_t *buf) {
	int ret, code;
    struct streambuf_iov_st *iov;
	size_t len=0, total=0;

	if (ioctl(fd, FIONREAD, &len)<0) {
		return -errno;
	}
	if (len==0) {
		return EAGAIN;
	}

	iov = streambuf_iov_alloc(len);
	if (iov==NULL) {
		return ENOMEM;
	}

	while (1) {
		iov->len = recv(fd, iov->mem + iov->pos, iov->memlen, MSG_DONTWAIT);
		if (len==0) {
			code = EPIPE;
		} else if (len<0) {
			if (errno==EAGAIN) {
			}
		} else {
			streambuf_write();
		}
	}

    while (streambuf_nr_bytes(buf)>0) {      
        ret = streambuf_read_nb(buf, &iov);  
        len = send(fd, iov->mem + iov->pos, iov->len - iov->pos,  MSG_DONTWAIT);                          
        if (len < 0) {
            /* Nonblock send */                          
            if (errno == EAGAIN || errno == EWOULDBLOCK) {                                                        
                streambuf_unread(buf, iov);
				break;
            }   
            return -errno; 
        }   
            
        iov->pos += len;                                 
        total += len;

        if (iov->len == iov->pos) {
            streambuf_iov_free(iov);
        } else {
            /* Iov sent partially, insert iov to buffer head */
            streambuf_unread(buf, iov);
            break;
        }
    }
	return total;
}
#endif

ssize_t streambuf_send(int fd, streambuf_t *buf) {
	ssize_t ret;
	struct streambuf_st *this = buf;
    struct streambuf_iov_st *iov;
	ssize_t total=0;
	struct iovec batch[1024];
	int batch_size, true=1;

	total=0;
	if (streambuf_nr_bytes(buf)<=0) {
		return 0;
	}
	batch_size=0;
	llist_foreach(this->ringbuf, iov, {
			if (batch_size>=1024) {
			break;
			}
			batch[batch_size].iov_base = iov->mem + iov->pos;
			batch[batch_size].iov_len = iov->len;
			batch_size++;
			total += iov->len;
		});

	total = writev(fd, batch, batch_size);
	if (total < 0) {
		/* Nonblock send */
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return -EAGAIN;
		}
		return -errno; 
	}
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &true, sizeof(true));

	ret = total;

	while (total>0) {
		if (streambuf_read_nb(buf, &iov)) {
			break;
		}
		if (iov->len <= total) {
			total -= iov->len;
			streambuf_iov_free(iov);
		} else {
			iov->pos += total;
			iov->len -= total;
			total = 0;
			streambuf_unread(buf, iov);
		}
	}

	return ret;
}

size_t streambuf_nr_bytes(streambuf_t *p)
{
	struct streambuf_st *buf=p;

	return buf->nr_bytes;
}

