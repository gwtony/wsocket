#ifndef WEIBOSOCKET_H
#define WEIBOSOCKET_H

/** Include protocol.h for the utility macro: FRAME_FLAG_MAKE(v, c, z)
    which has protocol depencency. */
#include <protocol.h>
#include <sys/time.h>
#define RELEASE_BUILDING
typedef struct {
	void (*recv_cb)(void*, void*, size_t);
	void *recv_cb_arg1;
	void (*sendok_cb)(void*);
	void *sendok_cb_arg1;
	void (*eof_cb)(void*, void*, size_t);
	void *eof_cb_arg1;
	void (*except_cb)(void*, int);
	void *except_cb_arg1;
} callback_t;

typedef void wsocket_context_t;

enum wsocket_states {
	STATE_NOTOPEN=1,
	STATE_INPROGRESS=2,
	STATE_CLOSED=3,
	STATE_CANCELED=4,
	STATE_FAILED=5,
	STATE_TIMEOUT=6,
};

struct wsocket_stat_st {
	enum wsocket_states state;
	int64_t send_bytes, recv_bytes;
	time_t start_time,end_time;
};

typedef struct flist_node_st {
	void (*func)(void);
        struct flist_node_st *next;
} flist_node_t;

wsocket_context_t *wsocket_context_new(void);
void wsocket_context_delete(wsocket_context_t*);

int wsocket_context_set_hashkey(wsocket_context_t*,  const void *hashkey, size_t hashkey_len);
int wsocket_context_set_flag(wsocket_context_t*, int local, int peer);
int wsocket_context_set_recv_timeout(wsocket_context_t*, int timeout);
int wsocket_context_set_callback(wsocket_context_t*, callback_t*);
int wsocket_context_set_data(wsocket_context_t*, const void*, size_t);

int wsocket_run(wsocket_context_t*);
int wsocket_send(wsocket_context_t*, const void*, size_t);
int wsocket_cancel(wsocket_context_t*);
struct wsocket_stat_st *wsocket_stat(wsocket_context_t*, struct wsocket_stat_st*);

#endif

