#ifndef CONTEXT_H
#define CONTEXT_H

#include <stdint.h>
#include <weibo_socket.h>

#define	HASHKEYSIZE	64

struct wsocket_context_st {
	char hashkey[HASHKEYSIZE];
	int pipeline_id;
	int prev_id;
	int next_id;
	int local_flag;
	int peer_flag;
	int timeout;
	callback_t cb;
	struct wsocket_stat_st stat;
	size_t data_len;
	uint8_t *data;
};

#endif

