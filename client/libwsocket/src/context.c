/** \cond 0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
/** \endcond */

#include "context.h"

wsocket_context_t *wsocket_context_new(void)
{
	struct wsocket_context_st *context;

	context = calloc(sizeof(*context), 1);
	if(context == NULL) {
		return NULL;
	}
	context->pipeline_id = -1;
	context->data_len = 0;
	context->data = NULL;
	context->stat.send_bytes = 0;
	context->stat.recv_bytes = 0;
	context->stat.state = STATE_NOTOPEN;

	return context;
}

void wsocket_context_delete(wsocket_context_t *p)
{
	struct wsocket_context_st *context=p;
	if(context->data != NULL) {
		free(context->data);
		context->data = NULL;
	}
	free(context);
}

int wsocket_context_set_hashkey(wsocket_context_t *p,  const void *hashkey, size_t hashkey_len)
{
	struct wsocket_context_st *context=p;
	if(context->stat.state == STATE_INPROGRESS) {
		return -EINVAL;
	}
	memset(context->hashkey, 0, HASHKEYSIZE);
	memcpy(context->hashkey, hashkey, (hashkey_len > HASHKEYSIZE ? HASHKEYSIZE : hashkey_len));
	return 0;
}


int wsocket_context_set_data(wsocket_context_t *p,  const void *data, size_t size)
{
	struct wsocket_context_st *context=p;
	if(context->stat.state == STATE_INPROGRESS) {
		return -EINVAL;
	}
	if(context->data != NULL) {
		return -EAGAIN;
	}

	context->data = malloc(size);
	if(context->data == NULL) {
		return -EINVAL;
	}
	context->data_len = size;
	memcpy(context->data, (uint8_t *)data, size);
	return 0;
}

int wsocket_context_set_flag(wsocket_context_t *p, int local, int peer)
{
	struct wsocket_context_st *context=p;
	context->local_flag = local;
	context->peer_flag = peer;
	return 0;
}

int wsocket_context_set_recv_timeout(wsocket_context_t *p, int timeout)
{
	struct wsocket_context_st *context=p;
	if(context->stat.state == STATE_INPROGRESS) {
		return -EINVAL;
	}
	context->timeout = timeout;
	return 0;
}

int wsocket_context_set_callback(wsocket_context_t *p, callback_t *cb)
{
	struct wsocket_context_st *context=p;
	if(context->stat.state == STATE_INPROGRESS) {
		return -EINVAL;
	}
	memcpy(&context->cb, cb, sizeof(callback_t));
	return 0;
}

