/** \cond 0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <assert.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <frame.h>
#include "cJSON.h"
/** \endcond */

#include "upstream.h"
#include "l7server.h"
#include "pipeline_end.h"
#include "socket_end.h"
#include "util_time.h"
#include "util_log.h"
#include "util_misc.h"
#include "http_xff.h"

#define UPSTREAM_DEFAULT_TIMEOUT 3000
#define UPSTREAM_RECV_SIZE MSG_FRAME_DATA_MAX


/** 将ring_buffer的数据send到upstream_sd，直到没有数据或者写操作阻塞为止 */
int pipeline_upstream_send(struct pipeline_end_st *pipeline_end)
{
	struct streambuf_iov_st *buf;
	ssize_t len;
	int total = 0;
	int true=1;

	mylog(L_DEBUG, "Upstream send");

	while (streambuf_read_nb(pipeline_end->upstream_send_buf, &buf)==0) {
		len = send(pipeline_end->upstream_sd, buf->mem+buf->pos, buf->len, MSG_DONTWAIT);
		if (len<0 && errno==EAGAIN) {
			mylog(L_DEBUG, "Upstream send nonblock");
			streambuf_unread(pipeline_end->upstream_send_buf, buf);
			if (total > 0) {
				return total;
			}
			return -EAGAIN;	/* IO Blocked */
		}
		if (len<0) {
			mylog(L_ERR, "Upstream send failed, pe[%d]", pipeline_end->id);
			streambuf_iov_free(buf);
			return -EINVAL;
		}

		total += len;
		if (len < buf->len) {
			mylog(L_DEBUG, "Upstream partial send, pe[%d]", pipeline_end->id);
			buf->pos += len;
			buf->len -= len;
			streambuf_unread(pipeline_end->upstream_send_buf, buf);
			break;	/* Partial send */
		}
		mylog(L_DEBUG, "Sent %u bytes to upstream, pe[%d]", len, pipeline_end->id);
		/* Send OK */ 
		streambuf_iov_free(buf);
	}
	if (setsockopt(pipeline_end->upstream_sd, IPPROTO_TCP, TCP_NODELAY, &true, sizeof(true))< 0) {
		mylog(L_DEBUG, "Flushing upstream_sd by setting nodelay failed");
	}

	return total;	/* No more data for now */
}

/**
 *	return value:
 *	-EAGAIN: nonblock recv, need not to update timeout
 *	-EINVAL: receive failed
 *	-EPIPE:  upstream close
 *	-1:		 msg enqueue failed
 *	EAGAIN:	 nonblock recv, need to update timeout
 * */
int pipeline_upstream_recv(struct pipeline_end_st *pipeline_end)
{
	int ret, retcode=0;
	int flag = 0;
	internal_msg_t *brokedown_framebody;

	mylog(L_DEBUG, "Upstream read and send");
	
	brokedown_framebody = malloc(sizeof(*brokedown_framebody));
	if (brokedown_framebody == NULL) {
		mylog(L_ERR, "Malloc brokedown_framebody failed");
		return -EINVAL;
	}

	brokedown_framebody->msg_type = 0;
	brokedown_framebody->data_frame_body.flow_id = pipeline_end->id;
	brokedown_framebody->data_frame_body.data = malloc(32768);
	if (brokedown_framebody->data_frame_body.data == NULL) {
		mylog(L_ERR, "Malloc data_frame_body.data failed");
		free(brokedown_framebody);
		return -EINVAL;
	}

	while (1) {
		ret = recv(pipeline_end->upstream_sd, brokedown_framebody->data_frame_body.data, UPSTREAM_RECV_SIZE, MSG_DONTWAIT);
		if (ret<0 && errno==EAGAIN) {
			retcode = -EAGAIN;
			goto quit;
		} else if (ret<0) {
			mylog(L_ERR, "Pipeline upstream receive failed: %m, pe[%d]", pipeline_end->id);
			retcode = -EINVAL;
			goto quit;
		}
		if (ret==0) {
			mylog(L_DEBUG, "Pipeline upstream receive upstream close, pe[%d]", pipeline_end->id);
			retcode = -EPIPE;
			goto quit;
		}
		mylog(L_DEBUG, "Pipeline upstream receive %d data", ret);
		if (ret>0) {
			flag = 1;
			brokedown_framebody->data_frame_body.data_len = ret;
			ret = socket_end_msg_enqueue(pipeline_end->socket_end,
					FRAME_FLAG_MAKE(1, pipeline_end->crypt_flag, pipeline_end->zip_flag),
					brokedown_framebody, pipeline_end->id);
			if(ret==0) {
				continue;
			} else if (ret==EAGAIN) {
				retcode = -EAGAIN;
				goto quit;
			} else {
				retcode = -1;
				goto quit;
			}
		}
	}
quit:
	free(brokedown_framebody->data_frame_body.data);
	free(brokedown_framebody);
	if (retcode == -EAGAIN && flag) {
		return EAGAIN; /* need update timeout */
	}
	return retcode;
}

int pipeline_failure(struct pipeline_end_st *pipeline_end)
{
    internal_msg_t pl_failure;

    pl_failure.msg_type = 1;
    pl_failure.ctl_frame_body.code = CTL_PIPELINE_FAILURE;
    pl_failure.ctl_frame_body.arg.pipeline_failure.flow_id = pipeline_end->id;
    pl_failure.ctl_frame_body.arg.pipeline_failure.error_code = pipeline_end->error_code;

	pipeline_end->closed = 1;

	return socket_end_msg_enqueue(pipeline_end->socket_end, FRAME_FLAG_MAKE(1, pipeline_end->crypt_flag, pipeline_end->zip_flag), &pl_failure, pipeline_end->id);
}

int pipeline_close(struct pipeline_end_st *pipeline_end)
{
    internal_msg_t pl_close;

    pl_close.msg_type = 1;
    pl_close.ctl_frame_body.code = CTL_PIPELINE_CLOSE;
    pl_close.ctl_frame_body.arg.pipeline_close.flow_id = pipeline_end->id;

	pipeline_end->closed = 1;

	return socket_end_msg_enqueue(pipeline_end->socket_end, FRAME_FLAG_MAKE(1, pipeline_end->crypt_flag, pipeline_end->zip_flag), &pl_close, pipeline_end->id);
}

struct pipeline_end_st *pipeline_end_create(struct socket_end_st *socket_end, struct upstream_entry_st *upstream, int id)
{
	struct pipeline_end_st *mem;
	int f;

	mem = calloc(1, sizeof(*mem));
	if (unlikely(mem==NULL)) {
		return NULL;
	}
	mem->upstream_sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (mem->upstream_sd < 0) {
		mylog(L_ERR, "Create upstream sd failed");
		free(mem);
		return NULL;
	}
	mylog(L_DEBUG, "Create upstream sd %d", mem->upstream_sd);
	mem->upstream = upstream;

    f = fcntl(mem->upstream_sd, F_GETFL);
    if (unlikely(fcntl(mem->upstream_sd, F_SETFL, f|O_NONBLOCK)<0)) {
        mylog(L_ERR, "Can't set listen sd to nonblock mode: %m");
        close(mem->upstream_sd);
		free(mem);
        return NULL;
    }

	mem->socket_end = socket_end;
	mem->connect_pending = 1;
	mem->id = id;
	mem->prev_id = -1;
	mem->next_id = -1;
	mem->upstream = upstream;
	mem->connect_timeout = upstream->connect_timeout;
	mem->send_timeout = upstream->send_timeout;
	mem->recv_timeout = upstream->max_recv_timeout;

	mem->connect_delay = -1;
	mem->service_delay = -1;
	mem->upstream_alive = 1;

	mem->header_past = http_xff;

	mem->upstream_send_buf = streambuf_new(PE_BUF_HARD);
	if (unlikely(mem->upstream_send_buf == NULL)) {
		free(mem);
		return NULL;
	}

	mylog(L_DEBUG, "Pipeline end create pe[%d]", id);
	return  mem;
}

int pipeline_try_connect(struct pipeline_end_st *pipeline_end)
{
    int ret, true=1;

    ret = connect(pipeline_end->upstream_sd, (void*)&pipeline_end->upstream->addr, sizeof(struct sockaddr_in));

    if (ret<0 && (errno==EINPROGRESS || errno==EALREADY)) {
        pipeline_end->connect_pending = 1;
		if (pipeline_end->connect_start==0) {
			pipeline_end->connect_start = systimestamp_ms();
		}
		return -EINPROGRESS;
    } else if (ret<0) {
		mylog(L_ERR, "Connect to upstream failed: (%d)%m, pe[%d]", errno, pipeline_end->id);
        pipeline_end->connect_pending = 0;
		pipeline_end->upstream_alive = 0;
		if (pipeline_end->connect_start==0) {
			pipeline_end->connect_delay = 0;
		} else {
			pipeline_end->connect_delay = systimestamp_ms() - pipeline_end->connect_start;
		}
        return -EINVAL;
    } else {	/* Connect success */
        pipeline_end->connect_pending = 0;
		
		if (setsockopt(pipeline_end->upstream_sd, IPPROTO_TCP, TCP_CORK, &true, sizeof(true))<0) {
			mylog(L_ERR, "Set upstream sd cork failed");
		}
		if (pipeline_end->connect_start==0) {	// So lucky!
			pipeline_end->connect_delay = 0;
		} else {
			pipeline_end->connect_delay = systimestamp_ms() - pipeline_end->connect_start;
		}
		return 0;
    }
}

void pipeline_end_destroy(struct pipeline_end_st *pipeline_end)
{
	mylog(L_DEBUG, "Pipeline end destroy pe[%d]", pipeline_end->id);
	streambuf_delete(pipeline_end->upstream_send_buf);
	close(pipeline_end->upstream_sd);
	free(pipeline_end);
}

cJSON *pipeline_end_serialize(const struct pipeline_end_st *pe)
{
	cJSON *result;

	result = cJSON_CreateObject();

	cJSON_AddNumberToObject(result, "id", pe->id);
	cJSON_AddNumberToObject(result, "UpstreamSocket", pe->upstream_sd);
	cJSON_AddNumberToObject(result, "SendBuffer", streambuf_nr_bytes(pe->upstream_send_buf));
	cJSON_AddNumberToObject(result, "ConnectPending", pe->connect_pending);
	cJSON_AddNumberToObject(result, "ZipFlag", pe->zip_flag);
	cJSON_AddNumberToObject(result, "CryptFlag", pe->crypt_flag);
	return result;
}

