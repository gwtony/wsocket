#ifndef SOCKET_END_H
#define SOCKET_END_H

/** \cond 0 */
#include <protocol.h>
#include <frame.h>
/** \endcond */

#include "util_streambuf.h"
#include "pipeline_end.h"

enum {
	SOCKET_RECV_STATE_LEN=1,
	SOCKET_RECV_STATE_TAIL,
};

#define	CONCURRENT_UNDERLIMIT	1024
#define	CONCURRENT_UPPERLIMIT	102400

#define CLIENT_HOST_STR 16

struct socket_end_st {
	int id;
	char client_str[CLIENT_HOST_STR];
	unsigned short client_port;

	uint8_t shared_key[SHAREDKEY_BYTESIZE];
	int shared_key_flag;

	streambuf_t *send_buffer;

	int socket;
	int recv_timeout;
	int send_timeout;
	time_t timeout_abs_ms; /** << socket end timeout */

	time_t min_timeout_abs_ms; /** <<  min timeout of socket end and all pipelines */

	int recv_state;
	uint16_t buf_len;
	int buf_len_pos;
	char *buf_tail;
	int buf_tail_pos;

	struct pipeline_end_st **pipeline_end;
	size_t pipeline_arr_size;
	size_t pipeline_nr;
	int pipeline_1;
	int send_pending_count;
};

struct socket_end_st *socket_end_new(int sd);
int socket_end_delete(struct socket_end_st *);

/** Send an internal message via socket_end.
	\param s Socket end address.
	\param flag Sending compress and crypt flags.
	\param m internal message.
	\return Status code, 0=OK, EAGAIN=should not recv, ENOMEM=send failed. */
int socket_end_msg_enqueue(struct socket_end_st *s, int flag, internal_msg_t *m, int plid);

void *thr_socket_end_engine(void *p);
void *thr_socket_end_accepter(void *p);

cJSON *socket_end_serialize(struct socket_end_st *);

#endif

