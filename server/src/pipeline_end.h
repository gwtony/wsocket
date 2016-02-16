#ifndef PIPELINE_END_H
#define PIPELINE_END_H

#include "cJSON.h"
#include "upstream.h"
#include "util_streambuf.h"

#define PE_BUF_HARD (1024*1024) 

struct socket_end_st;

struct pipeline_end_st {
	struct socket_end_st *socket_end;
	int id;
	int prev_id, next_id;

	int upstream_sd;
	struct upstream_entry_st *upstream;
	int upstream_sd_events_save;
	time_t connect_start, connect_delay;
	time_t service_start, service_delay;
	int upstream_alive;

	int connect_pending;

	time_t connect_timeout;
	time_t send_timeout;
	time_t recv_timeout;

	time_t timeout_abs_ms;
	time_t connect_timeout_abs_ms;
	time_t send_timeout_abs_ms;
	time_t recv_timeout_abs_ms;
	streambuf_t *upstream_send_buf;

	struct streambuf_iov_st *iov_recv_pending;
	struct streambuf_iov_st *iov_send_pending;

	int zip_flag;
	int crypt_flag;
	int closed;
	int header_past;

	uint8_t error_code;
};

struct pipeline_end_st *pipeline_end_create(struct socket_end_st *, struct upstream_entry_st *, int id);
void pipeline_end_destroy(struct pipeline_end_st *pipeline_end);

int pipeline_try_connect(struct pipeline_end_st *pipeline_end);
int pipeline_upstream_recv(struct pipeline_end_st *pipeline_end);
int pipeline_upstream_send(struct pipeline_end_st *pipeline_end);

int pipeline_failure(struct pipeline_end_st *pipeline_end);
int pipeline_close(struct pipeline_end_st *pipeline_end);

cJSON *pipeline_end_serialize(const struct pipeline_end_st *pe);

#endif

