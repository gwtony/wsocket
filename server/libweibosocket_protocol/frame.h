#ifndef FRAME_H
#define FRAME_H

#include "my_crypt.h"
#include "protocol.h"

#define MSG_DATA_TYPE 0
#define MSG_CTL_TYPE 1

#define	MSG_FRAME_MAX	2048
#define MSG_FRAME_BODY_MAX (MSG_FRAME_MAX-sizeof(struct frame_st))
#define MSG_FRAME_DATA_MAX (MSG_FRAME_BODY_MAX-sizeof(internal_msg_t))
#define TIMEOUT_NOLIMIT 65535

struct internal_frame_st { 
	int frame_flags;
	int frame_body_len;
	uint8_t *frame_body; 
};

struct internal_body_data_st {
	int flow_id;
	int data_len;
	uint8_t *data; 
};

struct internal_ctl_socket_cert_st {
	int crt_len;
	uint8_t *crt_bin;
};

struct internal_ctl_socket_key_sync_st {
	uint32_t crc32;			/* crc32 of shared_key */
	int encrypted_shared_key_len;
	uint8_t *encrypted_shared_key;
};

struct internal_ctl_pipeline_open_st {
	int flow_id; 
	int max_delay_in_ms;
	int	reply_frame_flags;
	int upstream_recvtimeo_ms;
	int data_len;
	uint8_t *data;
};

struct internal_ctl_pipeline_failure_st {
	int flow_id;
	uint8_t error_code;
};

struct internal_ctl_pipeline_close_st {
	int flow_id;
};

typedef struct {
	int msg_type;	// 0:data; 1:ctl
	union {
		struct internal_body_data_st data_frame_body;
		struct {
			int code;
			union {
				struct internal_ctl_socket_cert_st		socket_cert;
				struct internal_ctl_socket_key_sync_st	socket_key_sync;
				struct internal_ctl_pipeline_open_st	pipeline_open;
				struct internal_ctl_pipeline_failure_st	pipeline_failure;
				struct internal_ctl_pipeline_close_st	pipeline_close;
			} arg;
		} ctl_frame_body;
	};
} internal_msg_t;

int frame_decode(internal_msg_t *dstptr, struct frame_st *frame, uint8_t sharedkey[SHAREDKEY_BYTESIZE], uint8_t *chunk, size_t size);
ssize_t frame_encode(struct frame_st *dstptr, size_t size, internal_msg_t *frame_body, int frame_flags, uint8_t sharedkey[SHAREDKEY_BYTESIZE]);

#endif
