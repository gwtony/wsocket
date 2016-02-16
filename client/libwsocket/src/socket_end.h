#ifndef SOCKET_END_H
#define SOCKET_END_H

/** \cond 0 */
#include <syslog.h>
#include <pthread.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/blowfish.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <zlib.h>
/** \endcond */

#include "context.h"
#include "util_streambuf.h"
#include <weibo_socket.h>
#include <protocol.h>
#include <frame.h>

#define SE_BUF_SOFT (512*1024*10)
#define SE_BUF_HARD (1024*1024*10)
#define PIPELINE_ARR_SIZE 2048

enum {
	SOCKET_RECV_STATE_LEN=0,
	SOCKET_RECV_STATE_TAIL=1,
};

enum {
	SHAREDKEY_STATE_CERT_EMPTY=0,
	SHAREDKEY_STATE_CERT_REQ=1,
	SHAREDKEY_STATE_CERT_LOADED=2,
	SHAREDKEY_STATE_CERT_FAILURE=3,
	SHAREDKEY_STATE_KEY_SYNC=4,
	SHAREDKEY_STATE_KEY_OK=5,
	SHAREDKEY_STATE_KEY_REJ=6,
};

struct socket_end_st {
	int fd;						// Must be the first element !!
	char hashkey[HASHKEYSIZE];	// Must be the second element !!
	int connclosed;
	int keepalive;

	int id;
	int prev_id;
	int next_id;

	X509 *cert;
	int his_cert;
	int	sharedkey_state;
	pthread_cond_t cond_key_state;
	uint8_t sharedkey[SHAREDKEY_BYTESIZE];
	streambuf_t *send_buffer;

	int recv_state;
	uint16_t buf_len;
	int buf_len_pos;
	char *buf_tail;
	int buf_tail_pos;

	int pipeline_nextid;
	size_t pipeline_num;
	struct wsocket_context_st **pipeline_end;
	int pipeline_1;
	pthread_mutex_t mut;
};

int my_atexit(void (*function)(void));
void *thr_poll(void *p);
struct socket_end_st *socket_end_new(void);
int socket_end_delete(struct socket_end_st *);

void socket_end_recv_cb(struct socket_end_st *se);
void socket_end_send_cb(struct socket_end_st *se);
void socket_end_hup_cb(struct socket_end_st *se);

int socket_end_append_pipeline(struct socket_end_st *se, struct wsocket_context_st *c);
int socket_end_remove_pipeline(struct socket_end_st *se, int pipeline_id);

int socket_end_open_pipeline(struct socket_end_st *se, struct wsocket_context_st *c);
int socket_end_close_pipeline(struct socket_end_st *se, struct wsocket_context_st *c);
int socket_end_send_data(struct socket_end_st *se, struct wsocket_context_st *c, const void *data, size_t data_len);

int socket_end_load_and_sync_key(struct socket_end_st *se);
int socket_end_cert_req(struct socket_end_st *se);
int socket_end_key_sync(struct socket_end_st *se);


enum log_prio {
	L_MINVALUE = LOG_ERR,

	L_ERR = LOG_ERR,
	L_NOTICE = LOG_NOTICE,
	L_WARNING = LOG_WARNING,
	L_INFO = LOG_INFO,
	L_DEBUG = LOG_DEBUG,

	L_MAXVALUE = LOG_DEBUG,
};

#ifndef RELEASE_BUILDING
static int log_base_level_ = L_ERR;
#define mylog(level_, format_, ...) do{if(level_<=log_base_level_){fprintf(stderr, format_, ##__VA_ARGS__);}}while(0)
#else
#define mylog(level_, format_, ...) do{}while(0)
#endif


#endif

