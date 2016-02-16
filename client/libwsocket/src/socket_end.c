/** \cond 0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
/** \endcond */

#include "util_time.h"
#include "socket_end.h"

#ifndef PTHREAD_MUTEX_RECURSIVE
#define PTHREAD_MUTEX_RECURSIVE PTHREAD_MUTEX_RECURSIVE_NP
#endif

static struct sockaddr *get_server_addr(void)
{
	int error;
	struct addrinfo hint;
	struct addrinfo *aihead;
	const struct addrinfo *ai;
	struct sockaddr *addr=NULL;

	hint.ai_flags = AI_CANONNAME;
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_addrlen = 0;
	hint.ai_canonname = NULL;
	hint.ai_addr = NULL;
	hint.ai_next = NULL;

	error = getaddrinfo(getenv("WSOCKET_SERVER"), getenv("WSOCKET_PORT"), &hint, &aihead);
	if(error !=0) {
		mylog(L_ERR, "getaddrinfo() error:%s.\n", gai_strerror(error));
		return NULL;
	}

	for(ai=aihead;ai!=NULL;ai=ai->ai_next) {
		if(ai->ai_addr != NULL) {
			addr = malloc(ai->ai_addrlen);
			memcpy(addr, ai->ai_addr, ai->ai_addrlen);
			break;
		}
	}

	freeaddrinfo(aihead);
	return addr;
}

static int connect_server(void)
{
	int sd,f,flg;
	struct sockaddr *addr;

	sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(sd < 0) {
		mylog(L_ERR, "socket() error:%s.\n", strerror(errno));
		return -1;
	}

	flg=1;
	setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &flg, sizeof(flg));
	addr = get_server_addr();
	if(addr == NULL) {
		mylog(L_ERR, "get_server_addr() error:%s.\n", strerror(errno));
		close(sd);
		return -1;
	}

	if(connect(sd, addr, sizeof(struct sockaddr)) < 0) {
		mylog(L_ERR, "connect() error:%s.\n", strerror(errno));
		close(sd);
		free(addr);
		return -1;
	}
	free(addr);

	f = fcntl(sd, F_GETFL);
	if(fcntl(sd, F_SETFL, f|O_NONBLOCK)<0) {
		mylog(L_ERR, "Can't set sd to nonblock mode:%s.\n", strerror(errno));
		close(sd);
		return -1;
	}

	return sd;
}

static int save_x509(unsigned char *crt_bin, size_t crt_len)
{
	int fp;

	fp = open(getenv("WSOCKET_CERT_SERVER"), O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if(fp < 0) {
		mylog(L_ERR, "Open server cert error:%s.\n", getenv("WSOCKET_CERT_SERVER"));
		return -1;
	}

	if(write(fp, crt_bin, crt_len) != crt_len) {
		mylog(L_ERR, "Write server cert to file error.\n");
		close(fp);
		return -1;
	}
	close(fp);
	return 0;
}

static int load_and_verify_x509(struct socket_end_st *se)
{
	X509 *ca;

	se->cert = load_x509(getenv("WSOCKET_CERT_SERVER"));
	if(se->cert == NULL) {
		mylog(L_ERR, "Can't load server cert:%s.\n", getenv("WSOCKET_CERT_SERVER"));
		return -1;
	}

	ca = load_x509(getenv("WSOCKET_CERT_CA"));
	if(ca == NULL) {
		X509_free(se->cert);
		se->cert = NULL;
		mylog(L_ERR, "Can't load CA cert:%s.\n", getenv("WSOCKET_CERT_CA"));
		return -1;
	}
	if(verify_cert(se->cert, ca) != 0) {
		X509_free(se->cert);
		se->cert = NULL;
		X509_free(ca);
		ca = NULL;
		mylog(L_ERR, "Server cert file verifying error.\n");
		return -1;
	}
	X509_free(ca);

	return 0;
}

static int socket_end_msg_enqueue(struct socket_end_st *se, int flag, internal_msg_t *msg, size_t msg_size) {
	ssize_t size;
	int ret,retcode = -EINVAL;
	struct frame_st *dst = NULL;
	struct streambuf_iov_st *iov = NULL;

	dst = malloc(sizeof(struct frame_st) + msg_size);
	if (dst == NULL) {
		goto error;
	}
	size = frame_encode(dst, msg_size, msg, flag, se->sharedkey);
	if(size <= 0) {
		mylog(L_ERR, "frame_encode() error:%s.\n", strerror(errno));
		goto error;
	}

	iov = streambuf_iov_construct(dst, size);
	if(iov == NULL) {
		mylog(L_ERR, "streambuf_iov_construct() error:%s.\n", strerror(errno));
		goto error;
	}
	iov->len = size;
	iov->pos = 0;

	ret = streambuf_write_nb(se->send_buffer, iov);
	if(ret == 0 || ret==EAGAIN) {
		retcode = size;
	} else if(ret==ENOMEM) {
		mylog(L_ERR, "Send bufffer is full:%s.\n", strerror(errno));
		retcode = -EAGAIN;
		goto error;
	} else {
		mylog(L_ERR, "Send bufffer write failed:%s.\n", strerror(errno));
		retcode = -EINVAL;
	}
	return retcode;

error:
	if(iov) {
		free(iov);
		iov = NULL;
	}
	if(dst) {
		free(dst);
		dst = NULL;
	}

	return retcode;
}

static void socket_end_protocol(struct socket_end_st *se)
{
	char *frame_buf;
	int plid, error_code, ret;
	size_t body_len;
	internal_msg_t body; /* Broken down frame body */
	struct wsocket_context_st *ple;
	uint8_t *chunk = NULL;

	chunk = malloc(MSG_FRAME_MAX);
	if(chunk == NULL) {
		mylog(L_ERR, "Allocate decode chunk buf failed, se[%d].\n", se->id);
		return;
	}

	body_len = ntohs(se->buf_len);
	frame_buf = malloc(body_len + 2); /* 2 is sizeof(body_len) */

	/* Copy body_len to buf */
	memcpy(frame_buf, &se->buf_len, 2);
	/* Copy body to buf */
	memcpy(frame_buf+2, se->buf_tail, body_len);

	ret = frame_decode(&body, (struct frame_st *)frame_buf, se->sharedkey, chunk, MSG_FRAME_MAX);
	free(frame_buf);
	frame_buf = NULL;
	if(ret < 0) {
		mylog(L_ERR, "Unknown protocol, se[%d].\n", se->id);
		goto error;
	}

	if(body.msg_type == 0) { /* Data frame */
		plid = body.data_frame_body.flow_id;
		pthread_mutex_lock(&se->mut);
		ple = se->pipeline_end[plid];
		pthread_mutex_unlock(&se->mut);
		if(ple == NULL) {
			mylog(L_ERR, "pipeline[%d] data unknown flowid(%d).\n", plid, plid);
		} else {
			ple->stat.recv_bytes += body.data_frame_body.data_len;
			ple->cb.recv_cb(ple->cb.recv_cb_arg1, body.data_frame_body.data, body.data_frame_body.data_len);
		}
	} else if(body.msg_type) { /* Control frame */
		switch(body.ctl_frame_body.code) {
			case CTL_PIPELINE_CLOSE:
				plid = body.ctl_frame_body.arg.pipeline_close.flow_id;
				pthread_mutex_lock(&se->mut);
				ple = se->pipeline_end[plid];
				if(ple == NULL) {
					pthread_mutex_unlock(&se->mut);
					mylog(L_ERR, "pipeline[%d] close unknown flowid(%d).\n", plid, plid);
				} else {
					socket_end_remove_pipeline(se, plid);
					ple->stat.state = STATE_CLOSED;
					pthread_mutex_unlock(&se->mut);
					ple->cb.eof_cb(ple->cb.eof_cb_arg1, NULL, 0);
				}
				break;
			case CTL_PIPELINE_FAILURE:
				plid = body.ctl_frame_body.arg.pipeline_failure.flow_id;
				pthread_mutex_lock(&se->mut);
				ple = se->pipeline_end[plid];
				if(ple == NULL) {
					pthread_mutex_unlock(&se->mut);
					mylog(L_ERR, "pipeline[%d] failure unknown flowid(%d).\n", plid, plid);
				} else {
					socket_end_remove_pipeline(se, plid);
					switch(body.ctl_frame_body.arg.pipeline_failure.error_code) {
						case PIPELINE_FAILURE_CONNECT_FAILED:
							ple->stat.state = STATE_FAILED;
							error_code = ENOTCONN;
							mylog(L_ERR, "pipeline[%d] upstream connect failed.\n", plid);
						break;
						case PIPELINE_FAILURE_RECV_FAILED:
							ple->stat.state = STATE_FAILED;
							error_code = EREMOTEIO;
							mylog(L_ERR, "pipeline[%d] upstream recv failed.\n", plid);
						break;
						case PIPELINE_FAILURE_SEND_FAILED:
							ple->stat.state = STATE_FAILED;
							error_code = EREMOTEIO;
							mylog(L_ERR, "pipeline[%d] upstream send failed.\n", plid);
						break;
						case PIPELINE_FAILURE_TIMEOUT:
							ple->stat.state = STATE_TIMEOUT;
							error_code = ETIME;
							mylog(L_ERR, "pipeline[%d] upstream timeout.\n", plid);
						break;
					}
					pthread_mutex_unlock(&se->mut);
					ple->cb.except_cb(ple->cb.except_cb_arg1, error_code);
				}
				break;
			case CTL_SOCKET_CERT:
				ret = save_x509(body.ctl_frame_body.arg.socket_cert.crt_bin, body.ctl_frame_body.arg.socket_cert.crt_len);
				if(ret == 0) {
					ret = load_and_verify_x509(se);
				}
				pthread_mutex_lock(&se->mut);
				if(ret < 0) {
					se->sharedkey_state = SHAREDKEY_STATE_CERT_FAILURE;
				} else {
					se->sharedkey_state = SHAREDKEY_STATE_CERT_LOADED;
					socket_end_load_and_sync_key(se);
				}
				pthread_cond_broadcast(&se->cond_key_state);
				pthread_mutex_unlock(&se->mut);
				break;
			case CTL_SOCKET_KEY_OK:
				pthread_mutex_lock(&se->mut);
				se->sharedkey_state = SHAREDKEY_STATE_KEY_OK;
				pthread_cond_broadcast(&se->cond_key_state);
				pthread_mutex_unlock(&se->mut);
				break;
			case CTL_SOCKET_KEY_REJ:
				/* if history cert expire need to reload and sync the key agian. */
				pthread_mutex_lock(&se->mut);
				if(se->his_cert) {
					mylog(L_DEBUG, "History cert expire, reload cert and sync key.\n");
					se->sharedkey_state = SHAREDKEY_STATE_CERT_EMPTY;
					socket_end_load_and_sync_key(se);
				} else {
					se->sharedkey_state = SHAREDKEY_STATE_KEY_REJ;
					mylog(L_ERR, "Sync the key failed.\n");
				}
				pthread_cond_broadcast(&se->cond_key_state);
				pthread_mutex_unlock(&se->mut);
				break;
		}
	}
error:
	free(chunk);
	chunk = NULL;
}

struct socket_end_st *socket_end_new(void) {
	struct socket_end_st *se;

	se = malloc(sizeof(*se));
	if(se == NULL) {
		return NULL;
	}

	se->fd = connect_server();
	if(se->fd < 0) {
		free(se);
		return NULL;
	}

	se->send_buffer = streambuf_new(SE_BUF_SOFT, SE_BUF_HARD);
	if(se->send_buffer == NULL) {
		close(se->fd);
		free(se);
		return NULL;
	}

	se->pipeline_end = calloc(1, PIPELINE_ARR_SIZE * sizeof(struct wsocket_context_st*));
	if(se->pipeline_end == NULL) {
		streambuf_delete(se->send_buffer);
		se->send_buffer = NULL;
		close(se->fd);
		free(se);
		return NULL;
	}

	se->recv_state = SOCKET_RECV_STATE_LEN;
	se->buf_len = 0;
	se->buf_len_pos = 0;
	se->buf_tail = NULL;
	se->buf_tail_pos = 0;
	se->pipeline_nextid = 1;
	se->pipeline_1 = -1;
	se->pipeline_num = 0;
	se->id = -1;
	se->prev_id = -1;
	se->next_id = -1;
	se->connclosed = 0;
	se->keepalive = getenv("WSOCKET_KEEPALIVE") == NULL ? 0 : strtol(getenv("WSOCKET_KEEPALIVE"), NULL, 10);

	if(load_and_verify_x509(se) == 0) {
		se->his_cert = 1;
		se->sharedkey_state = SHAREDKEY_STATE_CERT_LOADED;
	} else {
		se->cert = NULL;
		se->his_cert = 0;
		se->sharedkey_state = SHAREDKEY_STATE_CERT_EMPTY;
	}
	memset(se->hashkey, 0, HASHKEYSIZE);
	memcpy(se->sharedkey, NO_SHAREDKEY, SHAREDKEY_BYTESIZE);

	pthread_mutexattr_t ma;
	pthread_mutexattr_init(&ma);
	pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&se->mut, &ma);
	pthread_cond_init(&se->cond_key_state, NULL);
	pthread_mutexattr_destroy(&ma);

	return se;
}

int socket_end_delete(struct socket_end_st *se) {
	if(se == NULL) {
		return 0;
	}

	pthread_mutex_lock(&se->mut);
	if(se->fd) {
		close(se->fd);
	}
	if(se->pipeline_end != NULL) {
		free(se->pipeline_end);
		se->pipeline_end = NULL;
	}
	if(se->send_buffer != NULL) {
		streambuf_delete(se->send_buffer);
		se->send_buffer = NULL;
	}
	if(se->cert != NULL) {
		X509_free(se->cert);
		se->cert = NULL;
	}
	if(se->buf_tail != NULL) {
		free(se->buf_tail);
		se->buf_tail = NULL;
	}
	se->id = -1;
	se->prev_id = -1;
	se->next_id = -1;
	pthread_mutex_unlock(&se->mut);

	pthread_mutex_destroy(&se->mut);
	pthread_cond_destroy(&se->cond_key_state);
	free(se);
	return 0;
}

#define	FRAMEMAX	65535
#define	RECVBUF		(FRAMEMAX*2)

void socket_end_recv_cb(struct socket_end_st *se)
{
	uint16_t framemax = FRAMEMAX;
	static char buf[RECVBUF];
	int pos, size;

	pos = 0;
	size = recv(se->fd, buf, RECVBUF, MSG_DONTWAIT);
	if(size < 0) {
		mylog(L_ERR, "recv() error:%s.\n", strerror(errno));
		socket_end_hup_cb(se);
		return;
	} else if(size == 0) {
		mylog(L_ERR, "Unexpected eof:%s.\n",  strerror(errno));
		socket_end_hup_cb(se);
		return;
	} else {
		while(pos<size) {
			switch(se->recv_state) {
				case SOCKET_RECV_STATE_LEN:
					if(se->buf_len_pos==0 && size-pos>=2) {
						memcpy(&se->buf_len, buf+pos, 2);
						if(ntohs(se->buf_len)>framemax) {
							mylog(L_ERR, "Frame size seems bad:%d.\n", ntohs(se->buf_len));
							socket_end_hup_cb(se);
							return;
						}
						pos+=2;
						se->buf_tail = malloc(ntohs(se->buf_len));
						se->buf_tail_pos = 0;
						se->recv_state = SOCKET_RECV_STATE_TAIL;
					} else if(se->buf_len_pos==0 && size-pos==1) {
						memcpy(&se->buf_len, buf+pos, 1);
						pos+=1;
						se->buf_len_pos=1;
					} else if(se->buf_len_pos==1) {
						memcpy(((char*)(&se->buf_len))+1, buf+pos, 1);
						pos+=1;
						if(ntohs(se->buf_len)>framemax) {
							mylog(L_ERR, "Frame size seems bad:%d.\n", ntohs(se->buf_len));
							socket_end_hup_cb(se);
							return;
						}
						se->buf_tail = malloc(ntohs(se->buf_len));
						se->buf_tail_pos = 0;
						se->recv_state = SOCKET_RECV_STATE_TAIL;
					} else {
						mylog(L_ERR, "Unexpected frame size:%d.\n", ntohs(se->buf_len));
						socket_end_hup_cb(se);
						return;
					}
					break;
				case SOCKET_RECV_STATE_TAIL:
					if(size-pos >= ntohs(se->buf_len)-se->buf_tail_pos) {
						memcpy(se->buf_tail+se->buf_tail_pos, buf+pos, ntohs(se->buf_len)-se->buf_tail_pos);
						pos+=ntohs(se->buf_len)-se->buf_tail_pos;
						socket_end_protocol(se);
						free(se->buf_tail);
						se->buf_tail = NULL;
						se->buf_len_pos = 0;
						se->recv_state = SOCKET_RECV_STATE_LEN;
					} else {
						memcpy(se->buf_tail+se->buf_tail_pos, buf+pos, size-pos);
						se->buf_tail_pos += size-pos;
						//pos+=ntohs(se->buf_len)-se->buf_tail_pos;
						pos+=size-pos;
					}
					break;
				default:
					mylog(L_ERR, "Unknown recv state(%d).\n", se->recv_state);
					socket_end_hup_cb(se);
					return;
					break;
			}
		}
	}
}

void socket_end_send_cb(struct socket_end_st *se)
{
	int i, next;
	ssize_t ret;
	struct wsocket_context_st *ple;

	ret = streambuf_send(se->fd, se->send_buffer);
	if(ret == -EAGAIN) {
		mylog(L_DEBUG, "streambuf_send() again:%s.\n", strerror(-ret));
	} else if(ret < 0) {
		mylog(L_ERR, "streambuf_send() error:%s.\n", strerror(-ret));
		if(errno == ECONNABORTED || errno == ECONNREFUSED || errno == ECONNRESET) {
			socket_end_hup_cb(se);
		}
	} else {
		pthread_mutex_lock(&se->mut);
		for(i=se->pipeline_1; i!=-1; i=next) {
			ple = se->pipeline_end[i];
			next = ple->next_id;
			if(ple->cb.sendok_cb != NULL) {
				ple->cb.sendok_cb(ple->cb.sendok_cb_arg1);
			}
		}
		pthread_mutex_unlock(&se->mut);
	}
}

void socket_end_hup_cb(struct socket_end_st *se)
{
	int i, next,errno_tmp = errno;
	struct wsocket_context_st *ple;

	pthread_mutex_lock(&se->mut);
	se->connclosed = 1;
	if(se->sharedkey_state != SHAREDKEY_STATE_KEY_OK) {
		se->sharedkey_state = SHAREDKEY_STATE_KEY_REJ;
		pthread_cond_broadcast(&se->cond_key_state);
	}
	for(i=se->pipeline_1; i!=-1; i=next) {
		ple = se->pipeline_end[i];
		next = ple->next_id;
		ple->stat.state = STATE_FAILED;
		ple->stat.end_time = systimestamp_ms();
		ple->cb.except_cb(ple->cb.except_cb_arg1, errno_tmp);
	}
	pthread_mutex_unlock(&se->mut);
}

int socket_end_append_pipeline(struct socket_end_st *se, struct wsocket_context_st *c)
{
	int end;

	if(c->pipeline_id >= 0 && se->pipeline_end[c->pipeline_id] != NULL) {
		mylog(L_ERR, "pipeline[%d] append duplicate.\n", c->pipeline_id);
		return -EINVAL;
	}

	if(c->pipeline_id < 0) {
		end = se->pipeline_nextid;
		do {
			se->pipeline_nextid++;
			if(se->pipeline_nextid >= PIPELINE_ARR_SIZE) {
				se->pipeline_nextid = 1;
			}
			if(se->pipeline_nextid == end) {
				mylog(L_ERR, "Too many pipelines, limit:%d.\n", PIPELINE_ARR_SIZE);
				return -EINVAL;
			}
		} while(se->pipeline_end[se->pipeline_nextid] != NULL);
		c->pipeline_id = se->pipeline_nextid;
	}

	c->prev_id = -1;
	c->next_id = se->pipeline_1;
	if(se->pipeline_1 != -1) {
		se->pipeline_end[se->pipeline_1]->prev_id = c->pipeline_id;
	}

	se->pipeline_end[c->pipeline_id] = c;
	se->pipeline_1 = c->pipeline_id;
	se->pipeline_num++;
	mylog(L_DEBUG, "pipeline[%d] append success.\n", c->pipeline_id);
	return 0;
}

int socket_end_remove_pipeline(struct socket_end_st *se, int pipeline_id)
{
	struct wsocket_context_st *ple;

	if(se->pipeline_end == NULL || pipeline_id < 0 || se->pipeline_end[pipeline_id] == NULL) {
		mylog(L_ERR, "pipeline[%d] remove failed.\n", pipeline_id);
		return -EINVAL;
	}

	ple = se->pipeline_end[pipeline_id];
	if(ple->prev_id == -1 && ple->next_id == -1) {
		se->pipeline_1 = -1;
	} else if(ple->prev_id == -1) {
		se->pipeline_end[ple->next_id]->prev_id = -1;
		se->pipeline_1 = ple->next_id;
	} else if(ple->next_id == -1) {
		se->pipeline_end[ple->prev_id]->next_id = -1;
	} else {
		se->pipeline_end[ple->prev_id]->next_id = ple->next_id;
		se->pipeline_end[ple->next_id]->prev_id = ple->prev_id;
	}
	se->pipeline_end[ple->pipeline_id] = NULL;
	se->pipeline_num--;
	if(!se->keepalive && se->pipeline_num <= 0) {
		se->connclosed = 1;
		if(se->sharedkey_state != SHAREDKEY_STATE_KEY_OK) {
			se->sharedkey_state = SHAREDKEY_STATE_KEY_REJ;
			pthread_cond_broadcast(&se->cond_key_state);
		}
	}

	ple->pipeline_id = -1;
	ple->prev_id = -1;
	ple->next_id = -1;
	ple->stat.end_time = systimestamp_ms();
	mylog(L_DEBUG, "pipeline[%d] remove success.\n", pipeline_id);
	return 0;
}

int socket_end_open_pipeline(struct socket_end_st *se, struct wsocket_context_st *c)
{
	int size, retcode;
	internal_msg_t *msg;
	size_t msg_size;

	if(streambuf_write_wouldblock(se->send_buffer)) {
		return -EAGAIN;
	}

	if(socket_end_append_pipeline(se, c) < 0) {
		return -EINVAL;
	}

	msg = malloc(sizeof(internal_msg_t));
	msg->msg_type = 1;
	msg->ctl_frame_body.code = CTL_PIPELINE_OPEN;
	msg->ctl_frame_body.arg.pipeline_open.flow_id = c->pipeline_id;
	msg->ctl_frame_body.arg.pipeline_open.max_delay_in_ms = c->timeout;
	msg->ctl_frame_body.arg.pipeline_open.reply_frame_flags = c->peer_flag;
	msg->ctl_frame_body.arg.pipeline_open.upstream_recvtimeo_ms = c->timeout;

	if(c->data_len > MSG_FRAME_DATA_MAX) {
		msg->ctl_frame_body.arg.pipeline_open.data_len = 0;
		msg->ctl_frame_body.arg.pipeline_open.data = NULL;
		msg_size = sizeof(internal_msg_t);
	} else {
		msg->ctl_frame_body.arg.pipeline_open.data_len = c->data_len;
		msg->ctl_frame_body.arg.pipeline_open.data = c->data;
		msg_size = sizeof(internal_msg_t) + c->data_len;
	}

	c->stat.start_time = systimestamp_ms();
	size = socket_end_msg_enqueue(se, c->local_flag, msg, msg_size);
	if(size >= 0) {
		mylog(L_DEBUG, "pipeline[%d] open success.\n", c->pipeline_id);
		c->stat.state = STATE_INPROGRESS;
		c->stat.send_bytes = size;
		retcode = 0;
		if(c->data_len > MSG_FRAME_DATA_MAX) {
			retcode = socket_end_send_data(se, c, c->data, c->data_len);
			if(retcode < 0) {
                		socket_end_close_pipeline(se, c);
                		c->stat.state = STATE_FAILED;
			}
		}
	} else if(size == -EAGAIN) {
		mylog(L_DEBUG, "pipeline[%d] open again.\n", c->pipeline_id);
		socket_end_remove_pipeline(se, c->pipeline_id);
		retcode = -EAGAIN;
	} else {
		mylog(L_DEBUG, "pipeline[%d] open failed.\n", c->pipeline_id);
		socket_end_remove_pipeline(se, c->pipeline_id);
		c->stat.state = STATE_FAILED;
		retcode = -EINVAL;
	}

	if(msg != NULL) {
		free(msg);
		msg = NULL;
	}

	return retcode;
}

int socket_end_close_pipeline(struct socket_end_st *se, struct wsocket_context_st *c)
{
	int retcode;
	internal_msg_t *msg;

	msg = malloc(sizeof(internal_msg_t));
	msg->msg_type = 1;
	msg->ctl_frame_body.code = CTL_PIPELINE_CLOSE;
	msg->ctl_frame_body.arg.pipeline_close.flow_id = c->pipeline_id;

	retcode = socket_end_msg_enqueue(se, 0, msg, sizeof(internal_msg_t));
	if(retcode >= 0) {
		mylog(L_DEBUG, "pipeline[%d] close success.\n", c->pipeline_id);
		socket_end_remove_pipeline(se, c->pipeline_id);
		c->stat.state = STATE_CLOSED;
		retcode = 0;
	} else if(retcode == -EAGAIN) {
		mylog(L_DEBUG, "pipeline[%d] close again.\n", c->pipeline_id);
		retcode = -EAGAIN;
	} else {
		mylog(L_DEBUG, "pipeline[%d] close failed.\n", c->pipeline_id);
		retcode = -EINVAL;
	}

	if(msg != NULL) {
		free(msg);
		msg = NULL;
	}
	return retcode;
}

int socket_end_send_data(struct socket_end_st *se, struct wsocket_context_st *c, const void *data, size_t data_len)
{
	int size,pos=0,len=0;
	uint8_t *buf;
	internal_msg_t *msg;
	size_t msg_size;

	if(streambuf_write_wouldblock(se->send_buffer)) {
		return -EAGAIN;
	}

	while(pos < data_len) {
		len = (pos + MSG_FRAME_DATA_MAX) > data_len ? data_len - pos : MSG_FRAME_DATA_MAX;
		buf = malloc(len);
		if(buf == NULL) {
			mylog(L_ERR, "pipeline[%d] send data failed, %s.\n", c->pipeline_id, strerror(errno));
			return -EINVAL;
		}
		memcpy(buf, (uint8_t *)data+pos, len);

		msg = malloc(sizeof(internal_msg_t));
		if(msg == NULL) {
			free(buf);
			buf = NULL;
			mylog(L_ERR, "pipeline[%d] send data failed, %s.\n", c->pipeline_id, strerror(errno));
			return -EINVAL;
		}
		msg->msg_type = 0;
		msg->data_frame_body.flow_id = c->pipeline_id;
		msg->data_frame_body.data_len = len;
		msg->data_frame_body.data = buf;

		msg_size = sizeof(internal_msg_t) + len;
		size = socket_end_msg_enqueue(se, c->local_flag, msg, msg_size);
		free(msg);
		msg = NULL;
		free(buf);
		buf = NULL;

		if(size>=0) {
			mylog(L_DEBUG, "pipeline[%d] send data success(%d bytes).\n", c->pipeline_id, size);
			c->stat.send_bytes += size;
			pos += len;
		} else {
			mylog(L_DEBUG, "pipeline[%d] send data failed(%d bytes).\n", c->pipeline_id, size);
			return -EINVAL;
		}
	}
	return 0;
}

int socket_end_load_and_sync_key(struct socket_end_st *se)
{
	int ret=-EINVAL;

	switch(se->sharedkey_state) {
		case SHAREDKEY_STATE_CERT_EMPTY:
			if(socket_end_cert_req(se) >= 0) {
				se->sharedkey_state = SHAREDKEY_STATE_CERT_REQ;
				ret = -EAGAIN;
			} else {
				se->sharedkey_state = SHAREDKEY_STATE_CERT_FAILURE;
				mylog(L_ERR, "socket_end_cert_req() error:%s.\n", strerror(errno));
				ret = -EINVAL;
			}
			break;
		case SHAREDKEY_STATE_CERT_LOADED:
			if(socket_end_key_sync(se) >= 0) {
				se->sharedkey_state = SHAREDKEY_STATE_KEY_SYNC;
				ret = -EAGAIN;
			} else {
				se->sharedkey_state = SHAREDKEY_STATE_KEY_REJ;
				mylog(L_ERR, "socket_end_key_sync() error:%s.\n", strerror(errno));
				ret = -EINVAL;
			}
			break;
		case SHAREDKEY_STATE_CERT_FAILURE:
			mylog(L_DEBUG, "Download server cert failed.\n");
			ret = -EINVAL;
			break;
		case SHAREDKEY_STATE_KEY_REJ:
			mylog(L_DEBUG, "Sync key failed.\n");
			ret = -EINVAL;
			break;
		case SHAREDKEY_STATE_CERT_REQ:
		case SHAREDKEY_STATE_KEY_SYNC:
			ret = -EAGAIN;
		case SHAREDKEY_STATE_KEY_OK:
			ret = 0;
			break;
	}

	return ret;
}

int socket_end_cert_req(struct socket_end_st *se)
{
	int ret;
	internal_msg_t *msg;

	msg = malloc(sizeof(internal_msg_t));
	msg->msg_type = 1;
	msg->ctl_frame_body.code = CTL_SOCKET_CERT_REQ;

	ret = socket_end_msg_enqueue(se, 0, msg, sizeof(internal_msg_t));
	if(msg != NULL) {
		free(msg);
		msg = NULL;
	}
	return ret;
}

int socket_end_key_sync(struct socket_end_st *se)
{
	int ret;
	EVP_PKEY *pubkey=NULL;
	uint8_t cryptedkey[RSA_KEYSIZE];
	uint32_t crc32;
	internal_msg_t *msg;

	SSL_library_init();
	ERR_load_crypto_strings();

	pubkey = EVP_PKEY_IN_X509(se->cert);
	if(pubkey == NULL) {
		mylog(L_ERR, "EVP_PKEY_IN_X509() error:%s.\n", strerror(errno));
		return -1;
	}

	rand_sharedkey(se->sharedkey);
	if(RSA_public_encrypt(SHAREDKEY_BYTESIZE,
				se->sharedkey,
			   	cryptedkey,
			   	RSA_IN_EVP_PKEY(pubkey),
			   	RSA_PKCS1_PADDING)<0) {
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(pubkey);

		mylog(L_ERR, "RSA_public_encrypt() error:%s.\n", strerror(errno));
		return -errno;
	}

	crc32 = mycrc32(se->sharedkey, SHAREDKEY_BYTESIZE);

	msg = malloc(sizeof(internal_msg_t));
	msg->msg_type = 1;
	msg->ctl_frame_body.code = CTL_SOCKET_KEY_SYNC;
	msg->ctl_frame_body.arg.socket_key_sync.crc32 = crc32;
	msg->ctl_frame_body.arg.socket_key_sync.encrypted_shared_key_len = RSA_KEYSIZE;
	msg->ctl_frame_body.arg.socket_key_sync.encrypted_shared_key = cryptedkey;

	ret = socket_end_msg_enqueue(se, 0, msg, sizeof(internal_msg_t)+RSA_KEYSIZE);
	EVP_PKEY_free(pubkey);
	if(msg != NULL) {
		free(msg);
		msg = NULL;
	}
	return ret;
}

#ifdef UNIT_TEST
cJSON *socket_end_serialize(struct socket_end_st *se) {
	cJSON *result;

	result = cJSON_CreateObject();
	return result;
}

#endif

