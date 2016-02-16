#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <alloca.h>

#include "my_crypt.h"
#include "frame.h"

static int fill_internal_msg(internal_msg_t *dst, uint8_t *buf, int len, uint8_t *chunk, size_t size);

static ssize_t data_frame_body_encode(void *dstptr, const struct internal_body_data_st *datap)
{
	struct frame_body_data_st *dst = (struct frame_body_data_st *)dstptr;

	dst->type_id = htons((uint16_t)FRAME_DATA_TYPE_ID(datap->flow_id));

	memcpy(dst->data, datap->data, datap->data_len);

	return datap->data_len + 2;
}

int frame_decode(internal_msg_t *dstptr, struct frame_st *frame, uint8_t sharedkey[SHAREDKEY_BYTESIZE], uint8_t *chunk, size_t size)
{
	int len,ret = -1;
	uint8_t *plain_buf;
	int flags = (int)frame->frame_flags;

	int crypt_buf_size = (int)ntohs(frame->body_len) - 1; /* subtract frame_flags len */
	uint8_t *crypt_buf = (uint8_t *)frame->frame_body;
	int plain_buf_size = decrypt_frame_bufsize_hint(crypt_buf_size, flags);

	if (plain_buf_size > size) {
		return ret;
	}

	/* decrypt & decompress */
	plain_buf = alloca(plain_buf_size);
	if(plain_buf == NULL) {
		return ret;
	}
	len = decrypt_frame_body(plain_buf, plain_buf_size, crypt_buf, crypt_buf_size, flags, sharedkey);
	if(len == -ENOMEM) {
		return ret;
	}

	if (len >= 0) {
		ret = fill_internal_msg(dstptr, plain_buf, len, chunk, size);
	}

	return ret;
}

ssize_t frame_encode(struct frame_st *dstptr, size_t size, internal_msg_t *frame_body, int frame_flags, uint8_t sharedkey[SHAREDKEY_BYTESIZE])
{
	ssize_t len;
	size_t crypt_bufsize;
	uint8_t *crypt_buf = NULL, *buf = NULL;

	FRAME_VERSION_SET(frame_flags, 1);

	if (frame_body->msg_type == MSG_DATA_TYPE) {
		len = frame_body->data_frame_body.data_len + 2; //uint16_t
		if (len > size) {
			return -EBADMSG;
		}
		buf = alloca(len);
		if (buf == NULL) {
			return -ENOMEM;
		}

		len = data_frame_body_encode(buf, &frame_body->data_frame_body);
		if (len <= 0) {
			return -EBADMSG;
		}

	} else if (frame_body->msg_type == MSG_CTL_TYPE) {
		uint16_t opcode = (uint16_t)frame_body->ctl_frame_body.code;

		switch(frame_body->ctl_frame_body.code) {
			case CTL_SOCKET_CERT_REQ:
				len = 2; //uint16_t
				buf = alloca(len);
				if (buf == NULL) {
					return -ENOMEM;
				}

				struct frame_body_ctl_socket_cert_req_st *socket_cert_req = (struct frame_body_ctl_socket_cert_req_st *)buf;
				socket_cert_req->type_opcode = htons((uint16_t)FRAME_CTL_TYPE_OPCODE(opcode));

				break;
			case CTL_SOCKET_CERT:
				len = frame_body->ctl_frame_body.arg.socket_cert.crt_len + 2; //uint16_t
				if (len > size) {
					return -EBADMSG;
				}
				buf = alloca(len);
				if (buf == NULL) {
					return -ENOMEM;
				}

				struct frame_body_ctl_socket_cert_st *socket_cert = (struct frame_body_ctl_socket_cert_st *)buf;
				socket_cert->type_opcode = htons((uint16_t)FRAME_CTL_TYPE_OPCODE(opcode));
				memcpy(socket_cert->x509_certificate,
					frame_body->ctl_frame_body.arg.socket_cert.crt_bin,
					frame_body->ctl_frame_body.arg.socket_cert.crt_len);

				break;
			case CTL_SOCKET_KEY_SYNC:
				len = frame_body->ctl_frame_body.arg.socket_key_sync.encrypted_shared_key_len + 6; //uint16_t + uint32_t
				if (len > size) {
					return -EBADMSG;
				}
				buf = alloca(len);
				if (buf == NULL) {
					return -ENOMEM;
				}

				struct frame_body_ctl_socket_key_sync_st *socket_key_sync = (struct frame_body_ctl_socket_key_sync_st *)buf;
				socket_key_sync->type_opcode = htons((uint16_t)FRAME_CTL_TYPE_OPCODE(opcode));
				socket_key_sync->crc32 = htonl(frame_body->ctl_frame_body.arg.socket_key_sync.crc32);
				memcpy(socket_key_sync->encrypted_shared_key,
					frame_body->ctl_frame_body.arg.socket_key_sync.encrypted_shared_key,
					frame_body->ctl_frame_body.arg.socket_key_sync.encrypted_shared_key_len);

				break;
			case CTL_SOCKET_KEY_OK:
				len = 2; //uint16_t
				buf = alloca(len);
				if (buf == NULL) {
					return -ENOMEM;
				}

				struct frame_body_ctl_socket_key_ok_st *socket_key_ok = (struct frame_body_ctl_socket_key_ok_st *)buf;
				socket_key_ok->type_opcode = htons((uint16_t)FRAME_CTL_TYPE_OPCODE(opcode));

				break;
			case CTL_SOCKET_KEY_REJ:
				len = 2; //uint16_t
				buf = alloca(len);
				if (buf == NULL) {
					return -ENOMEM;
				}

				struct frame_body_ctl_socket_key_rej_st *socket_key_rej = (struct frame_body_ctl_socket_key_rej_st *)buf;
				socket_key_rej->type_opcode = htons((uint16_t)FRAME_CTL_TYPE_OPCODE(opcode));

				break;
			case CTL_PIPELINE_OPEN:
				len = frame_body->ctl_frame_body.arg.pipeline_open.data_len + sizeof(struct frame_body_ctl_pipeline_open_st);
				if (len > size) {
					return -EBADMSG;
				}
				buf = alloca(len);
				if (buf == NULL) {
					return -ENOMEM;
				}

				struct frame_body_ctl_pipeline_open_st *pipeline_open = (struct frame_body_ctl_pipeline_open_st *)buf;
				pipeline_open->type_opcode = htons((uint16_t)FRAME_CTL_TYPE_OPCODE(opcode));
				pipeline_open->pipeline_id = htons((uint16_t)frame_body->ctl_frame_body.arg.pipeline_open.flow_id);
				pipeline_open->max_delay_in_ms = htons((uint16_t)frame_body->ctl_frame_body.arg.pipeline_open.max_delay_in_ms);
				pipeline_open->reply_frame_flags = (uint8_t)frame_body->ctl_frame_body.arg.pipeline_open.reply_frame_flags;
				pipeline_open->upstream_recvtimeo_ms = htons(frame_body->ctl_frame_body.arg.pipeline_open.upstream_recvtimeo_ms);

				memcpy(pipeline_open->data,
					frame_body->ctl_frame_body.arg.pipeline_open.data,
					frame_body->ctl_frame_body.arg.pipeline_open.data_len);
				len = sizeof(*pipeline_open) + frame_body->ctl_frame_body.arg.pipeline_open.data_len;

				break;
			case CTL_PIPELINE_FAILURE:
				len = sizeof(struct frame_body_ctl_pipeline_failure_st);
				buf = alloca(len);
				if (buf == NULL) {
					return -ENOMEM;
				}

				struct frame_body_ctl_pipeline_failure_st *pipeline_failure = (struct frame_body_ctl_pipeline_failure_st *)buf;
				pipeline_failure->type_opcode = htons((uint16_t)FRAME_CTL_TYPE_OPCODE(opcode));
				pipeline_failure->pipeline_id = htons((uint16_t)frame_body->ctl_frame_body.arg.pipeline_failure.flow_id);
				pipeline_failure->error_code = frame_body->ctl_frame_body.arg.pipeline_failure.error_code;
				len = sizeof(*pipeline_failure);

				break;
			case CTL_PIPELINE_CLOSE:
				len = 4; //uint16_t + uint16_t
				buf = alloca(len);
				if (buf == NULL) {
					return -ENOMEM;
				}

				struct frame_body_ctl_pipeline_close_st *pipeline_close = (struct frame_body_ctl_pipeline_close_st *)buf;
				pipeline_close->type_opcode = htons((uint16_t)FRAME_CTL_TYPE_OPCODE(opcode));
				pipeline_close->pipeline_id = htons((uint16_t)frame_body->ctl_frame_body.arg.pipeline_close.flow_id);
				len = sizeof(*pipeline_close);

				break;
			default:
				return -EBADMSG;
		}
	} else {
		/* Unknown msg type */
		return -EBADMSG;
	}


	crypt_bufsize = encrypt_frame_bufsize_hint(len, frame_flags);
	if (crypt_bufsize > size) {
		return -EBADMSG;
	}
	crypt_buf = alloca(crypt_bufsize);
	if (crypt_buf == NULL) {
		return -ENOMEM;
	}
	len = encrypt_frame_body(crypt_buf, crypt_bufsize, buf, len, frame_flags, sharedkey);
	if (len < 0) {
		return -EBADMSG;
	}

	if (len > size) {
		return -EBADMSG;
	}
	//if (sizeof(struct frame_st) + len > size) {
	//	return -EBADMSG;
	//}
	
	memcpy(dstptr->frame_body, crypt_buf, len);
	dstptr->frame_flags = (uint8_t)frame_flags;
	dstptr->body_len = htons((uint16_t)(len + 1)); /* add frame_flags len */

	return len + sizeof(struct frame_st);
}

static int fill_internal_msg(internal_msg_t *dst, uint8_t *buf, int len, uint8_t *chunk, size_t size)
{
	int msg_len;

	struct frame_body_data_st *fdp = (struct frame_body_data_st *)buf;

	dst->msg_type = (int)FRAME_TYPE(ntohs(fdp->type_id));

	/* data frame */

	if (dst->msg_type == 0) {
		dst->data_frame_body.flow_id = (int)FRAME_PIPLINEID(ntohs(fdp->type_id));
		msg_len = len - 2; //uint16_t
		if (msg_len > size) {
			return -1;
		}

		memcpy(chunk, fdp->data, msg_len);
		dst->data_frame_body.data = chunk;
		dst->data_frame_body.data_len = msg_len;

		return 0;
	}

	/* control frame */
	struct frame_body_ctl_socket_cert_req_st *tfcp = (struct frame_body_ctl_socket_cert_req_st *)buf;
	dst->ctl_frame_body.code = (int)FRAME_OPCODE(ntohs(tfcp->type_opcode));

	switch (dst->ctl_frame_body.code) {
		case CTL_SOCKET_CERT_REQ:	//do nothing
			break;

		case CTL_SOCKET_CERT:
			msg_len = len - 2;
			if (msg_len > size) {
				return -1;
			}

			memcpy(chunk, ((struct frame_body_ctl_socket_cert_st *)buf)->x509_certificate, msg_len);
			dst->ctl_frame_body.arg.socket_cert.crt_bin = chunk;
			dst->ctl_frame_body.arg.socket_cert.crt_len = msg_len;
			break;

		case CTL_SOCKET_KEY_SYNC:
			dst->ctl_frame_body.arg.socket_key_sync.crc32 = ntohl(((struct frame_body_ctl_socket_key_sync_st *)buf)->crc32);
			msg_len = len - 6;
			if (msg_len > size) {
				return -1;
			}
			memcpy(chunk, ((struct frame_body_ctl_socket_key_sync_st *)buf)->encrypted_shared_key, msg_len);
			dst->ctl_frame_body.arg.socket_key_sync.encrypted_shared_key = chunk;
			dst->ctl_frame_body.arg.socket_key_sync.encrypted_shared_key_len = msg_len;
			break;

		case CTL_SOCKET_KEY_OK:		//do nothing
			break;
		case CTL_SOCKET_KEY_REJ:	//do nothing
			break;

		case CTL_PIPELINE_OPEN:
			dst->ctl_frame_body.arg.pipeline_open.flow_id = (int)ntohs(((struct frame_body_ctl_pipeline_open_st *)buf)->pipeline_id);
			dst->ctl_frame_body.arg.pipeline_open.max_delay_in_ms = (int)ntohs(((struct frame_body_ctl_pipeline_open_st *)buf)->max_delay_in_ms);
			dst->ctl_frame_body.arg.pipeline_open.reply_frame_flags = (int)((struct frame_body_ctl_pipeline_open_st *)buf)->reply_frame_flags;
			dst->ctl_frame_body.arg.pipeline_open.upstream_recvtimeo_ms = (int)ntohs(((struct frame_body_ctl_pipeline_open_st *)buf)->upstream_recvtimeo_ms);
			msg_len = len - 9;
			if (msg_len > size) {
				return -1;
			}
			memcpy(chunk, ((struct frame_body_ctl_pipeline_open_st *)buf)->data, msg_len);
			dst->ctl_frame_body.arg.pipeline_open.data = chunk;
			dst->ctl_frame_body.arg.pipeline_open.data_len = msg_len;
			break;

		case CTL_PIPELINE_FAILURE:
			dst->ctl_frame_body.arg.pipeline_failure.flow_id = (int)ntohs(((struct frame_body_ctl_pipeline_failure_st *)buf)->pipeline_id);
			dst->ctl_frame_body.arg.pipeline_failure.error_code = ((struct frame_body_ctl_pipeline_failure_st *)buf)->error_code;
			break;

		case CTL_PIPELINE_CLOSE:
			dst->ctl_frame_body.arg.pipeline_close.flow_id = (int)ntohs(((struct frame_body_ctl_pipeline_close_st *)buf)->pipeline_id);
			break;

		default:
			return -1;
	}

	return 0;
}


#ifdef FRAME_TEST

#include <unistd.h>
#include <fcntl.h>
#include <openssl/pem.h>
#include <openssl/blowfish.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <zlib.h>

static void bin_dump(FILE *fp, unsigned char *p, int len)
{
#define	DISPMAX	16
	int i;

	for (i=0;i<len && i<DISPMAX;++i) {
		fprintf(fp, "%.2x,", p[i]);
	}
	if (i<len) {
		fputs("...", fp);
	}
	fputc('\n', fp);
}

static int get_key(uint8_t key[KEYSIZE])
{
	EVP_PKEY *privkey, *pubkey;
	X509 *cert;
	uint8_t cryptedkey[KEYSIZE], plainkey[KEYSIZE];

	SSL_library_init();
	ERR_load_crypto_strings();

	privkey = load_privkey("keys/server.key");
	if (privkey==NULL) {
		perror("load_privkey()");
		exit(1);
	}

	cert = load_x509("keys/server.crt");
	if (cert==NULL) {
		perror("load_x509()");
		exit(1);
	}

	pubkey = EVP_PKEY_IN_X509(cert);
	if (pubkey == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	rand_sharedkey(key);

	if (RSA_public_encrypt(KEYSIZE, key, cryptedkey, RSA_IN_EVP_PKEY(pubkey), RSA_NO_PADDING)<0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (RSA_private_decrypt(KEYSIZE, cryptedkey, plainkey, RSA_IN_EVP_PKEY(privkey), RSA_NO_PADDING)<0) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (memcmp(key, plainkey, SHAREDKEY_BYTESIZE)==0) {
		puts("RSA_public_encrypt/RSA_private_decrypt OK.");
	} else {
		puts("RSA_public_encrypt/RSA_private_decrypt FAILed.");
	}

	return 0;
}

int test_frame_data(uint8_t key[SHAREDKEY_BYTESIZE]) {
#define	TESTBUFSIZE	4096
	int i,ret;
	ssize_t crypted_len;
	struct frame_st *crypted_frame = NULL;
	internal_msg_t *ori_frame_body;
	internal_msg_t decrypt_frame_body;

	ori_frame_body = malloc(sizeof(*ori_frame_body));
	ori_frame_body->msg_type = 0;
	ori_frame_body->data_frame_body.flow_id = 12345;
	ori_frame_body->data_frame_body.data = malloc(TESTBUFSIZE);
	ori_frame_body->data_frame_body.data_len = TESTBUFSIZE;
	for (i=0;i<TESTBUFSIZE;++i) {
		ori_frame_body->data_frame_body.data[i] = i%63;
	}

	printf("Original: %d bytes.\n", TESTBUFSIZE);

	crypted_len = frame_encode(&crypted_frame, ori_frame_body, FRAME_FLAG_MAKE(1, 1, 1), key);
	printf("frame_encode() = %d bytes.\n", (int)crypted_len);

	ret = frame_decode(&decrypt_frame_body, crypted_frame, key);
	printf("frame_decode() = %d bytes.\n", decrypt_frame_body.data_frame_body.data_len);

	if (memcmp(ori_frame_body->data_frame_body.data, decrypt_frame_body.data_frame_body.data, TESTBUFSIZE)==0) {
		puts("encrypt_frame_body/decrypt_frame_body OK.");
	} else {
		puts("encrypt_frame_body/decrypt_frame_body FAILed.");
	}
	printf("Original: ");
	bin_dump(stdout, ori_frame_body->data_frame_body.data, TESTBUFSIZE);
	printf("Crypted: ");
	bin_dump(stdout, crypted_frame->frame_body, crypted_len);
	printf("Derypted: ");
	bin_dump(stdout, decrypt_frame_body.data_frame_body.data, decrypt_frame_body.data_frame_body.data_len);

	free(ori_frame_body->data_frame_body.data);
	free(ori_frame_body);
	free(crypted_frame);
	return 0;
}

int test_frame_ctl(uint8_t key[SHAREDKEY_BYTESIZE]) {
#define	TESTBUFSIZE	4096
	int i,ret;
	ssize_t crypted_len;
	struct frame_st *crypted_frame = NULL;
	internal_msg_t *ori_frame_body;
	internal_msg_t decrypt_frame_body;

	ori_frame_body = malloc(sizeof(*ori_frame_body));
	ori_frame_body->msg_type = MSG_CTL_TYPE;
	ori_frame_body->ctl_frame_body.code = CTL_PIPELINE_OPEN;
	ori_frame_body->ctl_frame_body.arg.pipeline_open.flow_id = 1234;
	ori_frame_body->ctl_frame_body.arg.pipeline_open.max_delay_in_ms = 500;
	ori_frame_body->ctl_frame_body.arg.pipeline_open.reply_frame_flags = 1;
	ori_frame_body->ctl_frame_body.arg.pipeline_open.data = malloc(TESTBUFSIZE);
	ori_frame_body->ctl_frame_body.arg.pipeline_open.data_len = TESTBUFSIZE;
	for (i=0;i<TESTBUFSIZE;++i) {
		ori_frame_body->ctl_frame_body.arg.pipeline_open.data[i] = i%63;
	}

	printf("Original: %d bytes.\n", TESTBUFSIZE);

	crypted_len = frame_encode(&crypted_frame, ori_frame_body, FRAME_FLAG_MAKE(1, 1, 1), key);
	printf("frame_encode() = %d bytes.\n", (int)crypted_len);

	ret = frame_decode(&decrypt_frame_body, crypted_frame, key);
	printf("frame_decode() = %d bytes.\n", decrypt_frame_body.ctl_frame_body.arg.pipeline_open.data_len);

	if (memcmp(ori_frame_body->ctl_frame_body.arg.pipeline_open.data, decrypt_frame_body.ctl_frame_body.arg.pipeline_open.data, TESTBUFSIZE)==0) {
		puts("encrypt_frame_body/decrypt_frame_body OK.");
	} else {
		puts("encrypt_frame_body/decrypt_frame_body FAILed.");
	}
	printf("Original: ");
	bin_dump(stdout, ori_frame_body->ctl_frame_body.arg.pipeline_open.data, TESTBUFSIZE);
	printf("Crypted: ");
	bin_dump(stdout, crypted_frame->frame_body, crypted_len);
	printf("Derypted: ");
	bin_dump(stdout, decrypt_frame_body.ctl_frame_body.arg.pipeline_open.data, decrypt_frame_body.ctl_frame_body.arg.pipeline_open.data_len);

	free(ori_frame_body->ctl_frame_body.arg.pipeline_open.data);
	free(ori_frame_body);
	free(crypted_frame);
	return 0;
}

int
main()
{
	printf("===============LOAD KEY================\n");
	uint8_t key[KEYSIZE];
	get_key(key);

	printf("==============TEST FRAME DATA==========\n");
	test_frame_data(key);

	printf("=============TEST FRAME CTL============\n");
	test_frame_ctl(key);

	return 0;
}

#endif

