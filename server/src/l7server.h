#ifndef L7_SERVER_H
#define L7_SERVER_H

/** \cond 0 */
#include <sys/types.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "cJSON.h"
/** \endcond */

#define MAX_THREADS 64
#define MAX_NAME 32

struct l7_info_st {
	pid_t pid;
	char name[MAX_NAME];
	size_t name_size;
	int monitor_fd;
	cJSON *conf;
	time_t start_time;
	int socket_in_pipe;
};

struct l7_worker_arg {
	cJSON *conf;
	int index;
	int *socket_in_pipe;
};
struct l7_param_st {
	EVP_PKEY *server_pubkey;    /** < Server side pubkey */
	EVP_PKEY *server_privkey;   /** < Server side privkey */
	X509 *server_cert;          /** < Server's certificate  */
	unsigned char *server_cert_bin; /** < Server's certificate mmapped into memory */
	size_t server_cert_bin_size;    /** < Server's certificate mmapped into memory (size) */
	X509 *ca_cert;              /** < CA's certificate  */
};

extern char *l7_name;
extern struct l7_param_st l7_param;
extern struct upstream_st *l7_upstream;
extern int l7_listen_socket;
extern int *socket_in_pipe;
extern int accept_pipe[MAX_THREADS];
extern int work_pipe[MAX_THREADS];

int l7_spawn(cJSON *conf, struct l7_info_st*);

int l7_kill(pid_t);

#endif

