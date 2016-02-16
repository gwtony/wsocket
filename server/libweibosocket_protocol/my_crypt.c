#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/blowfish.h>
#include <openssl/rsa.h>
#include <zlib.h>
#include <pthread.h>

#include "my_crypt.h"
#include "frame.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void rand_sharedkey(uint8_t *buf)
{
	int i;

	do {
		for (i=0; i<SHAREDKEY_BYTESIZE; ++i) {
			buf[i] = rand();
		}
	} while (memcmp(buf, NO_SHAREDKEY, strlen(NO_SHAREDKEY))==0);
	return;
}

X509 *load_x509(const char *fname)
{
	FILE *fp;
	X509 *x509;

	fp = fopen(fname, "r");
	if (fp==NULL) {
		return NULL;
	}
	x509 = PEM_read_X509(fp, NULL, NULL, NULL);
	if (x509==NULL) {
		fclose(fp);
		return NULL;
	}
	fclose(fp);
	return x509;
}

EVP_PKEY *load_privkey(const char *fname)
{
	FILE *fp;
	EVP_PKEY *ret;

	fp = fopen(fname, "r");
	if (fp==NULL) {
		return NULL;
	}
	ret = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	return ret;
}

static ssize_t decrypt_frame_body_blowfish(	uint8_t *plain_buf, size_t plain_buf_size,
											uint8_t *crypt_buf, size_t crypt_buf_size,
											int frame_flags, uint8_t sharedkey[SHAREDKEY_BYTESIZE])
{
	int padlen;
	BF_KEY key;
	unsigned char bf_secret_ivec[]="9obi1MYX";

	padlen = crypt_buf[0];
	BF_set_key(&key, SHAREDKEY_BYTESIZE, sharedkey);
	BF_cbc_encrypt(crypt_buf+1, plain_buf, crypt_buf_size-1, &key, bf_secret_ivec, BF_DECRYPT);
	return crypt_buf_size-padlen-1;
}

ssize_t decrypt_frame_body(	uint8_t *plain_buf, size_t plain_buf_size,
							uint8_t *crypt_buf, size_t crypt_buf_size,
							int frame_flags, uint8_t sharedkey[SHAREDKEY_BYTESIZE])
{
	ssize_t datalen=0, plain_len;
	uint8_t *buf;

	buf = alloca(plain_buf_size);

	if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_NOCRYPT) {
		memcpy(buf, crypt_buf, crypt_buf_size);
		datalen = crypt_buf_size;
	} else if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_CRYPT_BLOWFISH) {
		datalen = decrypt_frame_body_blowfish(buf, plain_buf_size, crypt_buf, crypt_buf_size, frame_flags, sharedkey);
	}
	if (FLAG_ZIP(frame_flags)==FRAME_FLAG_NOZIP) {
		memcpy(plain_buf, buf, datalen);
		plain_buf_size = datalen;
//fprintf(stderr, "Skipped decompressing\n");
	} else if (FLAG_ZIP(frame_flags)==FRAME_FLAG_ZIP) {
//fprintf(stderr, "Decompressing %d  bytes...\n", datalen);
		plain_len = uncompress(plain_buf, &plain_buf_size, buf, datalen);
		if (plain_len == Z_BUF_ERROR) {
			return -ENOMEM;
		}
		if (plain_len == Z_DATA_ERROR) {
			fprintf(stderr, "input data was corrupted or incomplete\n");
			return -EINVAL;
		}
		if (plain_len != Z_OK) {
			return -EINVAL;
		}
//fprintf(stderr, "Decompressed: %d -> %d\n", datalen, plain_buf_size);
	} else {
//fprintf(stderr, "Unknown FLAG_ZIP !!\n");
	}
	return plain_buf_size;
}

static ssize_t encrypt_frame_body_blowfish(	uint8_t *crypt_buf, size_t crypt_bufsize,
											uint8_t *plain_buf, size_t plain_buf_size,
											int frame_flags, uint8_t sharedkey[SHAREDKEY_BYTESIZE])
{
	BF_KEY key;
	unsigned char bf_secret_ivec[]="9obi1MYX";

	BF_set_key(&key, SHAREDKEY_BYTESIZE, sharedkey);

	BF_cbc_encrypt(plain_buf, crypt_buf, plain_buf_size, &key, bf_secret_ivec, BF_ENCRYPT);
	return plain_buf_size;
}

ssize_t encrypt_frame_body(	uint8_t *crypt_buf, size_t crypt_bufsize,
							uint8_t *plain_buf, size_t plain_buf_size,
							int frame_flags, uint8_t sharedkey[SHAREDKEY_BYTESIZE])
{
	int ret;
	int padlen;
	ssize_t crypted_len = 0;
	size_t datalen;
	uint8_t *buf;

	buf = alloca(crypt_bufsize);
	memset(buf, 0, crypt_bufsize);

	if (FLAG_ZIP(frame_flags)==FRAME_FLAG_NOZIP) {
		memcpy(buf, plain_buf, plain_buf_size);
		datalen = plain_buf_size;
//fprintf(stderr, "Skipped compressing\n");
	} else if (FLAG_ZIP(frame_flags)==FRAME_FLAG_ZIP) {
		//bufsize = compressBound(plain_buf_size)+SHAREDKEY_BYTESIZE;
		datalen = crypt_bufsize;
		ret = compress(buf, &datalen, plain_buf, plain_buf_size);
		if (ret == Z_BUF_ERROR) {
			return -ENOMEM;
		}
		if (ret != Z_OK) {
			return -EINVAL;
		}
//fprintf(stderr, "Compressed: %d -> %d\n", plain_buf_size, datalen);
	}

	if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_NOCRYPT) {
		memcpy(crypt_buf, buf, datalen);
		crypted_len = datalen;
	} else if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_CRYPT_BLOWFISH) {
		if (datalen%8==0) {
			padlen = 0;
		} else {
			padlen = 8 - datalen%8;
		}
//fprintf(stderr, "encrypt_frame_body(): padlen = %d\n", padlen);
		crypt_buf[0] = (char)padlen;
		encrypt_frame_body_blowfish(crypt_buf+1, crypt_bufsize-1, buf, datalen+padlen, frame_flags, sharedkey);
		crypted_len = datalen+padlen+1;
	}
	return crypted_len;
}

size_t decrypt_frame_bufsize_hint(size_t crypted_frame_size, int frame_flags)
{
	size_t l;
	if (FLAG_ZIP(frame_flags)==FRAME_FLAG_NOZIP) {
		if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_NOCRYPT) {
			return crypted_frame_size;
		} else if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_CRYPT_BLOWFISH) {
			return crypted_frame_size;
		} else {
			return crypted_frame_size;
		}
	} else {
		l = MSG_FRAME_MAX;
		return l;
		//l = crypted_frame_size*4;
		//if (l<MSG_DATA_MAX) {
		//	l=MSG_DATA_MAX;
		//}
		//if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_NOCRYPT) {
		//	return l;
		//} else if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_CRYPT_BLOWFISH) {
		//	return l;
		//} else {
		//	return l;
		//}
	}
}

size_t encrypt_frame_bufsize_hint(size_t plain_frame_size, int frame_flags)
{
	size_t l;

	if (FLAG_ZIP(frame_flags)==FRAME_FLAG_NOZIP) {
		if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_NOCRYPT) {
			return plain_frame_size;
		} else if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_CRYPT_BLOWFISH) {
			return plain_frame_size%8 ? (plain_frame_size/8+1)*8+1 : plain_frame_size+1;
		} else {
			return plain_frame_size*2;
		}
	} else {
		l = compressBound(plain_frame_size);
		if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_NOCRYPT) {
			return l;
		} else if (FLAG_CRYPT(frame_flags)==FRAME_FLAG_CRYPT_BLOWFISH) {
			return l%8 ? (l/8+1)*8+1 : l+1;
		} else {
			return l;
		}
	}
}

uint32_t mycrc32(const uint8_t *datap, size_t len)
{
	uint32_t crc;

	crc = crc32(0L, Z_NULL, 0);

	crc = crc32(crc, datap, len);

	return crc;
}

int decrypt_synckey(unsigned char *from, unsigned char *to, EVP_PKEY *key)
{
	int ret;
	pthread_mutex_lock(&lock);
	ret = RSA_private_decrypt(RSA_KEYSIZE, from, to, RSA_IN_EVP_PKEY(key), RSA_PKCS1_PADDING);
	pthread_mutex_unlock(&lock);
	return ret;
}

int verify_cert(X509 *cert, X509 *issuer)
{
	int res = -1;
	EVP_PKEY *pubkey = NULL;

	if (X509_check_issued(issuer, cert) != X509_V_OK)
	{
		goto end;
	}

	pubkey = X509_get_pubkey(issuer);
	if (!X509_verify(cert, pubkey))
	{
		goto end;
	}

	res = 0;

end:
	if (pubkey)
	{
		EVP_PKEY_free(pubkey);
	}

	return res;
}

int check_private_key(X509 *cert, EVP_PKEY *key)
{
	if (X509_check_private_key(cert, key) == 1) {
		return 0;
	} else {
		return -1;
	}
}

void free_cert(X509 *cert)
{
	X509_free(cert);
}

void free_key(EVP_PKEY *key)
{
   	EVP_PKEY_free(key);
}

#ifdef CRYPT_TEST
#define	KEYSIZE	256

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

int
main()
{
	EVP_PKEY *privkey, *pubkey;
	X509 *cert;
	uint8_t key[KEYSIZE], cryptedkey[KEYSIZE], plainkey[KEYSIZE];

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

puts("============================================");

#define	TESTBUFSIZE	21312
	int i;
	char buf0[TESTBUFSIZE];
	char cryptbuf[TESTBUFSIZE*2], plainbuf[TESTBUFSIZE*2];
	int crypted_len, plain_len;

	for (i=0;i<TESTBUFSIZE;++i) {
		buf0[i] = i%63;
	}
	printf("Original: %d bytes.\n", TESTBUFSIZE);

	crypted_len = encrypt_frame_body(cryptbuf, TESTBUFSIZE*2, buf0, TESTBUFSIZE, FRAME_FLAG_MAKE(1, 1, 1), key);
	printf("encrypt_frame_body() = %d bytes.\n", crypted_len);

	plain_len = decrypt_frame_body(plainbuf, TESTBUFSIZE*2, cryptbuf, crypted_len, FRAME_FLAG_MAKE(1, 1, 1), key);
	printf("decrypt_frame_body() = %d bytes.\n", plain_len);

	if (memcmp(buf0, plainbuf, TESTBUFSIZE)==0) {
		puts("encrypt_frame_body/decrypt_frame_body OK.");
	} else {
		puts("encrypt_frame_body/decrypt_frame_body FAILed.");
	}
	printf("Original: ");
	bin_dump(stdout, buf0, TESTBUFSIZE);
	printf("Crypted: ");
	bin_dump(stdout, cryptbuf, crypted_len);
	printf("Derypted: ");
	bin_dump(stdout, plainbuf, plain_len);
	return 0;
}

#endif

