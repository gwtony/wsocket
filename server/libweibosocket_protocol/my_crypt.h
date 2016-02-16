#ifndef MY_CRYPT_H
#define MY_CRYPT_H

#include <stdint.h>
#include <openssl/pem.h>

#include <protocol.h>
#include <frame.h>

#define RSA_KEYSIZE 256

#define	NO_SHAREDKEY	"==NO_SHAREDKEY=="	/* strlen(NO_SHAREDKEY) == SHAREDKEY_BYTESIZE */

X509 *load_x509(const char *fname);

#define	EVP_PKEY_IN_X509(x) (X509_PUBKEY_get((x)->cert_info->key))

#define	RSA_IN_EVP_PKEY(x) ((x)->pkey.rsa)

EVP_PKEY *load_privkey(const char *fname);

void rand_sharedkey(uint8_t *buf);

ssize_t decrypt_frame_body(	uint8_t *plain_buf, size_t plain_buf_size,
							uint8_t *crypt_buf, size_t crypt_buf_size,
							int frame_flags, uint8_t sharedkey[SHAREDKEY_BYTESIZE]);

ssize_t encrypt_frame_body(	uint8_t *crypt_buf, size_t crypt_bufsize,
							uint8_t *plain_buf, size_t plain_buf_size,
							int frame_flags, uint8_t sharedkey[SHAREDKEY_BYTESIZE]);

size_t decrypt_frame_bufsize_hint(size_t crypted_frame_size, int frame_flags);
size_t encrypt_frame_bufsize_hint(size_t plain_frame_size, int frame_flags);

uint32_t mycrc32(const uint8_t *datap, size_t len);
int decrypt_synckey(unsigned char *from, unsigned char *to, EVP_PKEY *key);

int verify_cert(X509 *cert, X509 *issuer);

int check_private_key(X509 *cert, EVP_PKEY *key);

void free_cert(X509 *cert);
void free_key(EVP_PKEY *key);

#endif

