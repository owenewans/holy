#ifndef HOLY_SIGN_H
#define HOLY_SIGN_H

/* dir is locked by the publisher; both functions validate index digest. */
int holy_sign_index(int dir, const char *digest, const char *private_key);
int holy_verify_index(int dir, const char *digest, const char *public_key);
int holy_verify_index_keyhash(int dir, const char *digest, const char *public_key,
                              char key_hash[65]);
int holy_verify_index_bytes(int dir, const char *digest, const char *public_key,
                            const unsigned char signature[64], char key_hash[65]);
/* reads an Ed25519 PEM public key and returns its canonical raw bytes in hex. */
int holy_public_key_hex(const char *path, char output[65]);

#endif
