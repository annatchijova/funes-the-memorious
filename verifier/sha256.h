/* SHA-256 (FIPS 180-4). In-tree implementation; verified against published
 * test vectors by tests/run_tests.sh via the collector's hashing path. */
#ifndef FUNES_VERIFY_SHA256_H
#define FUNES_VERIFY_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} funes_sha256_ctx;

void funes_sha256_init(funes_sha256_ctx *ctx);
void funes_sha256_update(funes_sha256_ctx *ctx, const uint8_t *data, size_t len);
void funes_sha256_final(funes_sha256_ctx *ctx, uint8_t hash[32]);
void funes_sha256_hex(const uint8_t hash[32], char out[65]);

#endif
