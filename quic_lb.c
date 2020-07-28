/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */
#ifdef NOBIGIP
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "quic_lb.h"
#include <stdio.h> // mhd
#define ROUNDUPDIV(n, m) (((n) + ((m) - 1)) / (m))
#define RAND_bytes(ptr,size) RAND_bytes((unsigned char *)(ptr), size)
#else
#include <openssl/evp.h>
#include <local/sys/cpu.h>
#include <local/sys/debug.h>
#include <local/sys/def.h>
#include <local/sys/err.h>
#include <local/sys/lib.h>
#include <local/sys/rnd.h>
#include <local/sys/umem.h>
#endif

#define QUIC_LB_TUPLE_ROUTE 0xc0
#define QUIC_LB_USABLE_BYTES (QUIC_LB_MAX_CID_LEN - 1)

enum quic_lb_alg {
    QUIC_LB_OCID,
    QUIC_LB_SCID,
    QUIC_LB_BCID,
};

struct quic_lb_generic_config {
    u_int8_t         cr : 2;
    u_int8_t         encode_length : 1;
    enum quic_lb_alg alg : 5;
};

struct quic_lb_ocid_config {
    u_int8_t            cr : 2;
    u_int8_t            encode_length : 1;
    enum quic_lb_alg    alg : 5;
    u_int8_t            sidl;
    u_int8_t            bitmask[QUIC_LB_USABLE_BYTES];
    /* These are presented in host order */
    u_int8_t            modulus[QUIC_LB_OCID_SIDL_MAX];
    u_int8_t            divisor[QUIC_LB_OCID_SIDL_MAX];
};

struct quic_lb_scid_config {
    u_int8_t            cr : 2;
    u_int8_t            encode_length : 1;
    enum quic_lb_alg    alg : 5;
    u_int8_t            nonce_len;
    u_int8_t            sidl;
    u_int8_t            sid[QUIC_LB_SCID_SIDL_MAX];
    __uint128_t             nonce_ctr;
    EVP_CIPHER_CTX     *ctx;
};

struct quic_lb_bcid_config {
    u_int8_t            cr : 2;
    u_int8_t            encode_length : 1;
    enum quic_lb_alg    alg : 5;
    u_int8_t            zp_len;
    u_int8_t            sidl;
    u_int8_t            sid[QUIC_LB_BCID_SIDL_MAX];
    u_int8_t            key[16];
    EVP_CIPHER_CTX     *ctx;
};

#ifndef UINT128_MAX
   /* Get around the inability to define 128-bit constants */
   u_int64_t uint128_max_array[2] = {0xffffffffffffffffULL,
           0xffffffffffffffffULL};
   #define UINT128_MAX *(__uint128_t *)uint128_max_array
#endif

static inline void
quic_lb_5tuple_routing(void *cid, size_t cid_len)
{
    RAND_bytes(cid, cid_len);
    *(u_int8_t *)cid &= QUIC_LB_TUPLE_ROUTE;
    return;
}

/*
 * Note: this is NOT deterministic because the multiple selection must always
 * be random.
 */
static void
quic_lb_ocid_encrypt(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_ocid_config *cfg = config;
    __uint128_t max_encoding, max_multiple, multiple = UINT128_MAX, encoding;
    __uint128_t divisor = 0, modulus = 0;
    u_int8_t  *cid_ptr, mask_bits = 0, rand_bits, *mask;
    u_int8_t  *svr_use_ptr = server_use;
    int     i, shift, encode_shift;

    for (i = 0; i < (cid_len - 1); i++) {
        mask_bits += bit_count(cfg->bitmask[i]);
    }
    assert(cid_len > ROUNDUPDIV(mask_bits + 18, 8));
    max_encoding = ((__uint128_t)0x1 << mask_bits) - 1;
    memcpy(&divisor, cfg->divisor, sizeof(cfg->divisor));
    memcpy(&modulus, cfg->modulus, sizeof(cfg->modulus));
    max_multiple = (max_encoding / divisor);
    if (((max_multiple * divisor) + modulus) > max_encoding) {
        max_multiple--;
    }
    /*
     * Do not overweight low multiples. We must retry if the result is very
     * large.
     */
    while ((UINT128_MAX - multiple) < max_multiple) {
        RAND_bytes(&multiple, sizeof(multiple));
    }
    multiple = multiple % max_multiple;
    encoding = modulus + (divisor * multiple);
    /* Put the encoding in the routing mask */
    memset(cid, 0, cid_len);
    cid_ptr = (u_int8_t *)cid + cid_len - 1;
    mask = (u_int8_t *)cfg->bitmask + cid_len - 2;
    encode_shift = 0;
#if 1
    printf("multiple ");
    u_int8_t *ptr = (u_int8_t *)&multiple;
    int j;
    for (j = 0; j < sizeof(multiple); j++) {
        printf("%02x ", *ptr);
        ptr++;
    }
    printf("\n");
#endif
    for (i = 1; i < cid_len; i++) {
        rand_bits = *svr_use_ptr;
        svr_use_ptr++;
        for (shift = 0; shift < 8; shift++) {
            if (((*mask >> shift) & 0x1) == 0x1) {
                *cid_ptr |= (((encoding >> encode_shift) & 0x1) << shift);
                encode_shift++;
            } else {
                *cid_ptr |= (rand_bits & (0x1 << shift));
            }
        }
        cid_ptr--;
        mask--;
    }
    *cid_ptr = cfg->encode_length ? (cid_len - 1) : ((*svr_use_ptr) & 0x3f);
    *cid_ptr |= ((u_int8_t)cfg->cr << 6); /* Set cfg rotation bits. */
}

static int
quic_lb_ocid_decrypt(void *cid, void *config, size_t *cid_len, u_int8_t *sid)
{
    struct quic_lb_ocid_config *cfg = config;
    __uint128_t encoding = 0, divisor = 0, result;
    int     i, shift, encode_shift;
    u_int8_t  *cid_ptr, *mask;

    /* Get the encoding from the routing mask */
    cid_ptr = (u_int8_t *)cid + sizeof(cfg->bitmask);
    mask = (u_int8_t *)cfg->bitmask + sizeof(cfg->bitmask) - 1;
    encode_shift = 0;
    if (cfg->encode_length) {
        *cid_len = (*(u_int8_t *)cid & 0x3f) + 1;
    }
    for (i = 0; i < sizeof(cfg->bitmask); i++) {
        if (*mask != 0) {
            for (shift = 0; shift < 8; shift++) {
                if (((*mask >> shift) & 0x1) == 0x1) {
                    encoding |= ((__uint128_t)((*cid_ptr >> shift) & 0x1) <<
                            encode_shift);
                    encode_shift++;
                }
            }
        }
        cid_ptr--;
        mask--;
    }
    memcpy(&divisor, cfg->divisor, sizeof(cfg->divisor));
    result = encoding % divisor;
    memcpy(sid, &result, cfg->sidl);
    return 0;
}

static inline int
quic_lb_encrypt_apply_nonce(struct quic_lb_scid_config *cfg, u_int8_t *nonce,
        u_int8_t nonce_len, u_int8_t *target, u_int8_t target_len)
{
    u_int8_t pt[16];
    u_int8_t ct[16];
    int ct_len, i, err;

    memset(pt, 0, sizeof(pt));
    memcpy(pt, nonce, nonce_len);
    err = EVP_EncryptUpdate(cfg->ctx, ct, &ct_len, pt, sizeof(pt));
    if (err != 1) {
        return err;
    }
    if (ct_len != sizeof(pt)) {
        return EINVAL;
    }
    for (i = 0; i < target_len; i++) {
        *(target + i) = ct[i] ^ target[i];
    }
    return 0;
}


static void
quic_lb_scid_encrypt(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_scid_config *cfg = config;
    u_int8_t  *nonce = cid + 1, *sid = nonce + cfg->nonce_len,
           *extra = sid + cfg->sidl, *svr_use_ptr = server_use;

    if (cfg->nonce_ctr > ((1 << (cfg->nonce_len * 8)) - 1)) {
        /* Nonce is not big enough for unique CIDs */
        quic_lb_5tuple_routing(cid, cid_len);
        return;
    }
    if (cfg->encode_length) {
        *(u_int8_t *)cid = cid_len - 1;
    } else {
        memcpy(cid, server_use, 1);
    }
    *(u_int8_t *)cid &= 0x3f;
    *(u_int8_t *)cid |= (cfg->cr << 6);
    svr_use_ptr++;
    memcpy(nonce, &cfg->nonce_ctr, cfg->nonce_len); /* Host order! */
    memcpy(sid, cfg->sid, cfg->sidl);
    /* 1st Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl) != 0) {
        quic_lb_5tuple_routing(cid, cid_len);
        return;
    }
    cfg->nonce_ctr++;
    /* 2nd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, sid, cfg->sidl, nonce,
            cfg->nonce_len) != 0) {
        quic_lb_5tuple_routing(cid, cid_len);
        return;
    }
    /* 3rd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl) != 0) {
        quic_lb_5tuple_routing(cid, cid_len);
        return;
    }
    if ((u_int8_t *)cid + cid_len > extra) {
        memcpy(extra, server_use + 1, cid_len -
                (1 + cfg->nonce_len + cfg->sidl));
    }
    return;
}

static int
quic_lb_scid_decrypt(void *cid, void *config, size_t *cid_len, u_int8_t *sid)
{
    struct quic_lb_scid_config *cfg = config;
    u_int8_t nonce[cfg->nonce_len];
    int err;

    if (cfg->encode_length) {
        *cid_len = (*(u_int8_t *)cid & 0x3f) + 1;
    }
    memcpy(nonce, cid + 1, cfg->nonce_len);
    memset(sid, 0, sizeof(sid));
    memcpy(sid, cid + 1 + cfg->nonce_len, cfg->sidl);
    /* 1st Pass */
    err = quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl);
    if (err != 0) {
        return err;
    }
    /* 2nd Pass */
    err = quic_lb_encrypt_apply_nonce(cfg, sid, cfg->sidl, nonce,
            cfg->nonce_len);
    if (err != 0) {
        return err;
    }
    /* 3rd Pass */
    err = quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl);
    if (err != 0) {
        return err;
    }
    return 0;
}

static void
quic_lb_bcid_encrypt(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_bcid_config *cfg = config;
    u_int8_t *ptr = cid, *svr_use_ptr = server_use;
    u_int8_t block[16];
    int ct_len, i;

    *ptr = (cfg->cr << 6) | (cfg->encode_length ? (cid_len - 1) :
            ((*svr_use_ptr) & 0x3f));
    memcpy(&block[0], cfg->sid, cfg->sidl);
    memset(&block[cfg->sidl], 0, cfg->zp_len);
    svr_use_ptr++;
    for (i = cfg->sidl + cfg->zp_len; i < sizeof(block); i++) {
       block[i] = *svr_use_ptr;
       svr_use_ptr++;
    }
    if ((EVP_EncryptUpdate(cfg->ctx, ptr + 1, &ct_len, block, sizeof(block))
            != 1) || (ct_len != sizeof(block))) {
        quic_lb_5tuple_routing(cid, cid_len);
        return;
    }
    for (i = ct_len + 1; i < cid_len; i++) {
        *(ptr + i) = *svr_use_ptr;
        svr_use_ptr++;
    }
    return;
}

static int
quic_lb_bcid_decrypt(void *cid, void *config, size_t *cid_len, u_int8_t *sid)
{
    struct quic_lb_bcid_config *cfg = config;
    u_int8_t *ptr = cid;
    u_int8_t block[16];
    u_int8_t zeroes[cfg->zp_len];
    int pt_len, err;

    if (cfg->encode_length) {
        *cid_len = (*(u_int8_t *)cid & 0x3f) + 1;
    }
    memset(block, 0, sizeof(block)); // mhd;
    err = EVP_DecryptUpdate(cfg->ctx, &block[0], &pt_len, ptr + 1,
            sizeof(block));
    if ((err != 1) || (pt_len != sizeof(block))) {
        return err;
    }
    memcpy(sid, block, cfg->sidl);
    memset(zeroes, 0, sizeof(zeroes));
    if (memcmp(&block[cfg->sidl], zeroes, cfg->zp_len) != 0) {
        return EINVAL;
    }
    return 0;
}

/* server_use MUST be of length cid_len */
void
quic_lb_encrypt_cid(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_generic_config *generic;

    if (config == NULL) {
        quic_lb_5tuple_routing(cid, cid_len);
        return;
    }
    generic = (struct quic_lb_generic_config *)config;
    switch(generic->alg) {
    case QUIC_LB_OCID:
        quic_lb_ocid_encrypt(cid, config, cid_len, server_use);
        break;
    case QUIC_LB_SCID:
        quic_lb_scid_encrypt(cid, config, cid_len, server_use);
        break;
    case QUIC_LB_BCID:
        quic_lb_bcid_encrypt(cid, config, cid_len, server_use);
        break;
    }
}

void
quic_lb_encrypt_cid_random(void *cid, void *config, size_t cid_len)
{
    u_int8_t server_use[cid_len];

    RAND_bytes(server_use, sizeof(server_use));
    quic_lb_encrypt_cid(cid, config, cid_len, server_use);
}

int
quic_lb_decrypt_cid(void *cid, void *config, size_t *cid_len, void *sid)
{
    struct quic_lb_generic_config *generic;
    int err = 0;

    generic = (struct quic_lb_generic_config *)config;
    switch(generic->alg) {
    case QUIC_LB_OCID:
        err = quic_lb_ocid_decrypt(cid, config, cid_len, sid);
        break;
    case QUIC_LB_SCID:
        err = quic_lb_scid_decrypt(cid, config, cid_len, sid);
        break;
    case QUIC_LB_BCID:
        err = quic_lb_bcid_decrypt(cid, config, cid_len, sid);
        break;
    }
    return err;
}

/* The bitmask should be filled out for the entire 19 byte length */
void *
quic_lb_load_ocid_config(u_int8_t cr, bool encode_len, u_int8_t *bitmask,
        u_int8_t *modulus, u_int8_t *divisor, u_int8_t sidl)
{
    struct quic_lb_ocid_config *cfg =
            malloc(sizeof(struct quic_lb_ocid_config));

    if (cfg == NULL) {
        return NULL;
    }
    if (cr > 0x3) {
        free(cfg);
        return NULL;
    }
    cfg->cr = cr;
    cfg->encode_length = encode_len;
    cfg->alg = QUIC_LB_OCID;
    cfg->sidl = sidl;
    memcpy(cfg->bitmask, bitmask, QUIC_LB_USABLE_BYTES);
    memcpy(cfg->modulus, modulus, QUIC_LB_OCID_SIDL_MAX);
    memcpy(cfg->divisor, divisor, QUIC_LB_OCID_SIDL_MAX);
    return cfg;
}

void *
quic_lb_load_scid_config(u_int8_t cr, bool encode_len, u_int8_t *key, u_int8_t sidl,
        u_int8_t nonce_len, u_int8_t *sid)
{
    struct quic_lb_scid_config *cfg = 
            malloc(sizeof(struct quic_lb_scid_config));

    if (cfg == NULL) {
        return NULL;
    }
    if ((cr > 0x3) || (nonce_len < 8) || (nonce_len > 16) ||
            (nonce_len + sidl > QUIC_LB_USABLE_BYTES)) {
        free(cfg);
        return NULL;
    }
    cfg->cr = cr;
    cfg->encode_length = encode_len;
    cfg->alg = QUIC_LB_SCID;
    cfg->nonce_len = nonce_len;
    cfg->sidl = sidl;
    memcpy(cfg->sid, sid, sidl);
    cfg->nonce_ctr = 0;
    cfg->ctx = EVP_CIPHER_CTX_new();
    /*
     * CTR mode just encrypts the nonce using AES-ECB and XORs it with
     * the plaintext or ciphertext. So for encrypt or decrypt, in this
     * case we're technically encrypting.
     */
    if (cfg->ctx == NULL) {
        free(cfg);
        return NULL;
    }
    if (EVP_CipherInit_ex(cfg->ctx, EVP_aes_128_ecb(), NULL, key, NULL, 1)
            == 0) {
        EVP_CIPHER_CTX_free(cfg->ctx);
        free(cfg);
        return NULL;
    }
    return cfg;
}

void *
quic_lb_load_bcid_config(u_int8_t cr, bool encode_len, u_int8_t *key,
        u_int8_t sidl, u_int8_t zp_len, u_int8_t *sid, bool encrypt)
{
    struct quic_lb_bcid_config *cfg =
            malloc(sizeof(struct quic_lb_bcid_config));

    if (cfg == NULL) {
        return NULL;
    }
    cfg->ctx = NULL;
    if ((cr > 0x3) || (zp_len < 4) || (zp_len + sidl > 12)) {
        free(cfg);
        return NULL;
    }
    cfg->cr = cr;
    cfg->encode_length = encode_len;
    cfg->alg = QUIC_LB_BCID;
    cfg->zp_len = zp_len;
    cfg->sidl = sidl;
    memcpy(cfg->sid, sid, sidl);
    memcpy(cfg->key, key, sizeof(cfg->key));
    cfg->ctx = EVP_CIPHER_CTX_new();
    if (cfg->ctx == NULL) {
        free(cfg);
        return NULL;
    }
    if (EVP_CipherInit_ex(cfg->ctx, EVP_aes_128_ecb(), NULL, key, NULL,
            encrypt ? 1 : 0) == 0) {
        EVP_CIPHER_CTX_free(cfg->ctx);
        free(cfg);
        return NULL;
    }
    if (EVP_CIPHER_CTX_set_padding(cfg->ctx, 0) == 0) {
        EVP_CIPHER_CTX_free(cfg->ctx);
        free(cfg);
        return NULL;
    }
    return cfg;
}

void
quic_lb_free_config(void *config)
{
    struct quic_lb_generic_config *generic;
    EVP_CIPHER_CTX  *ctx;

    generic = (struct quic_lb_generic_config *)config;
    if (generic->alg != QUIC_LB_OCID) {
        ctx = (generic->alg == QUIC_LB_SCID) ?
                ((struct quic_lb_scid_config *)config)->ctx :
                ((struct quic_lb_bcid_config *)config)->ctx;
        if (ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
    free(config);
    return;
}
