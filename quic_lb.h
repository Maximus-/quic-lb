/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */
#ifndef _QUIC_LB_H_
#define _QUIC_LB_H_

#ifdef NOBIGIP
#include <stdbool.h>
#else
#include <local/sys/types.h>
#endif

#define QUIC_LB_TOKEN_LEN 16
#define QUIC_LB_MAX_CID_LEN 20
/* Maximum Server ID Lengths */
#define QUIC_LB_OCID_SIDL_MAX 16
#define QUIC_LB_SCID_SIDL_MAX 11
#define QUIC_LB_BCID_SIDL_MAX 11

void quic_lb_encrypt_cid(void *cid, void *config, size_t cid_len,
        void *server_use);
/*
 * This wrapper calles quic_lb_encrypt_cid and generates random bits for
 * the server use octets.
 */
void quic_lb_encrypt_cid_random(void *cid, void *config, size_t cid_len);
int quic_lb_decrypt_cid(void *cid, void *config, size_t *cid_len,
        void *result);
/* Temporary functions */
void *quic_lb_load_scid_config(u_int8_t cr, bool encode_len, u_int8_t *key,
        u_int8_t cidl, u_int8_t nonce_len, u_int8_t *sid);
void *quic_lb_load_bcid_config(u_int8_t cr, bool encode_len, u_int8_t *key,
        u_int8_t sidl, u_int8_t zp_len, u_int8_t *sid, bool encrypt);
void quic_lb_free_config(void *config);
#endif /* _QUIC_LB_H */
