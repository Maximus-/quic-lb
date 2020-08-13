/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */

#include <openssl/rand.h>

#ifdef NOBIGIP
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "quic_lb.h"
#else
#include <local/sys/types.h>
#include <local/sys/cpu.h>
#include <local/sys/err.h>
#include <local/sys/lib.h>
#include <local/sys/rnd.h>
#include <local/sys/umem.h>
#include <local/modules/hudfilter/quic/quic_lb.h>
#include <cut/cut.h>
#endif

#define TEST_QUIC_LB_NUM_CONFIG 5
#define TEST_QUIC_LB_NUM_SRV_ID 5
#define TEST_QUIC_LB_PER_SERVER 1

#ifdef NOBIGIP
#define CUT_ASSERT(arg) assert(arg)
#define ERR_OK 0

static inline u_int8_t
rnd8_range(u_int8_t max)
{
    unsigned char value;
    RAND_bytes(&value, sizeof(max));
    return ((max < UINT8_MAX) ? (value % (max + 1)) : value);
}
#else
#define rnd8_range(arg) rnd8_range(RND_PSEUDO, arg)
#endif /* NOBIGIP */

static void
test_quic_lb_scid(void)
{
    u_int8_t  key[16], nonce_len, sidl = 0, sid[QUIC_LB_SCID_SIDL_MAX],
             cid[QUIC_LB_MAX_CID_LEN], max_nonce_len;
    u_int8_t  result[QUIC_LB_SCID_SIDL_MAX];
    int    cfg, srv, run;
#ifdef NOBIGIP
    int i;
#endif
    size_t cid_len;
    void  *record;
    bool   len_encode;

    for (cfg = 0; cfg < TEST_QUIC_LB_NUM_CONFIG; cfg++) {
        RAND_bytes((unsigned char *)key, sizeof(key));
        len_encode = (cfg % 2 == 0);
        sidl++;
        max_nonce_len = ((19 - sidl) > 16) ? 16 : (19 - sidl);
        nonce_len = rnd8_range(max_nonce_len - 8) + 8;
        cid_len = sidl + nonce_len + 1;
#ifdef NOBIGIP
        printf("SCID LB configuration: cr_bits 0x0 length_self_encoding: %s "
                "nonce_len %u sid_len %u ", len_encode ? "y" : "n", nonce_len,
                sidl);
        printf("key ");
        for (i = 0; i < 16; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");
#endif
        for (srv = 0; srv < TEST_QUIC_LB_NUM_SRV_ID; srv++) {
            memset(sid, 0, sizeof(sid));
            RAND_bytes((unsigned char *)sid, sidl);
            record = quic_lb_load_scid_config(0, len_encode, key, sidl,
                    nonce_len, sid);
            CUT_ASSERT(record != NULL);
            for (run = 0; run < TEST_QUIC_LB_PER_SERVER; run++) {
                quic_lb_encrypt_cid_random(cid, record, cid_len);
                CUT_ASSERT(quic_lb_decrypt_cid(cid, record, &cid_len, result) ==
                        ERR_OK);
#ifdef NOBIGIP
                printf("cid ");
                for (i = 0; i < cid_len; i++) {
                    printf("%02x", cid[i]);
                }
                printf(" sid ");
                for (i = 0; i < sidl; i++) {
                    printf("%02x", sid[i]);
                }
                printf("\n");
#endif
                CUT_ASSERT(memcmp(result, sid, sidl) == 0);
                CUT_ASSERT(cid_len == sidl + nonce_len + 1);
            }
            quic_lb_free_config(record);
        }
    }
}

static void
test_quic_lb_bcid(void)
{
    u_int8_t  key[16], sidl = 0, sid[8], cid[QUIC_LB_MAX_CID_LEN];
    u_int8_t  result[QUIC_LB_BCID_SIDL_MAX];
    int    cfg, srv, run;
#ifdef NOBIGIP
    int i;
#endif
    void  *svr_cfg, *lb_cfg;
    size_t cid_len = QUIC_LB_MAX_CID_LEN, zp_len;
    bool   len_encode;

    for (cfg = 0; cfg < TEST_QUIC_LB_NUM_CONFIG; cfg++) {
        RAND_bytes((unsigned char *)key, sizeof(key));
        len_encode = (cfg % 2 == 0);
        sidl++;
        zp_len = 12 - sidl;
#ifdef NOBIGIP
        printf("BCID LB configuration: cr_bits 0x0 length_self_encoding: %s "
                "sid_len %u zp_len %lu ", len_encode ? "y" : "n", sidl, zp_len);
        printf("key ");
        for (i = 0; i < 16; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");
#endif
        for (srv = 0; srv < TEST_QUIC_LB_NUM_SRV_ID; srv++) {
            memset(sid, 0, sizeof(sid));
            RAND_bytes((unsigned char *)sid, sidl);
            svr_cfg = quic_lb_load_bcid_config(0, len_encode, key, sidl, zp_len,
                    sid, true);
            lb_cfg = quic_lb_load_bcid_config(0, len_encode, key, sidl, zp_len,
                    sid, false);
            CUT_ASSERT(svr_cfg != NULL);
            CUT_ASSERT(lb_cfg != NULL);
            for (run = 0; run < TEST_QUIC_LB_PER_SERVER; run++) {
                quic_lb_encrypt_cid_random(cid, svr_cfg, cid_len);
                CUT_ASSERT(quic_lb_decrypt_cid(cid, lb_cfg, &cid_len, result) ==
                        ERR_OK);
#ifdef NOBIGIP
                printf("cid ");
                for (i = 0; i < QUIC_LB_MAX_CID_LEN; i++) {
                    printf("%02x", cid[i]);
                }
                printf(" sid: ");
                for (i = 0; i < sidl; i++) {
                    printf("%02x", sid[i]);
                }
                printf("\n");
#endif
                CUT_ASSERT(memcmp(&result, sid, sidl) == 0);
                CUT_ASSERT(cid_len == QUIC_LB_MAX_CID_LEN);
            }
            quic_lb_free_config(svr_cfg);
            quic_lb_free_config(lb_cfg);
        }
    }
}

#ifdef NOBIGIP
int main(int argc, char* argv[])
{
    test_quic_lb_scid();
    test_quic_lb_bcid();
}
#else
CUT_SUITE(quic_lb);
CUT_SUITE_TEST(quic_lb, test_quic_lb_scid);
CUT_SUITE_TEST(quic_lb, test_quic_lb_bcid);
#endif
