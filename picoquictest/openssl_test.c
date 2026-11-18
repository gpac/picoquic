/*
* Author: Christian Huitema
* Copyright (c) 2024, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picosocks.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "picoquic_qlog.h"
#include "picoquictest.h"

#include "picotls.h"
#include "picoquic_crypto_provider_api.h"

#ifdef PTLS_WITHOUT_OPENSSL
int openssl_cert_test(void)
{
    /* Nothing to do, as the module is not loaded. */
    return 0;
}
#else

#include <openssl/pem.h>

ptls_iovec_t* picoquic_openssl_get_certs_from_file(char const* file_name, size_t* count);

#ifdef _WINDOWS
#define TEST_CERT1 "certs\\tests\\cert.pem"
#define TEST_CERT2 "certs\\tests\\chain.pem"
#define TEST_CERT3 "certs\\tests\\fullchain.pem"
#else
#define TEST_CERT1 "certs/tests/cert.pem"
#define TEST_CERT2 "certs/tests/chain.pem"
#define TEST_CERT3 "certs/tests/fullchain.pem"
#endif

static int openssl_cert_test_one(char const * cert_file_name, int expected_count)
{
    /* Nothing to do, as the module is not loaded. */
    int ret = 0;
    size_t count = 0;
    char cert_file_path[512];

    ret = picoquic_get_input_path(cert_file_path, sizeof(cert_file_path), picoquic_solution_dir, cert_file_name);

    if (ret == 0) {
        ptls_iovec_t* certs_vec = picoquic_openssl_get_certs_from_file(cert_file_path, &count);

        if ((int)count != expected_count) {
            DBG_PRINTF("Expected %d certs for %s, got=%d", expected_count, cert_file_path, count);
            ret = -1;
        }
        if (certs_vec == NULL) {
            if (count > 0) {
                DBG_PRINTF("No certificate vector for %s, count=%d", cert_file_path, count);
                ret = -1;
            }
        }
        else {
            for (size_t i = 0; i < count; i++) {
                free(certs_vec[i].base);
                certs_vec[i] = ptls_iovec_init(NULL, 0);
            }
            free(certs_vec);
        }
    }
    return 0;
}

static int openssl_der_key_test(void)
{
    uint64_t simulated_time = 0, loss_mask = 0;
    picoquic_test_tls_api_ctx_t* ctx = NULL;
    EVP_PKEY* key = NULL;
    BIO* bio = NULL;
    unsigned char* der = NULL;
    unsigned char* cursor;
    int der_len = 0;
    int ret;
    char key_path[512], cert_path[512];
    ptls_iovec_t* certs;
    size_t cert_count = 0;
    const uint8_t invalid[] = { 0x30, 0x01, 0xff };

    ret = tls_api_init_ctx_ex2(&ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0,
        NULL, 8, 0, 0, 1);
    if (ret == 0)
        ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_CERT);
    if (ret == 0) {
        certs = picoquic_get_certs_from_file(cert_path, &cert_count);
        if (certs == NULL || cert_count == 0) {
            free(certs);
            ret = -1;
        } else
            picoquic_set_tls_certificate_chain(ctx->qserver, certs, cert_count);
    }
    if (ret == 0)
        ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_KEY);
    if (ret == 0) {
        bio = BIO_new_file(key_path, "rb");
        if (bio != NULL)
            key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (key == NULL || (der_len = i2d_PrivateKey(key, NULL)) <= 0 ||
            (der = malloc((size_t)der_len + 1)) == NULL)
            ret = -1;
    }
    if (ret == 0) {
        cursor = der;
        if (i2d_PrivateKey(key, &cursor) != der_len ||
            picoquic_set_tls_key(NULL, der, (size_t)der_len) == 0 ||
            picoquic_set_tls_key(ctx->qserver, NULL, (size_t)der_len) == 0 ||
            picoquic_set_tls_key(ctx->qserver, der, 0) == 0 ||
            picoquic_set_tls_key(ctx->qclient, der, (size_t)der_len) == 0 ||
            picoquic_set_tls_key(ctx->qserver, der, (size_t)der_len) != 0 ||
            picoquic_set_tls_key(ctx->qserver, invalid, sizeof(invalid)) == 0)
            ret = -1;
    }
    if (ret == 0) {
        der[der_len] = 0;
        if (picoquic_set_tls_key(ctx->qserver, der, (size_t)der_len + 1) == 0)
            ret = -1;
    }
    if (ret == 0) {
        ret = tls_api_connection_loop(ctx, &loss_mask, 0, &simulated_time);
        if (ret == 0 &&
            (ctx->cnx_client->cnx_state != picoquic_state_ready &&
                ctx->cnx_client->cnx_state != picoquic_state_client_ready_start))
            ret = -1;
        if (ret == 0 &&
            (ctx->cnx_server == NULL ||
                (ctx->cnx_server->cnx_state != picoquic_state_ready &&
                    ctx->cnx_server->cnx_state != picoquic_state_server_false_start)))
            ret = -1;
    }
    if (ctx != NULL)
        tls_api_delete_ctx(ctx);
    free(der);
    EVP_PKEY_free(key);
    BIO_free(bio);
    return ret;
}


int openssl_cert_test(void)
{
    /* Nothing to do, as the module is not loaded. */
    int ret = 0;

    if (openssl_cert_test_one(TEST_CERT1, 1) != 0 ||
        openssl_cert_test_one(TEST_CERT2, 1) != 0 ||
        openssl_cert_test_one(TEST_CERT3, 2) != 0 ||
        openssl_der_key_test() != 0) {
        ret = -1;
    }
    return ret;
}

#endif /* !PTLS_WITHOUT_OPENSSL */
