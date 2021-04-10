// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "crypto.h"
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>

Crypto::Crypto()
{
    m_initialized = init_mbedtls();
}

Crypto::~Crypto()
{
    cleanup_mbedtls();
}

bool Crypto::init_mbedtls(void)
{
    bool ret = false;
    int res = -1;

    mbedtls_ctr_drbg_init(&m_ctr_drbg_contex);
    mbedtls_entropy_init(&m_entropy_context);
    mbedtls_pk_init(&m_pk_context);
    mbedtls_ecdh_init(&m_ecdh_context);

    res = mbedtls_ctr_drbg_seed(
        &m_ctr_drbg_contex, mbedtls_entropy_func, &m_entropy_context, NULL, 0);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_seed failed.");
        goto exit;
    }

    res = mbedtls_pk_setup(
        &m_pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_setup failed (%d).", res);
        goto exit;
    }

    res = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(m_pk_context),
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_contex,
        2048,
        65537);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_rsa_gen_key failed (%d)\n", res);
        goto exit;
    }

    res = mbedtls_pk_write_pubkey_pem(
        &m_pk_context, m_public_key, sizeof(m_public_key));
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_write_pubkey_pem failed (%d)\n", res);
        goto exit;
    }

    ret = mbedtls_ecp_group_load( &m_ecdh_context.grp, MBEDTLS_ECP_DP_CURVE25519 );
    if( ret != 0 )
    {
        TRACE_ENCLAVE( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public( &m_ecdh_context.grp, &m_ecdh_context.d, &m_ecdh_context.Q,
                                   mbedtls_ctr_drbg_random, &m_ctr_drbg_contex );
    if( ret != 0 )
    {
        TRACE_ENCLAVE( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &m_ecdh_context.Q.X, srv_to_cli, 32 );
    if( ret != 0 )
    {
        TRACE_ENCLAVE( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_lset( &m_ecdh_context.Qp.Z, 1 );
    if( ret != 0 )
    {
        TRACE_ENCLAVE( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    ret = true;
    TRACE_ENCLAVE("mbedtls initialized.");
exit:
    return ret;
}

void Crypto::cleanup_mbedtls(void)
{
    mbedtls_pk_free(&m_pk_context);
    mbedtls_entropy_free(&m_entropy_context);
    mbedtls_ctr_drbg_free(&m_ctr_drbg_contex);
    mbedtls_ecdh_free(&m_ecdh_context);

    TRACE_ENCLAVE("mbedtls cleaned up.");
}

void Crypto::retrieve_public_key(uint8_t pem_public_key[512])
{
    memcpy(pem_public_key, m_public_key, sizeof(m_public_key));
}

void Crypto::retrieve_client_public_key(unsigned char pem_client_public_key[1024])
{   
    int keyLen = strlen((const char*) pem_client_public_key) + 1;
    mbedtls_pk_context g_RSAKeyContex;
    mbedtls_pk_init(&g_RSAKeyContex);
    mbedtls_pk_setup(&g_RSAKeyContex, mbedtls_pk_info_from_type((mbedtls_pk_type_t)MBEDTLS_PK_RSA));
    mbedtls_pk_parse_public_key(&g_RSAKeyContex, (unsigned char*)pem_client_public_key, (size_t)keyLen);

    mbedtls_pk_write_pubkey_pem(&g_RSAKeyContex, m_client_pubkey, sizeof(m_client_pubkey));
}

int Crypto::Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    int ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_update_ret(&ctx, data, data_size);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_finish_ret(&ctx, sha256);
    if (ret)
        goto exit;

exit:
    mbedtls_sha256_free(&ctx);
    return ret;
}

bool Crypto::Encrypt(
    const uint8_t* pem_public_key,
    const uint8_t* data,
    size_t data_size,
    uint8_t* encrypted_data,
    size_t* encrypted_data_size)
{
    bool result = false;
    mbedtls_pk_context key;
    size_t key_size = 0;
    int res = -1;
    mbedtls_rsa_context* rsa_context;

    mbedtls_pk_init(&key);

    if (!m_initialized)
        goto exit;

    // Read the given public key.
    key_size = strlen((const char*)pem_public_key) + 1; // Include ending '\0'.
    res = mbedtls_pk_parse_public_key(&key, pem_public_key, key_size);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_parse_public_key failed.");
        goto exit;
    }

    rsa_context = mbedtls_pk_rsa(key);
    rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
    rsa_context->hash_id = MBEDTLS_MD_SHA256;

    if (rsa_context->padding == MBEDTLS_RSA_PKCS_V21)
    {
        TRACE_ENCLAVE("Padding used: MBEDTLS_RSA_PKCS_V21 for OAEP or PSS");
    }

    if (rsa_context->padding == MBEDTLS_RSA_PKCS_V15)
    {
        TRACE_ENCLAVE("New MBEDTLS_RSA_PKCS_V15  for 1.5 padding");
    }

    // Encrypt the data.
    res = mbedtls_rsa_pkcs1_encrypt(
        rsa_context,
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_contex,
        MBEDTLS_RSA_PUBLIC,
        data_size,
        data,
        encrypted_data);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_rsa_pkcs1_encrypt failed with %d\n", res);
        goto exit;
    }

    *encrypted_data_size = mbedtls_pk_rsa(key)->len;
    result = true;
exit:
    mbedtls_pk_free(&key);
    return result;
}

bool Crypto::decrypt(
    const uint8_t* encrypted_data,
    size_t encrypted_data_size,
    uint8_t* data,
    size_t* data_size)
{
    bool ret = false;
    size_t output_size = 0;
    int res = 0;
    mbedtls_rsa_context* rsa_context;

    if (!m_initialized)
        goto exit;

    mbedtls_pk_rsa(m_pk_context)->len = encrypted_data_size;
    rsa_context = mbedtls_pk_rsa(m_pk_context);
    rsa_context->padding = MBEDTLS_RSA_PKCS_V21;
    rsa_context->hash_id = MBEDTLS_MD_SHA256;

    output_size = *data_size;
    res = mbedtls_rsa_pkcs1_decrypt(
        rsa_context,
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_contex,
        MBEDTLS_RSA_PRIVATE,
        &output_size,
        encrypted_data,
        data,
        output_size);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_rsa_pkcs1_decrypt failed with %d\n", res);
        goto exit;
    }
    *data_size = output_size;
    ret = true;

exit:
    return ret;
}

bool Crypto::get_rsa_modulus_from_pem(
    const char* pem_data,
    size_t pem_size,
    uint8_t** modulus,
    size_t* modulus_size)
{
    mbedtls_pk_context ctx;
    mbedtls_pk_type_t pk_type;
    mbedtls_rsa_context* rsa_ctx = NULL;
    uint8_t* modulus_local = NULL;
    size_t modulus_local_size = 0;
    int res = 0;
    bool ret = false;

    if (!m_initialized || !modulus || !modulus_size)
        goto exit_preinit;

    mbedtls_pk_init(&ctx);
    res = mbedtls_pk_parse_public_key(
        &ctx, (const unsigned char*)pem_data, pem_size);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_pk_parse_public_key failed with %d\n", res);
        goto exit;
    }

    pk_type = mbedtls_pk_get_type(&ctx);
    if (pk_type != MBEDTLS_PK_RSA)
    {
        TRACE_ENCLAVE("mbedtls_pk_get_type had incorrect type: %d\n", res);
        goto exit;
    }

    rsa_ctx = mbedtls_pk_rsa(ctx);
    modulus_local_size = mbedtls_rsa_get_len(rsa_ctx);
    modulus_local = (uint8_t*)malloc(modulus_local_size);
    if (modulus_local == NULL)
    {
        TRACE_ENCLAVE(
            "malloc for modulus failed with size %zu:\n", modulus_local_size);
        goto exit;
    }

    res = mbedtls_rsa_export_raw(
        rsa_ctx,
        modulus_local,
        modulus_local_size,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0,
        NULL,
        0);
    if (res != 0)
    {
        TRACE_ENCLAVE("mbedtls_rsa_export failed with %d\n", res);
        goto exit;
    }

    *modulus = modulus_local;
    *modulus_size = modulus_local_size;
    modulus_local = NULL;
    ret = true;

exit:
    if (modulus_local != NULL)
        free(modulus_local);

    mbedtls_pk_free(&ctx);

exit_preinit:
    return ret;
}

void Crypto::retrieve_ecdh_key(unsigned char key[32])
{   
    int ret;

    memcpy(&cli_to_srv, key, 32);
    ret = mbedtls_mpi_read_binary( &m_ecdh_context.Qp.X, cli_to_srv, 32 );
    if( ret != 0 )
    {
        TRACE_ENCLAVE( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        mbedtls_ecdh_free( &m_ecdh_context );
        mbedtls_ctr_drbg_free( &m_ctr_drbg_contex );
        mbedtls_entropy_free( &m_entropy_context );
    }

}

void Crypto::generate_secret()
{
    int ret;
    ret = mbedtls_ecdh_compute_shared( &m_ecdh_context.grp, &m_ecdh_context.z,
                                       &m_ecdh_context.Qp, &m_ecdh_context.d,
                                       mbedtls_ctr_drbg_random, &m_ctr_drbg_contex );
    if( ret != 0 )
    {
        TRACE_ENCLAVE( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        mbedtls_ecdh_free( &m_ecdh_context );
        mbedtls_ctr_drbg_free( &m_ctr_drbg_contex );
        mbedtls_entropy_free( &m_entropy_context );
    }

}

void Crypto::write_pem(unsigned char buff[513])
{
    int ret;
    ret = mbedtls_pk_write_pubkey_pem(&m_pk_context, buff, 513);
}