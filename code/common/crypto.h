// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_ENC_CRYPTO_H
#define OE_SAMPLES_ATTESTATION_ENC_CRYPTO_H

#include <openenclave/enclave.h>
// Includes for mbedtls shipped with oe.
// Also add the following libraries to your linker command line:
// -loeenclave -lmbedcrypto -lmbedtls -lmbedx509
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include "log.h"

#define PUBLIC_KEY_SIZE 512

class Crypto
{
  private:
    mbedtls_ctr_drbg_context m_ctr_drbg_contex;
    mbedtls_entropy_context m_entropy_context;
    mbedtls_pk_context m_pk_context;
    mbedtls_ecdh_context m_ecdh_context;
    uint8_t m_public_key[PUBLIC_KEY_SIZE];
    bool m_initialized;
    unsigned char srv_to_cli[32];
    unsigned char cli_to_srv[32];

    uint8_t m_client_public_key[PUBLIC_KEY_SIZE];

  public:
    Crypto();
    ~Crypto();

    void store_client_public_key(uint8_t pem_client_public_key[PUBLIC_KEY_SIZE]);
    void write_rsa_pem(uint8_t buff[PUBLIC_KEY_SIZE]);

    void store_ecdh_key(char key[256]);
    void write_ecdh_pem(char buff[512], size_t olen);
    void generate_secret();

    bool Encrypt(
        const uint8_t* data,
        size_t size,
        uint8_t* encrypted_data,
        size_t* encrypted_data_size);

    bool decrypt(
        const uint8_t* encrypted_data,
        size_t encrypted_data_size,
        uint8_t* data,
        size_t* data_size);

    bool get_rsa_modulus_from_pem(
        const char* pem_data,
        size_t pem_size,
        uint8_t** modulus,
        size_t* modulus_size);

    int Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32]);

    void retrieve_public_key(uint8_t pem_public_key[512]);

  private:

    bool init_mbedtls(void);

    void cleanup_mbedtls(void);
};

#endif
