// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <string.h>

client_dispatcher::client_dispatcher(
    const char* name)
    : m_crypto(NULL)
{
    m_initialized = initialize(name);
}

client_dispatcher::~client_dispatcher()
{
    if (m_crypto)
        delete m_crypto;
}

bool client_dispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_crypto = new Crypto_client();
    if (m_crypto == NULL)
    {
        goto exit;
    }
    ret = true;

exit:
    return ret;
}

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * The enclave that receives the key will use the remote report to attest this
 * enclave.
 */

int client_dispatcher::generate_encrypted_message(uint8_t* message, int message_size, uint8_t** data, size_t* size)
{
    uint8_t encrypted_data_buffer[1024];
    size_t encrypted_data_size;
    uint8_t* host_buffer;
    int ret = 1;

    if (m_initialized == false)
    {
        fprintf(stderr, "client_dispatcher initialization failed");
        goto exit;
    }
    encrypted_data_size = sizeof(encrypted_data_buffer);
    if (m_crypto->Encrypt(
            message,
            message_size,
            encrypted_data_buffer,
            &encrypted_data_size) == false)
    {
        fprintf(stderr, "generate_encrypted_message failed");
        goto exit;
    }
        // TODO: the following code is not TEE-agnostic, as it assumes the
    // enclave can directly write into host memory
    host_buffer = (uint8_t*) malloc(encrypted_data_size);
    if (host_buffer == nullptr)
    {
        fprintf(stderr, "copying host_buffer failed, out of memory");
        goto exit;
    }
    memcpy(host_buffer, encrypted_data_buffer, encrypted_data_size);
    fprintf(stderr,
        "generate_encrypted_message: encrypted_data_size = %ld\n",
        encrypted_data_size);
    *data = host_buffer;
    *size = encrypted_data_size;

    //Export encrypted message
    ret = 0;
exit:
    return ret;
}

int client_dispatcher::process_encrypted_message(uint8_t* encrypted_data, size_t encrypted_data_size)
{
    uint8_t data[1024];
    size_t data_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        fprintf(stderr, "client_dispatcher initialization failed");
        goto exit;
    }

    data_size = sizeof(data);
    if (m_crypto->decrypt(
            encrypted_data, encrypted_data_size, data, &data_size))
    {
        // This is where the business logic for verifying the data should be.
        // In this sample, both enclaves start with identical data in
        // m_enclave_config->enclave_secret_data.
        // The following checking is to make sure the decrypted values are what
        // we have expected.
        fprintf(stderr, "Decrypted data: ");
        for (uint32_t i = 0; i < data_size; ++i)
        {
            fprintf(stderr, "%d ", data[i]);
        }
        fprintf(stderr, "\n");
    }
    else
    {
        fprintf(stderr, "client_dispatcher::process_encrypted_msg failed");
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}
