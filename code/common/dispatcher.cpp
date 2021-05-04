// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/enclave.h>
#include "regression.h"

ecall_dispatcher::ecall_dispatcher(
    const char* name)
    : m_crypto(NULL), m_attestation(NULL)
{
    m_initialized = initialize(name);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == NULL)
    {
        goto exit;
    }

    m_attestation = new Attestation(m_crypto);
    if (m_attestation == NULL)
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
int ecall_dispatcher::get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    uint8_t pem_public_key[PUBLIC_KEY_SIZE];
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* key_buf = NULL;
    int ret = 1;

    TRACE_ENCLAVE("get_remote_report_with_pubkey");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate a remote report for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_remote_report(
            pem_public_key, sizeof(pem_public_key), &report, &report_size))
    {
        // Allocate memory on the host and copy the report over.
        *remote_report = (uint8_t*)oe_host_malloc(report_size);
        if (*remote_report == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(*remote_report, report, report_size);
        *remote_report_size = report_size;
        oe_free_report(report);

        key_buf = (uint8_t*)oe_host_malloc(PUBLIC_KEY_SIZE);
        if (key_buf == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(key_buf, pem_public_key, sizeof(pem_public_key));

        *pem_key = key_buf;
        *key_size = sizeof(pem_public_key);

        ret = 0;
        TRACE_ENCLAVE("get_remote_report_with_pubkey succeeded");
    }
    else
    {
        TRACE_ENCLAVE("get_remote_report_with_pubkey failed.");
    }

exit:
    if (ret != 0)
    {
        if (report)
            oe_free_report(report);
        if (key_buf)
            oe_host_free(key_buf);
        if (*remote_report)
            oe_host_free(*remote_report);
    }
    return ret;
}

int ecall_dispatcher::generate_encrypted_message(uint8_t* message, int message_size, uint8_t** data, size_t* size)
{
    uint8_t encrypted_data_buffer[1024];
    size_t encrypted_data_size;
    uint8_t* host_buffer;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        goto exit;
    }

    encrypted_data_size = sizeof(encrypted_data_buffer);
    if (m_crypto->Encrypt(
            message,
            message_size,
            encrypted_data_buffer,
            &encrypted_data_size) == false)
    {
        TRACE_ENCLAVE("enclave: generate_encrypted_message failed");
        goto exit;
    }

    // TODO: the following code is not TEE-agnostic, as it assumes the
    // enclave can directly write into host memory
    host_buffer = (uint8_t*)oe_host_malloc(encrypted_data_size);
    if (host_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying host_buffer failed, out of memory");
        goto exit;
    }
    memcpy(host_buffer, encrypted_data_buffer, encrypted_data_size);
    TRACE_ENCLAVE(
        "enclave: generate_encrypted_message: encrypted_data_size = %ld\n",
        encrypted_data_size);
    *data = host_buffer;
    *size = encrypted_data_size;

    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::process_encrypted_message(
    uint8_t* encrypted_data,
    size_t encrypted_data_size)
{
    uint8_t data[1024];
    size_t data_size = 0;
    int ret = 1;

    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
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
        TRACE_ENCLAVE("Decrypted data: ");
        for (uint32_t i = 0; i < data_size; ++i)
        {
            printf("%d ", data[i]);
        }
        printf("\n");
    }
    else
    {
        TRACE_ENCLAVE("Enclave:ecall_dispatcher::process_encrypted_msg failed");
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}
