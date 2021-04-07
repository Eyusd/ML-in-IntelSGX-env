#include "common/linereg_t.h"
#include "common/regression.h"
#include <stdio.h>
#include <common/dispatcher.h>
#include <common/gatherer.h>
#include <enclave_pubkey.h>
#include <openenclave/enclave.h>


uint8_t g_enclave_secret_data[ENCLAVE_SECRET_DATA_SIZE] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

enclave_config_data_t config_data = {g_enclave_secret_data,
                                     OTHER_ENCLAVE_PUBLIC_KEY,
                                     sizeof(OTHER_ENCLAVE_PUBLIC_KEY)};

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static ecall_gatherer gatherer("Enclave1", &config_data);
const char* enclave_name = "Enclave1";
int get_enclave_format_settings(
    const oe_uuid_t* format_id,
    uint8_t** format_settings,
    size_t* format_settings_size)
{
    return gatherer.dispatcher.get_enclave_format_settings(
        format_id, format_settings, format_settings_size);
}

/**
 * Return the public key of this enclave along with the enclave's
 * evidence. Another enclave can use the evidence to attest the enclave
 * and verify the integrity of the public key.
 */
int get_evidence_with_public_key(
    const oe_uuid_t* format_id,
    uint8_t* format_settings,
    size_t format_settings_size,
    uint8_t** pem_key,
    size_t* pem_key_size,
    uint8_t** evidence,
    size_t* evidence_size)
{
    return gatherer.dispatcher.get_evidence_with_public_key(
        format_id,
        format_settings,
        format_settings_size,
        pem_key,
        pem_key_size,
        evidence,
        evidence_size);
}

// Attest and store the public key of another enclave.
int verify_evidence_and_set_public_key(
    const oe_uuid_t* format_id,
    uint8_t* pem_key,
    size_t pem_key_size,
    uint8_t* evidence,
    size_t evidence_size)
{
    return gatherer.dispatcher.verify_evidence_and_set_public_key(
        format_id, pem_key, pem_key_size, evidence, evidence_size);
}

// Encrypt message for another enclave using the public key stored for it.
int generate_encrypted_message(uint8_t** data, size_t* size)
{
    return gatherer.dispatcher.generate_encrypted_message(data, size);
}

// Process encrypted message
int process_encrypted_message(uint8_t* data, size_t size)
{
    return gatherer.dispatcher.process_encrypted_message(data, size);
}

void enclave_init()
{
    gatherer.regression.initialize();
}

void enclave_train(double values[9], double expected, double* output)
{
    *output = gatherer.regression.train(values, expected);
}

void enclave_infer(double values[9], double* output)
{
    *output = gatherer.regression.infer(values);
}

void enclave_old_to_new()
{
    gatherer.regression.old_to_new();
}

void enclave_new_to_old()
{
    gatherer.regression.new_to_old();
}