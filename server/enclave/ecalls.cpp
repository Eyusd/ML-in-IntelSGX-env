// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <common/dispatcher.h>
#include <common/regression.h>
#include <common/project_t.h>
#include <openenclave/enclave.h>

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static ecall_dispatcher dispatcher("Enclave1");
const char* enclave_name = "Enclave1";

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * Another enclave can use the remote report to attest the enclave and verify
 * the integrity of the public key.
 */
int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    TRACE_ENCLAVE("enter get_remote_report_with_pubkey");
    return dispatcher.get_remote_report_with_pubkey(
        pem_key, key_size, remote_report, remote_report_size);
}

void enclave_init()
{
    dispatcher.reg_initialize();
}

void enclave_train(double values[9], double expected, double* output)
{
    *output = dispatcher.reg_train(values, expected);
}

void enclave_infer(double values[9], double* output)
{
    *output = dispatcher.reg_infer(values);
}

void enclave_old_to_new()
{
    dispatcher.reg_old_to_new();
}

void enclave_new_to_old()
{
    dispatcher.reg_new_to_old();
}

void retrieve_ecdh_key(unsigned char key[32])
{
    dispatcher.retrieve_ecdh_key(key);
}

void generate_secret()
{
    dispatcher.generate_secret();
}

void retrieve_client_public_key(unsigned char pem_client_public_key[1024])
{
    dispatcher.retrieve_client_public_key(pem_client_public_key);
}