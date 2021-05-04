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

void server_store_ecdh_key(char key[256])
{
    dispatcher.store_ecdh_key(key);
}

void server_generate_secret()
{
    dispatcher.generate_secret();
}

void server_store_client_public_key(uint8_t pem_client_public_key[PUBLIC_KEY_SIZE])
{
    dispatcher.store_client_public_key(pem_client_public_key);
}

void server_write_rsa_pem(uint8_t buff[PUBLIC_KEY_SIZE])
{
    dispatcher.write_rsa_pem(buff);
}

void server_write_ecdh_pem(char buff[512])
{
    size_t olen;
    dispatcher.write_ecdh_pem(buff, olen);
}

void server_generate_encrypted_message(uint8_t* to_encrypt, int message_size, uint8_t** encrypted_data, size_t* size_encrypted)
{
    dispatcher.generate_encrypted_message(to_encrypt, message_size, encrypted_data, size_encrypted);
}

void server_decrypt_message(uint8_t* encrypted_data, size_t encrypted_data_size)
{
    dispatcher.process_encrypted_message(encrypted_data, encrypted_data_size);
}