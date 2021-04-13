// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once
#include <openenclave/enclave.h>
#include <string>
#include "attestation.h"
#include "crypto.h"
#include "regression.h"

using namespace std;

class ecall_dispatcher
{
  private:
    bool m_initialized;
    Crypto* m_crypto;
    Attestation* m_attestation;
    string m_name;
    ecall_regression m_regression;

  public:
    ecall_dispatcher(const char* name);
    ~ecall_dispatcher();
    int get_remote_report_with_pubkey(
        uint8_t** pem_key,
        size_t* key_size,
        uint8_t** remote_report,
        size_t* remote_report_size);
    
    int generate_encrypted_message(uint8_t* message, uint8_t** data, size_t* size);
    int process_encrypted_message(
        uint8_t* encrypted_data,
        size_t encrypted_data_size);

    void store_client_public_key(unsigned char pem_client_public_key[PUBLIC_KEY_SIZE + 1]) {m_crypto->store_client_public_key(pem_client_public_key);};
    void write_rsa_pem(unsigned char buff[PUBLIC_KEY_SIZE + 1]) {m_crypto->write_rsa_pem(buff);};
    
    void store_ecdh_key(char key[256]) {m_crypto->store_ecdh_key(key);};
    void write_ecdh_pem(char buff[512], size_t olen) {m_crypto->write_ecdh_pem(buff, olen);};
    void generate_secret() {m_crypto->generate_secret();};

    void reg_initialize() {m_regression.initialize();};
    double reg_infer(double values[9]) {return m_regression.infer(values);};
    double reg_train(double values[9], double expected) {return m_regression.train(values, expected);};
    void reg_new_to_old() {m_regression.new_to_old();};
    void reg_old_to_new() {m_regression.old_to_new();};

  private:
    bool initialize(const char* name);
};
