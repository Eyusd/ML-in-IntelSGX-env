// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma once
#include <string>
#include "crypto.h"

using namespace std;

class client_dispatcher
{
  private:
    bool m_initialized;
    Crypto_client* m_crypto;
    string m_name;

  public:
    client_dispatcher(const char* name);
    ~client_dispatcher();
    
    int generate_encrypted_message(uint8_t* message, int message_size, uint8_t** data, size_t* size);
    int process_encrypted_message(
        uint8_t* encrypted_data,
        size_t encrypted_data_size);

    void store_server_public_key(uint8_t pem_server_public_key[PUBLIC_KEY_SIZE]) {m_crypto->store_server_public_key(pem_server_public_key);};
    void write_rsa_pem(uint8_t buff[PUBLIC_KEY_SIZE]) {m_crypto->write_rsa_pem(buff);};
    
    void store_ecdh_key(char key[256]) {m_crypto->store_ecdh_key(key);};
    void write_ecdh_pem(char buff[512], size_t olen) {m_crypto->write_ecdh_pem(buff, olen);};
    void generate_secret() {m_crypto->generate_secret();};

  private:
    bool initialize(const char* name);
};
