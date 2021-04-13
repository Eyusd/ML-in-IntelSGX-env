/*
 *  This file is auto generated by oeedger8r. DO NOT EDIT.
 */
#ifndef EDGER8R_PROJECT_U_H
#define EDGER8R_PROJECT_U_H

#include <openenclave/host.h>

#include "project_args.h"

OE_EXTERNC_BEGIN

oe_result_t oe_create_project_enclave(
    const char* path,
    oe_enclave_type_t type,
    uint32_t flags,
    const oe_enclave_setting_t* settings,
    uint32_t setting_count,
    oe_enclave_t** enclave);

/**** ECALL prototypes. ****/
oe_result_t get_remote_report_with_pubkey(
    oe_enclave_t* enclave,
    int* _retval,
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size);

oe_result_t store_client_public_key(
    oe_enclave_t* enclave,
    unsigned char pem_client_public_key[513]);

oe_result_t write_rsa_pem(
    oe_enclave_t* enclave,
    unsigned char buff[513]);

oe_result_t store_ecdh_key(
    oe_enclave_t* enclave,
    char key[256]);

oe_result_t write_ecdh_pem(
    oe_enclave_t* enclave,
    char buff[512]);

oe_result_t generate_secret(oe_enclave_t* enclave);

oe_result_t enclave_init(oe_enclave_t* enclave);

oe_result_t enclave_old_to_new(oe_enclave_t* enclave);

oe_result_t enclave_new_to_old(oe_enclave_t* enclave);

oe_result_t enclave_train(
    oe_enclave_t* enclave,
    double values[9],
    double expected,
    double* output);

oe_result_t enclave_infer(
    oe_enclave_t* enclave,
    double values[9],
    double* output);

oe_result_t oe_get_sgx_report_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    const void* opt_params,
    size_t opt_params_size,
    sgx_report_t* report);

oe_result_t oe_get_report_v2_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    uint32_t flags,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t** report_buffer,
    size_t* report_buffer_size);

oe_result_t oe_verify_local_report_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report);

oe_result_t oe_sgx_init_context_switchless_ecall(
    oe_enclave_t* enclave,
    oe_result_t* _retval,
    oe_host_worker_context_t* host_worker_contexts,
    uint64_t num_host_workers);

oe_result_t oe_sgx_switchless_enclave_worker_thread_ecall(
    oe_enclave_t* enclave,
    oe_enclave_worker_context_t* context);

/**** OCALL prototypes. ****/
oe_result_t oe_get_supported_attester_format_ids_ocall(
    void* format_ids,
    size_t format_ids_size,
    size_t* format_ids_size_out);

oe_result_t oe_get_qetarget_info_ocall(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    sgx_target_info_t* target_info);

oe_result_t oe_get_quote_ocall(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const sgx_report_t* sgx_report,
    void* quote,
    size_t quote_size,
    size_t* quote_size_out);

oe_result_t oe_get_quote_verification_collateral_ocall(
    uint8_t fmspc[6],
    uint8_t collateral_provider,
    void* tcb_info,
    size_t tcb_info_size,
    size_t* tcb_info_size_out,
    void* tcb_info_issuer_chain,
    size_t tcb_info_issuer_chain_size,
    size_t* tcb_info_issuer_chain_size_out,
    void* pck_crl,
    size_t pck_crl_size,
    size_t* pck_crl_size_out,
    void* root_ca_crl,
    size_t root_ca_crl_size,
    size_t* root_ca_crl_size_out,
    void* pck_crl_issuer_chain,
    size_t pck_crl_issuer_chain_size,
    size_t* pck_crl_issuer_chain_size_out,
    void* qe_identity,
    size_t qe_identity_size,
    size_t* qe_identity_size_out,
    void* qe_identity_issuer_chain,
    size_t qe_identity_issuer_chain_size,
    size_t* qe_identity_issuer_chain_size_out);

oe_result_t oe_verify_quote_ocall(
    const oe_uuid_t* format_id,
    const void* opt_params,
    size_t opt_params_size,
    const void* p_quote,
    uint32_t quote_size,
    const time_t expiration_check_date,
    uint32_t* p_collateral_expiration_status,
    uint32_t* p_quote_verification_result,
    void* p_qve_report_info,
    uint32_t qve_report_info_size,
    void* p_supplemental_data,
    uint32_t supplemental_data_size,
    uint32_t* p_supplemental_data_size_out,
    uint32_t collateral_version,
    const void* p_tcb_info,
    uint32_t tcb_info_size,
    const void* p_tcb_info_issuer_chain,
    uint32_t tcb_info_issuer_chain_size,
    const void* p_pck_crl,
    uint32_t pck_crl_size,
    const void* p_root_ca_crl,
    uint32_t root_ca_crl_size,
    const void* p_pck_crl_issuer_chain,
    uint32_t pck_crl_issuer_chain_size,
    const void* p_qe_identity,
    uint32_t qe_identity_size,
    const void* p_qe_identity_issuer_chain,
    uint32_t qe_identity_issuer_chain_size);

oe_result_t oe_sgx_get_cpuid_table_ocall(
    void* cpuid_table_buffer,
    size_t cpuid_table_buffer_size);

oe_result_t oe_sgx_backtrace_symbols_ocall(
    oe_enclave_t* oe_enclave,
    const uint64_t* buffer,
    size_t size,
    void* symbols_buffer,
    size_t symbols_buffer_size,
    size_t* symbols_buffer_size_out);

void oe_sgx_thread_wake_wait_ocall(
    oe_enclave_t* oe_enclave,
    uint64_t waiter_tcs,
    uint64_t self_tcs);

void oe_sgx_wake_switchless_worker_ocall(oe_host_worker_context_t* context);

void oe_sgx_sleep_switchless_worker_ocall(oe_enclave_worker_context_t* context);

OE_EXTERNC_END

#endif // EDGER8R_PROJECT_U_H
