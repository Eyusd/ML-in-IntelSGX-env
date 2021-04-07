#include "gatherer.h"
#include "dispatcher.h"
#include <openenclave/enclave.h>

ecall_gatherer::ecall_gatherer(const char* name, enclave_config_data_t* enclave_config)
{
    dispatcher.initialize(name, enclave_config);
};