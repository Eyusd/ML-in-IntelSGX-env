#include "dispatcher.h"
#include "regression.h"
#include <openenclave/enclave.h>
#include <string>

class ecall_gatherer
{   
    public:
        ecall_dispatcher dispatcher;
        ecall_regression regression;
        ecall_gatherer(const char* name, enclave_config_data_t* enclave_config);
        ~ecall_gatherer();
};