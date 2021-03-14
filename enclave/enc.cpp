#include "linereg_t.h"
#include "linereg.h"
#include <stdio.h>

static ecall_regression regression;

void enclave_init()
{
    regression.initialize();
}

void enclave_train(double values[9], double expected, bool* output)
{
    *output = regression.train(values, expected);
}

void enclave_infer(double values[9], double* output)
{
    *output = regression.infer(values);
}

void enclave_old_to_new()
{
    regression.old_to_new();
}

void enclave_new_to_old()
{
    regression.new_to_old();
}