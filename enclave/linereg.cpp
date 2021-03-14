#include "linereg.h"
#include <openenclave/enclave.h>
#include <stdio.h>

void ecall_regression::initialize()
{
    oe_result_t result;
    int i;
    uint8_t samples[10];
    for (i=0;i<10;i++)
    {
        result = oe_random(&samples[i], sizeof(samples[i]));
        coeffs[i] = (double) (samples[i] % 10);
    }
}

double ecall_regression::infer(double values[9])
{
    double r = coeffs[0];
    int i;
    for (i=1;i<10;i++)
    {
        r = r +  coeffs[i]*values[i-1];
    }
    return r;
}

bool ecall_regression::train(double values[9], double expected)
{
    double y = coeffs[0];
    double learning_rate = 0.00002;

    int i;
    for (i=1;i<10;i++)
    {
        y = y +  coeffs[i]*values[i];
    }
    coeffs[0] = coeffs[0] + learning_rate*(expected - y);
    for (i=1;i<10;i++)
    {
        coeffs[i] = coeffs[i] + learning_rate*values[i]*(expected-y);
    }
    return true;
}

void ecall_regression::new_to_old()
{
    int i;
    double s;
    for (i=0;i<10;i++)
    {
        s = coeffs[i];
        old_coeffs[i] = s;
    }
}

void ecall_regression::old_to_new()
{
    int i;
    double s;
    for (i=0;i<10;i++)
    {
        s = old_coeffs[i];
        coeffs[i] = s;
        
    }
}