#include "regression.h"
#include <stdlib.h>
#include <math.h>
#include <openenclave/enclave.h>
#include <stdio.h>

void ecall_regression::initialize()
{
    oe_result_t result;
    int i;
    uint8_t samples[10];
    for (i=0;i<10;i++)
    {
        coeffs[i] = ((double) rand()) / (0.001* (double) RAND_MAX);
    }
}

double ecall_regression::infer(double values[9])
{
    double r = 0.0;
    r += coeffs[0];
    int i;
    for (i=1;i<10;i++)
    {
        r += coeffs[i]*values[i-1];
    }
    return r;
}

double ecall_regression::train(double values[9], double expected)
{
    double y = 0.0;
    double learning_rate = 0.00002;
    double dist;

    int i;
    y += coeffs[0];
    for (i=1;i<10;i++)
    {
        y +=  coeffs[i]*values[i-1];
    }

    dist = (expected - y);

    coeffs[0] += learning_rate*dist;
    for (i=1;i<10;i++)
    {
        coeffs[i] += learning_rate*values[i-1]*dist;
    }
    return fabs(dist/expected);
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