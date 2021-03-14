#ifndef DEF_REGRESSION
#define DEF_REGRESSION
#include <openenclave/enclave.h>
#include <stdio.h>

class ecall_regression
{
    private:
        double coeffs[10];
        double old_coeffs[10];
        // Stockés en A + Bx + Cy + Dz ==> {A;B;C;D}
    public:
        void initialize();
        bool train(double values[9], double expected);
        double infer(double values[9]);
        void new_to_old();
        void old_to_new();
};

#endif