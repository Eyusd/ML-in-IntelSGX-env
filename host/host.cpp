#include <openenclave/host.h>
#include <stdio.h>
#include "linereg_u.h"
#include <openenclave/attestation/sgx/evidence.h>

// SGX Local Attestation UUID.
static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
//
// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

oe_enclave_t* create_enclave(const char* enclave_path, uint32_t flags)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_attestation_enclave(
        enclave_path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_attestation_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave successfully created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: Enclave successfully terminated.\n");
}

//Fin Att

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 1;
    oe_enclave_t* enclave = NULL;

    //Program loop
    char choice;
    char useless;
    bool run = true;
    bool print = true;
    //Train
        FILE *csv_file;
        double values_t[9];
        double expected;
        bool allgood = true;
        double loss = 0.00000;
        double mean_loss;
        int compt;
    //Infer
        double values[9];
        double output;

    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s enclave_image_path [ --simulate  ]\n", argv[0]);
        goto exit;
    }




    //Run program
    result = enclave_init(enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "calling into enclave_linereg failed: result=%u (%s)\n", result, oe_result_str(result));
        goto exit;
    }
    enclave_new_to_old(enclave);

    while (run)
    {
        if (print) {
            fprintf(stderr, "\n");    
            fprintf(stderr, "Train, Infer, or Exit ? [t/i/e] ");
        }
        print = false;
        scanf("%c", &choice);
        switch (choice)
        {
            case 't':
                enclave_new_to_old(enclave);
                csv_file = fopen("trainingset2.csv", "r");
                compt = 0;
                while (fscanf(csv_file, "%lf,%lf,%lf,%lf,%lf,%lf,%lf,%lf,%lf,%lf\n", &values_t[0],&values_t[1],&values_t[2],&values_t[3],&values_t[4],&values_t[5],&values_t[6],&values_t[7],&values_t[8],&expected) == 10)
                {
                    enclave_train(enclave, values_t, expected, &loss);
                    compt+=1;
                    if (loss > 100000000) {
                        allgood = false;
                    }
                    else {
                        mean_loss += loss;
                    }
                }
                if (allgood)
                {
                    mean_loss = mean_loss / ((double) compt);
                    fprintf(stderr, "Training set registered successfully \nMean Loss : %lf\nSets : %i\n", mean_loss, compt);
                    enclave_new_to_old(enclave);
                }
                else
                {
                    fprintf(stderr, "Something went wrong \n");
                    enclave_old_to_new(enclave);
                }
                break;
            
            case 'i':
                scanf("%lf, %lf, %lf, %lf, %lf, %lf, %lf, %lf, %lf", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5], &values[6], &values[7], &values[8]);

                enclave_infer(enclave, values, &output);
                fprintf(stderr, "%lf \n", output);

                break;
            
            case 'e':
                run = false;
                break;

            default:
                print = true;
                break;
        }
    }

    ret = 0;

exit:
    if (pem_key)
        free(pem_key);

    if (remote_report)
        free(remote_report);

    myprintf("Host: Terminating enclave\n");
    if (enclave)
        terminate_enclave(enclave);

    myprintf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}