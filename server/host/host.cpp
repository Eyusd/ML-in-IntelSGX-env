// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "project_u.h"
#include "quotefile.h"

static bool EnableVerbosePrintf = true;

void myprintf(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    if (EnableVerbosePrintf){
      printf(format, ap);
    }
    va_end(ap);
}

oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;
    uint32_t flags = 0;

    if (strstr(enclave_path, "debug") != NULL)
    {
        flags = OE_ENCLAVE_FLAG_DEBUG;
    }

    myprintf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_project_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        flags,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        myprintf(
            "Host: oe_create_remoteattestation_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        myprintf("Host: Enclave successfully created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    myprintf("Host: Enclave successfully terminated.\n");
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result = OE_OK;
    int ret = 1;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;
    oe_report_t parsed_report = {0};

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


    if (argc != 3)
    {
        myprintf("\nUsage: genquote_host <path-to-enclave-binary> <json-file-name>\n");
        myprintf("  - generates remote quote for the enclave\n");
        myprintf("  - writes remote quote, parsed data and enclave held data to a json file\n\n");
        return 1;
    }
    // Creating the enclave
    myprintf("Host: Creating the enclave\n");
    enclave = create_enclave(argv[1]);
    if (enclave == NULL)
    {
        goto exit;
    }

    // Getting Attestation
    myprintf("Host: Requesting a remote report and the encryption key from the enclave\n");
    result = get_remote_report_with_pubkey(
        enclave,
        &ret,
        &pem_key,
        &pem_key_size,
        &remote_report,
        &remote_report_size);
    if ((result != OE_OK) || (ret != 0))
    {
        myprintf(
            "Host: get_remote_report_with_pubkey failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }

    myprintf("Host: The enclave's public key: \n%s\n", pem_key);

    myprintf("Host: Parsing the generated report and writing to a local file\n");
    result = oe_parse_report(remote_report, remote_report_size, &parsed_report);
    if (result != OE_OK)
    {
        myprintf(
            "Host: oe_parse_report failed. %s\n",
            oe_result_str(result));
        if (ret == 0)
            ret = 1;
        goto exit;
    }
    else
    {
        QuoteFile  myQuoteFile (parsed_report, remote_report, remote_report_size, pem_key, pem_key_size);

        printf("    JSON file created: %s\n", argv[2]);
        myQuoteFile.WriteToJsonFile("./quotes", argv[2]);
        if (EnableVerbosePrintf) 
        {
            myQuoteFile.WriteToJsonFile(stdout);
        }
    }

    // Main Loop
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
