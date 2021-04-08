#!/bin/bash
# 
# Script to verify all example remote attestation quotes
#
dotnet run ../../server/quotes/enclave.info.debug.json              sharedcus.cus.attest.azure.net    false

