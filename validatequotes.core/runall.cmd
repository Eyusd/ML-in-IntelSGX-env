@echo off
rem 
rem script to verify all example remote attestation quotes 
rem
dotnet run ../genquotes/quotes/enclave.info.debug.json               sharedcus.cus.attest.azure.net    false
