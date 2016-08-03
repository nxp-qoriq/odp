#!/bin/bash

echo
printf "\n\nTesting Macless_ni.....\n"
./api_test -m macless_ni -s
echo
mv tests_result.txt result_macless.txt
echo
echo

printf "\n\nTesting Timer.....\n"
./api_test -m timer -s
echo
mv tests_result.txt result_timer.txt
echo
echo

printf "\n\nTesting cmdif client.....\n"
./api_test -m ci_client -s
echo
mv tests_result.txt result_ciclient.txt
echo
echo

printf "\n\nTesting cmdif server.....\n"
./api_test -m ci_server -s
echo
mv tests_result.txt result_ciserver.txt
echo
echo

printf "\n\nTesting malloc.....\n"
./api_test -m malloc
echo
mv tests_result.txt result_malloc.txt
echo
echo

printf "\n\nTesting simple_crypto.....\n"
./api_test -m crypto -s
echo
mv tests_result.txt result_crypto.txt
echo
echo
echo

printf "\n\nTest Reports for Tested Modules are : \
\n\nresult_macless.txt\nresult_timer.txt\nresult_ciclient.txt\n\
result_ciserver.txt\nresult_malloc.txt\nresult_crypto.txt\n\n"
