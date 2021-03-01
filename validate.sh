#!/usr/bin/env bash

trap "rm test.crt; rm test.key" EXIT

./minikube-client -cn "test" -o "test" -out .

openssl x509 -noout -modulus -in test.crt | openssl md5
openssl rsa -noout -modulus -in test.key | openssl md5

openssl verify -verbose -CAfile ~/.minikube/ca.crt test.crt