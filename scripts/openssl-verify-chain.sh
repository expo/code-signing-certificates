#!/usr/bin/env bash

openssl verify -CAfile keys/expo-root-certificate.pem -untrusted keys/expo-go-certificate.pem keys/development-certificate.pem