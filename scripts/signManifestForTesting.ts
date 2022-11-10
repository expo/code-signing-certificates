#!/usr/bin/env node

/**
 * A simple helper script to sign the SHA-256 hash of a string with a RSA private key.
 * Outputs the Base64-encoded result.
 *
 * Usage: replace `dataToSign` and `privateKeyPEM` with your own values.
 * - `dataToSign` - the manifest string (or multipart manifest response part)
 * - `privateKeyPEM` - the PEM-encoded private key.
 *
 * The values for these that are checked into the repo are the same ones that are publicly
 * used in tests in the `expo/expo` repo.
 */

import { md, pki as PKI, util } from 'node-forge';

export async function run(): Promise<void> {
  const dataToSign =
    '{"id":"0754dad0-d200-d634-113c-ef1f26106028","createdAt":"2021-11-23T00:57:14.437Z","runtimeVersion":"1","assets":[{"hash":"cb65fafb5ed456fc3ed8a726cf4087d37b875184eba96f33f6d99104e6e2266d","key":"489ea2f19fa850b65653ab445637a181.jpg","contentType":"image/jpeg","url":"http://192.168.64.1:3000/api/assets?asset=updates/1/assets/489ea2f19fa850b65653ab445637a181&runtimeVersion=1&platform=android","fileExtension":".jpg"}],"launchAsset":{"hash":"323ddd1968ee76d4ddbb16b04fb2c3f1b6d1ab9b637d819699fecd6fa0ffb1a8","key":"696a70cf7035664c20ea86f67dae822b.bundle","contentType":"application/javascript","url":"http://192.168.64.1:3000/api/assets?asset=updates/1/bundles/android-696a70cf7035664c20ea86f67dae822b.js&runtimeVersion=1&platform=android","fileExtension":".bundle"},"extra":{"scopeKey":"@test/app","eas":{"projectId":"285dc9ca-a25d-4f60-93be-36dc312266d7"}}}';
  const privateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
  MIIEpAIBAAKCAQEAwUu28xC4lCjgfEDYdHtDore4+75O2SAncrwb/gAez2G4CJk7
  yUmdwiU35g2DreexDXfpHlf0Zw/W/LueYo66CQaEfEAElVbBGJoANXL/aMFGJCA8
  bAI8VfSWad1IDXkZkOyCiNSe5sjZ1EN0SHJUmZCTu1YhxksEzFwWp2jvzsI2OkjO
  hHGvPVzHKTnP9MQgYnRZDqp/45yF5N7jwKC4zzEHF+d+fgFGsnr8Eq+mKj1dMzhj
  mCctup+NNXh95rv1Gb3lsuqqe1bpnAZs/AJL0yQ4H0r9OD5N4KYuHfKuAAa7TOOq
  lpcOlDDIeUev4ujrv/OdusU4Tpt6hKRBl8mdlQIDAQABAoIBAEVijWCA/xDH/5T6
  nfhqCuRM+Mz9CkasYRyxY4bwuh6NIEeN4cUmdMetHnypGzyAr7B6+6ZVwjiAmhaM
  rpUIUMVOnp4PSNXml1fiZ/LHveD3h9sN60KGJuxf6OJFeUjE0KWSEGVXlVaYgIDO
  Wd5rk+yv1ifoCiWo5icJY2RiqbpYouveqb/InkQU+irZEwCviNvN1ZyJKqquNgcG
  FaY7iVd3WlHRealF1OfKHCBvSah9H5UBFWRBWUds2/xNzpCTAAGsmXdG6O9wPuEQ
  IhJqnSkTiQw49vyOH708VQnBfz/MILV7uTYqQ0Tep3+xkFFy4BSUIb6fE2zJegs5
  80MxIh0CgYEA4yf8cBcYidTAeoDbl2UXasDHAmNKeR4IxKAR3AJOiETIKDv4vAMP
  oBvHnUnnUQa5LhihrVXCbVwGqwATDka73K8sW/TkCE7OmuLDpZYvU/XQRWI74rka
  A/+nbD26NlwnM/a8mJNhbCVns/+PlLq1rK/5WlINcRNVk8PZ1UpG+nsCgYEA2dcM
  1TBZs1iqa+9AQ6nco5MWbsp3roq3sM06UneK0EGffWXPcmQkBZI9Jg+p5P2o/H13
  cYvkyKGmnL8qRZViXWEa/NI60kphQmFNGr+J/3PlKCOqZhlyqGhCFN9KLumJL17P
  XUuzVAa14UsfIFCiv7R33D02o/xw89u5TN+3ky8CgYEAhmkzszPHXk9YcWRsC2JS
  /+UAHQaZm59M+uPojXGD/JgOg9gwrzd0eH3XmNeRG13KF1+V01YKjOFGRMrve6QZ
  J1Uz/1mh0NSo5fdGY2XBrYGnclbVLqvum+0bqS3BUMcon1PhdrrGi9J6UYTn9c6h
  D4S1HF+u+njBS4U5ET85Tp8CgYEAno0bVf+/Cf467BxTFeyIHrZr2W+b9HoagKCf
  Fm7TpghdYRO9DXE9lqB9yToVWgoV+NAJI6fCeRTPA79PsR2tXnHTBris/2oLqBjR
  2eoXMsrTu4dZ+r4C6fgYQMDUaZiotMW5ABqdB0drEfNvUEHgcs+TfcVAA9M1EwiV
  shIStxkCgYBnxccKAfXywLjhVUCa50TsCrL8ToQ7WmWjU1LqN2iO/htFoxeIx4xP
  N7YauagBhyuypcq7SV3bKsdxlCzKi0cMNEonuRJb1Ejo3iU+4F7rzqsltGTjLtpB
  pgp5HP8sALzFZlWWif6W1TjzNJ87MIphr/VPcitRc9n4hWcbmxDvZA==
  -----END RSA PRIVATE KEY-----`;
  const privateKey = PKI.privateKeyFromPem(privateKeyPEM);

  const digest = md.sha256.create().update(dataToSign);
  const digestSignature = privateKey.sign(digest);
  console.log(util.encode64(digestSignature));
}

run();
