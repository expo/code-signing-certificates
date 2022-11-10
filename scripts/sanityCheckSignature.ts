#!/usr/bin/env node

/**
 * A simple helper script to verify the Base64-encoded signature of the SHA-256 hash of a string with the RSA public key.
 * Outputs a message indicating whether signature is correct.
 *
 * Usage: replace `stringThatWasSigned`, `digestSignature`, and `certificatePEM` with your own values.
 * - `stringThatWasSigned` - the manifest string (or multipart manifest response part) that was signed
 * - `digestSignature` - Base64-encoded signature.
 * - `certificatePEM` - the PEM-encoded code signing certificate.
 *
 * The values for these that are checked into the repo are the same ones that are publicly
 * used in tests in the `expo/expo` repo.
 */

import { md, pki as PKI, util } from 'node-forge';

export async function run(): Promise<void> {
  const stringThatWasSigned =
    '{"id":"0754dad0-d200-d634-113c-ef1f26106028","createdAt":"2021-11-23T00:57:14.437Z","runtimeVersion":"1","assets":[{"hash":"cb65fafb5ed456fc3ed8a726cf4087d37b875184eba96f33f6d99104e6e2266d","key":"489ea2f19fa850b65653ab445637a181.jpg","contentType":"image/jpeg","url":"http://192.168.64.1:3000/api/assets?asset=updates/1/assets/489ea2f19fa850b65653ab445637a181&runtimeVersion=1&platform=android","fileExtension":".jpg"}],"launchAsset":{"hash":"323ddd1968ee76d4ddbb16b04fb2c3f1b6d1ab9b637d819699fecd6fa0ffb1a8","key":"696a70cf7035664c20ea86f67dae822b.bundle","contentType":"application/javascript","url":"http://192.168.64.1:3000/api/assets?asset=updates/1/bundles/android-696a70cf7035664c20ea86f67dae822b.js&runtimeVersion=1&platform=android","fileExtension":".bundle"},"extra":{"scopeKey":"@test/app","eas":{"projectId":"285dc9ca-a25d-4f60-93be-36dc312266d7"}}}';
  const digestSignature = `iMU4xouvBS6f8Ttr2pUX+r5dJ51489SQfhHb4rG6uBhy5RxaY10o+DE3zVRyRH2yVnmp5Fe7bCQD+REZa0hvt/sKAp1aIhjH8Uv50hADwAPfbyDoOc3Kld2zOGTf70W5J6AyO5QczBrC+wB727CZU+mUkxT6rZ/uBwJVPHAF0qmNGnbJBhMRhGqSB1u/CO49Y7zQ1T53SQvcU2VDq2XtGnPDPCe4qYVV/0oLv1hDSzKqVs6IQu8OYfQwj3naGo3FBFj8fZFbcf8M3B2AU4Q5VigFpLi07rvPyCtDyD6BauU9yk5+sI9RPmm2XtCm1YFzYeicC9BN/QPCBQvj5b7ZIA==`;
  const certificatePEM = `-----BEGIN CERTIFICATE-----
  MIICzTCCAbWgAwIBAgIJWEL03IR99LhMMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV
  BAMTBHRlc3QwIBcNMjIwNDEyMTcyODIzWhgPMjEyMjA0MTIxNzI4MjNaMA8xDTAL
  BgNVBAMTBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBS7bz
  ELiUKOB8QNh0e0Oit7j7vk7ZICdyvBv+AB7PYbgImTvJSZ3CJTfmDYOt57ENd+ke
  V/RnD9b8u55ijroJBoR8QASVVsEYmgA1cv9owUYkIDxsAjxV9JZp3UgNeRmQ7IKI
  1J7myNnUQ3RIclSZkJO7ViHGSwTMXBanaO/OwjY6SM6Eca89XMcpOc/0xCBidFkO
  qn/jnIXk3uPAoLjPMQcX535+AUayevwSr6YqPV0zOGOYJy26n401eH3mu/UZveWy
  6qp7VumcBmz8AkvTJDgfSv04Pk3gpi4d8q4ABrtM46qWlw6UMMh5R6/i6Ou/8526
  xThOm3qEpEGXyZ2VAgMBAAGjKjAoMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8E
  DDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOCAQEATeE0FXXheYjw77pjy6sZ
  b6POytJdYLawMt7Chn11zP1TLx0LA1R01uH/ld0tVQQyt1XqG9AE3as1VCUYklPA
  zmwFSOxcSMiAXobEa5NcJ4S490YTjYmHI8fkz6TS+eeLkIr7eZMbpe6ck9V2d1e3
  0xHshYRc3NceNOKB018QYxbdxuTbV3a6f4yTlCSxKuyYfA5KDMoXaPAKE7Cwddrz
  1dbQpSI6djWknFjhTh7Bu/zpGWEx7wXTZlx9nIhKrinVowvyUkTaaCfuzdCmZOzS
  AJsADnJN0LEKDI4q0kDwl1v6U4cJ5Ru7VQv3xho03LPEA/fFKHK6OITDznspiXRs
  IA==
  -----END CERTIFICATE-----`;
  const certificate = PKI.certificateFromPem(certificatePEM);

  const digest = md.sha256.create().update(stringThatWasSigned);
  const isValidSignature = (certificate.publicKey as PKI.rsa.PublicKey).verify(
    digest.digest().getBytes(),
    util.decode64(digestSignature)
  );

  if (!isValidSignature) {
    throw new Error('Signature not valid for certificate and string');
  } else {
    console.log('Signature valid!');
  }
}

run();
