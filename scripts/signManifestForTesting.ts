#!/usr/bin/env node

import { md, pki as PKI, util } from 'node-forge';

export async function run(): Promise<void> {
  const dataToSign = '';
  const privateKeyPEM = ``;
  const privateKey = PKI.privateKeyFromPem(privateKeyPEM);

  const digest = md.sha256.create().update(dataToSign);
  const digestSignature = privateKey.sign(digest);
  console.log(util.encode64(digestSignature));
}

run();
