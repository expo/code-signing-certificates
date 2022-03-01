#!/usr/bin/env node

import fs from 'fs/promises';
import { pki as PKI, pki } from 'node-forge';

import { generateKeyPair, generateSelfSignedCodeSigningCertificate } from '../src/main';

type KeysAndCertificate = {
  publicKey: pki.rsa.PublicKey;
  privateKey: pki.rsa.PrivateKey;
  certificate: pki.Certificate;
};

export async function run(): Promise<void> {
  const keyPair = generateKeyPair();
  const validityNotBefore = new Date();
  const validityNotAfter = new Date();
  validityNotAfter.setFullYear(validityNotBefore.getFullYear() + 100);
  const certificate = generateSelfSignedCodeSigningCertificate({
    keyPair,
    validityNotBefore,
    validityNotAfter,
    commonName: 'test',
  });
  await exportCertificateAndKeysAsync({ ...keyPair, certificate }, 'test');
}

async function exportCertificateAndKeysAsync(
  { privateKey, publicKey, certificate }: KeysAndCertificate,
  prefix: string
): Promise<void> {
  await Promise.all([
    fs.writeFile(`keys/${prefix}-public-key.pem`, PKI.publicKeyToPem(publicKey)),
    fs.writeFile(`keys/${prefix}-private-key.pem`, PKI.privateKeyToPem(privateKey)),
    fs.writeFile(`keys/${prefix}-certificate.pem`, PKI.certificateToPem(certificate)),
  ]);
}

run();
