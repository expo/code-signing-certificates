#!/usr/bin/env node

/**
 * Simple wrapper script around {@link generateSelfSignedCodeSigningCertificate}.
 */

import fs from 'fs/promises';
import type { KeyObject } from 'node:crypto';

import {
  convertCertificateToCertificatePEM,
  generateKeyPair,
  generateSelfSignedCodeSigningCertificate,
} from '../src/main';
import type { CodeSigningCertificate } from '../src/x509';

type KeysAndCertificate = {
  publicKey: KeyObject;
  privateKey: KeyObject;
  certificate: CodeSigningCertificate;
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
    fs.writeFile(
      `keys/${prefix}-public-key.pem`,
      publicKey.export({ type: 'spki', format: 'pem' })
    ),
    fs.writeFile(
      `keys/${prefix}-private-key.pem`,
      privateKey.export({ type: 'pkcs1', format: 'pem' })
    ),
    fs.writeFile(`keys/${prefix}-certificate.pem`, convertCertificateToCertificatePEM(certificate)),
  ]);
}

void run();
