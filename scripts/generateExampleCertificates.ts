#!/usr/bin/env node

/**
 * This script generates an example chain of certificates simulating the Expo Go
 * use case, which is as follows:
 * - Root CA certificate embedded in Expo Go client. Private key stored offline.
 * - Intermediate CA certificate generated and served alongside the manifest, verified against embedded root certificate.
 *   Private key stored on server to sign manifests on-demand and generate child code signing certificate on-demand.
 * - Child code signing certificate generated via a CSR for offline development using `expo start`, and served alongside the
 *   development manifest in addition to the intermediate certificate.
 */

import fs from 'fs/promises';
import type { KeyObject } from 'node:crypto';

import {
  convertCertificateToCertificatePEM,
  generateCSR,
  generateDevelopmentCertificateFromCSR,
  generateKeyPair,
} from '../src/main';
import {
  type CodeSigningCertificate,
  type CertificateSigningRequest,
  getCertificateData,
} from '../src/x509';
import { createCertificate, type CertificateExtension } from '../src/x509Generation';

type KeysAndCertificate = {
  publicKey: KeyObject;
  privateKey: KeyObject;
  certificate: CodeSigningCertificate;
};

type KeysAndCSR = {
  publicKey: KeyObject;
  privateKey: KeyObject;
  csr: CertificateSigningRequest;
};

const testAppId = '285dc9ca-a25d-4f60-93be-36dc312266d7';
const testScopeKey = '@test/app';

export async function run(): Promise<void> {
  const root = await generateExpoRootCertificateAsync();
  await exportCertificateAndKeysAsync(root, 'expo-root');

  const expoGo = await generateExpoGoIntermediateCertificate(root);
  await exportCertificateAndKeysAsync(expoGo, 'expo-go');

  const developmentCSR = await generateDevelopmentCSR(testAppId);

  const testDevelopmentCert = await generateTestDevelopmentCertificate(developmentCSR, expoGo);
  await exportCertificateAndKeysAsync(testDevelopmentCert, 'development');
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

async function generateExpoRootCertificateAsync(): Promise<KeysAndCertificate> {
  const { privateKey, publicKey } = generateKeyPair();

  // 20 year validity
  const validityNotBefore = new Date();
  const validityNotAfter = new Date();
  validityNotAfter.setFullYear(validityNotBefore.getFullYear() + 20);

  const attrs = [
    {
      name: 'commonName',
      value: 'Expo Root Certificate',
    },
    {
      name: 'countryName',
      value: 'US',
    },
    {
      shortName: 'ST',
      value: 'California',
    },
    {
      name: 'localityName',
      value: 'Palo Alto',
    },
    {
      name: 'organizationName',
      value: 'Expo',
    },
    {
      shortName: 'OU',
      value: 'Engineering',
    },
  ];

  const extensions: CertificateExtension[] = [
    {
      name: 'basicConstraints',
      cA: true,
    },
    {
      name: 'keyUsage',
      critical: true,
      keyCertSign: true,
      cRLSign: true,
      digitalSignature: false,
      nonRepudiation: false,
      keyEncipherment: false,
      dataEncipherment: false,
    },
  ];

  const certificate = createCertificate({
    publicKey,
    signingKey: privateKey,
    subject: attrs,
    issuer: attrs,
    notBefore: validityNotBefore,
    notAfter: validityNotAfter,
    extensions,
  });

  return {
    privateKey,
    publicKey,
    certificate,
  };
}

async function generateExpoGoIntermediateCertificate(
  rootKeysAndCert: KeysAndCertificate
): Promise<KeysAndCertificate> {
  const { privateKey, publicKey } = generateKeyPair();

  // 2 year validity
  const validityNotBefore = new Date();
  const validityNotAfter = new Date();
  validityNotAfter.setFullYear(validityNotBefore.getFullYear() + 2);

  const attrs = [
    {
      name: 'commonName',
      value: 'Expo Go Certificate',
    },
    {
      name: 'countryName',
      value: 'US',
    },
    {
      shortName: 'ST',
      value: 'California',
    },
    {
      name: 'localityName',
      value: 'Palo Alto',
    },
    {
      name: 'organizationName',
      value: 'Expo',
    },
    {
      shortName: 'OU',
      value: 'Engineering',
    },
  ];

  const extensions: CertificateExtension[] = [
    {
      name: 'basicConstraints',
      critical: true,
      cA: true,
      pathLenConstraint: 0, // no subsequent intermediate certificates allowed
    },
    {
      name: 'keyUsage',
      critical: true,
      keyCertSign: true,
      cRLSign: true,
      digitalSignature: true,
      nonRepudiation: false,
      keyEncipherment: false,
      dataEncipherment: false,
    },
    {
      name: 'extKeyUsage',
      critical: true,
      serverAuth: false,
      clientAuth: false,
      codeSigning: true,
      emailProtection: false,
      timeStamping: false,
    },
  ];

  const certificate = createCertificate({
    publicKey,
    signingKey: rootKeysAndCert.privateKey,
    subject: attrs,
    issuer: getCertificateData(rootKeysAndCert.certificate).parsed.tbsCertificate.subject,
    notBefore: validityNotBefore,
    notAfter: validityNotAfter,
    extensions,
  });

  return {
    privateKey,
    publicKey,
    certificate,
  };
}

async function generateDevelopmentCSR(projectId: string): Promise<KeysAndCSR> {
  const keyPair = generateKeyPair();
  const csr = generateCSR(keyPair, `Expo Go Development Certificate ${projectId}`);
  return {
    ...keyPair,
    csr,
  };
}

async function generateTestDevelopmentCertificate(
  csrKeysAndCSR: KeysAndCSR,
  intermediate: KeysAndCertificate
): Promise<KeysAndCertificate> {
  const certificate = generateDevelopmentCertificateFromCSR(
    intermediate.privateKey,
    intermediate.certificate,
    csrKeysAndCSR.csr,
    testAppId,
    testScopeKey
  );

  return {
    privateKey: csrKeysAndCSR.privateKey,
    publicKey: csrKeysAndCSR.publicKey,
    certificate,
  };
}

void run();
