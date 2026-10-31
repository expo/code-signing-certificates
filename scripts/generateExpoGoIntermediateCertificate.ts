import fs from 'fs/promises';
import type { KeyObject } from 'node:crypto';

import {
  convertCertificatePEMToCertificate,
  convertCertificateToCertificatePEM,
  convertPrivateKeyPEMToPrivateKey,
  generateKeyPair,
} from '../src/main';
import { type CodeSigningCertificate, getCertificateData } from '../src/x509';
import { createCertificate, type CertificateExtension } from '../src/x509Generation';

type KeysAndCertificate = {
  publicKey: KeyObject;
  privateKey: KeyObject;
  certificate: CodeSigningCertificate;
};

/**
 * Generate a new Expo Go intermediate certificate from the existing root private key and certificate.
 * (The Expo root key and certificate PEMs can be found in 1Password and then copied to the `keys` folder here
 * to be processed by this script).
 */
async function generateExpoGoIntermediateCertificate(
  rootKeysAndCert: Pick<KeysAndCertificate, 'certificate' | 'privateKey'>
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

async function getExpoRootCertificateAsync(): Promise<
  Pick<KeysAndCertificate, 'certificate' | 'privateKey'>
> {
  const privateKeyPEMBuffer = await fs.readFile('keys/expo-root-private-key.pem');
  const privateKey = convertPrivateKeyPEMToPrivateKey(privateKeyPEMBuffer.toString());
  const certificatePEMBuffer = await fs.readFile('keys/expo-root-certificate.pem');
  const certificate = convertCertificatePEMToCertificate(certificatePEMBuffer.toString());

  return {
    privateKey,
    certificate,
  };
}

export async function run(): Promise<void> {
  const root = await getExpoRootCertificateAsync();

  const expoGo = await generateExpoGoIntermediateCertificate(root);
  await exportCertificateAndKeysAsync(expoGo, 'expo-go');
}

void run();
