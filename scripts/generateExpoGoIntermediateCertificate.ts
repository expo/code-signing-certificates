import fs from 'fs/promises';
import { pki as PKI, util, random, md, pki } from 'node-forge';

import {
  convertCertificatePEMToCertificate,
  convertPrivateKeyPEMToPrivateKey,
  generateKeyPair,
} from '../src/main';
import { toPositiveHex } from '../src/utils';

type KeysAndCertificate = {
  publicKey: pki.rsa.PublicKey;
  privateKey: pki.rsa.PrivateKey;
  certificate: pki.Certificate;
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

  const certificate = PKI.createCertificate();
  certificate.publicKey = publicKey;
  certificate.serialNumber = toPositiveHex(util.bytesToHex(random.getBytesSync(9)));

  // 2 year validity
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setFullYear(certificate.validity.notBefore.getFullYear() + 2);

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

  certificate.setSubject(attrs);

  certificate.setIssuer(rootKeysAndCert.certificate.subject.attributes);

  certificate.setExtensions([
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
  ]);

  certificate.sign(rootKeysAndCert.privateKey, md.sha256.create());

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
    fs.writeFile(`keys/${prefix}-public-key.pem`, PKI.publicKeyToPem(publicKey)),
    fs.writeFile(`keys/${prefix}-private-key.pem`, PKI.privateKeyToPem(privateKey)),
    fs.writeFile(`keys/${prefix}-certificate.pem`, PKI.certificateToPem(certificate)),
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

run();
