#!/usr/bin/env node

import fs from 'fs/promises';
import { pki as PKI, util, random, md, pki } from 'node-forge';

import { generateKeyPair } from '../src/main';
import { toPositiveHex } from '../src/utils';

type KeysAndCertificate = {
  publicKey: pki.rsa.PublicKey;
  privateKey: pki.rsa.PrivateKey;
  certificate: pki.Certificate;
};

type KeysAndCSR = {
  publicKey: pki.rsa.PublicKey;
  privateKey: pki.rsa.PrivateKey;
  csr: pki.CertificateRequest;
};

const testAppId = '285dc9ca-a25d-4f60-93be-36dc312266d7';
const testScopeKey = '@test/app';

// generated with oidgen script. in the microsoft OID space. could apply for Expo space but would take time: https://pen.iana.org/pen/PenApplication.page
const expoProjectInformationOID =
  '1.2.840.113556.1.8000.2554.43437.254.128.102.157.7894389.20439.2.1';

export async function run(): Promise<void> {
  const root = await generateExpoRootCertificateAsync();
  await exportCertificateAndKeysAsync(root, 'expo-root');

  const expoGo = await generateExpoGoIntermediateCertificate(root);
  await exportCertificateAndKeysAsync(expoGo, 'expo-go');

  const developmentCSR = await generateDevelopmentCSR(testAppId, testScopeKey);

  const testDevelopmentCert = await generateTestDevelopmentCertificate(developmentCSR, expoGo);
  await exportCertificateAndKeysAsync(testDevelopmentCert, 'development');

  // verify certificate chain
  // const caStore = PKI.createCaStore();
  // caStore.addCertificate(expoGo.certificate);
  // const chain = [testDevelopmentCert.certificate, expoGo.certificate];
  // PKI.verifyCertificateChain(caStore, chain);
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

async function generateExpoRootCertificateAsync(): Promise<KeysAndCertificate> {
  const { privateKey, publicKey } = generateKeyPair();

  const certificate = PKI.createCertificate();
  certificate.publicKey = publicKey;
  certificate.serialNumber = toPositiveHex(util.bytesToHex(random.getBytesSync(9)));

  // 20 year validity
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setFullYear(certificate.validity.notBefore.getFullYear() + 20);

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

  // root certificate is self-signed
  certificate.setSubject(attrs);
  certificate.setIssuer(attrs);

  certificate.setExtensions([
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
  ]);

  certificate.sign(privateKey, md.sha256.create());

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

async function generateDevelopmentCSR(projectId: string, scopeKey: string): Promise<KeysAndCSR> {
  const { privateKey, publicKey } = generateKeyPair();

  const csr = pki.createCertificationRequest();
  csr.publicKey = publicKey;

  const attrs = [
    {
      name: 'commonName',
      value: `Expo Go Development Certificate ${projectId}`,
    },
  ];
  csr.setSubject(attrs);

  return {
    publicKey,
    privateKey,
    csr,
  };
}

async function generateTestDevelopmentCertificate(
  csrKeysAndCSR: KeysAndCSR,
  intermediate: KeysAndCertificate
): Promise<KeysAndCertificate> {
  // TODO: check if csr is valid

  const certificate = PKI.createCertificate();
  certificate.publicKey = csrKeysAndCSR.csr.publicKey;
  certificate.serialNumber = toPositiveHex(util.bytesToHex(random.getBytesSync(9)));

  // 30 day validity
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setDate(certificate.validity.notBefore.getDate() + 30);

  // only take the subject (and public key) from CSR
  certificate.setSubject(csrKeysAndCSR.csr.subject.attributes);

  certificate.setIssuer(intermediate.certificate.subject.attributes);

  certificate.setExtensions([
    {
      name: 'keyUsage',
      critical: true,
      keyCertSign: false,
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
    {
      name: 'expoProjectInformation',
      id: expoProjectInformationOID,
      // critical: true, // can't be critical since openssl verify doesn't know about this extension
      value: `${testAppId},${testScopeKey}`,
    },
  ]);

  certificate.sign(intermediate.privateKey, md.sha256.create());

  return {
    privateKey: csrKeysAndCSR.privateKey,
    publicKey: csrKeysAndCSR.publicKey,
    certificate,
  };
}

run();
