#!/usr/bin/env node

/**
 * This script generates the full set of certificates and private keys needed to run the
 * code signing test suite in the expo-updates package (both iOS and Android).
 */

import * as pem from '@peculiar/utils/pem';
import fs from 'fs/promises';
import type { KeyObject } from 'node:crypto';
import { sign } from 'node:crypto';

import {
  convertCertificateToCertificatePEM,
  expoProjectInformationOID,
  generateCSR,
  generateKeyPair,
} from '../src/main';
import {
  type CodeSigningCertificate,
  type CertificateSigningRequest,
  getCertificateData,
  getCSRData,
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

function withInvalidSignature(certificate: CodeSigningCertificate): string {
  const der = Buffer.from(getCertificateData(certificate).der);
  // The final DER byte is part of the signature, so the certificate stays parseable.
  der[der.length - 1] = der[der.length - 1]! ^ 1;
  return pem.encode('CERTIFICATE', der);
}

export async function run(): Promise<void> {
  // self-signed normal
  const test = await generateSelfSigned(
    (validityNotBefore, validityNotAfter) => {
      validityNotAfter.setFullYear(validityNotBefore.getFullYear() + 100);
    },
    (extensions) => extensions
  );
  await exportCertificateAndKeysAsync(test, 'test');

  // self-signed validity expired
  const validityExpired = await generateSelfSigned(
    (validityNotBefore, validityNotAfter) => {
      validityNotBefore.setDate(validityNotBefore.getDate() - 2);
      validityNotAfter.setDate(validityNotAfter.getDate() - 1);
    },
    (extensions) => extensions
  );
  await exportCertificateAndKeysAsync(validityExpired, 'validityExpired');

  // self-signed no keyUsage
  const noKeyUsage = await generateSelfSigned(
    (validityNotBefore, validityNotAfter) => {
      validityNotAfter.setFullYear(validityNotBefore.getFullYear() + 100);
    },
    (extensions) => extensions.filter((ext) => ext.name !== 'keyUsage')
  );
  await exportCertificateAndKeysAsync(noKeyUsage, 'noKeyUsage');

  // self-signed no extendedKeyUsage
  const noCodeSigningExtendedUsage = await generateSelfSigned(
    (validityNotBefore, validityNotAfter) => {
      validityNotAfter.setFullYear(validityNotBefore.getFullYear() + 100);
    },
    (extensions) => extensions.filter((ext) => ext.name !== 'extKeyUsage')
  );
  await exportCertificateAndKeysAsync(noCodeSigningExtendedUsage, 'noCodeSigningExtendedUsage');

  // self-signed signature invalid
  await fs.writeFile(
    `generated-test-data/signatureInvalid.pem`,
    withInvalidSignature(test.certificate)
  );

  // normal chain
  const chainRoot = await generateExpoRootCertificateAsync((extensions) => extensions);
  await exportCertificateAndKeysAsync(chainRoot, 'chainRoot');
  const chainIntermediate = await generateExpoGoIntermediateCertificate(
    chainRoot,
    (extensions) => extensions
  );
  await exportCertificateAndKeysAsync(chainIntermediate, 'chainIntermediate');
  const chainLeafCSR = await generateDevelopmentCSR(testAppId);
  const chainLeaf = await generateTestDevelopmentCertificate(chainLeafCSR, chainIntermediate);
  await exportCertificateAndKeysAsync(chainLeaf, 'chainLeaf');

  // invalid signature chain leaf certificate
  await fs.writeFile(
    `generated-test-data/invalidSignatureChainLeaf.pem`,
    withInvalidSignature(chainLeaf.certificate)
  );

  // not CA intermediate chain
  const chainNotCARoot = await generateExpoRootCertificateAsync((extensions) => extensions);
  await exportCertificateAndKeysAsync(chainNotCARoot, 'chainNotCARoot');
  const chainNotCAIntermediate = await generateExpoGoIntermediateCertificate(
    chainNotCARoot,
    (extensions) => extensions.filter((ext) => ext.name !== 'basicConstraints')
  );
  await exportCertificateAndKeysAsync(chainNotCAIntermediate, 'chainNotCAIntermediate');
  const chainNotCALeafCSR = await generateDevelopmentCSR(testAppId);
  const chainNotCALeaf = await generateTestDevelopmentCertificate(
    chainNotCALeafCSR,
    chainNotCAIntermediate
  );
  await exportCertificateAndKeysAsync(chainNotCALeaf, 'chainNotCALeaf');

  // chain path len violation
  const chainPathLenViolationRoot = await generateExpoRootCertificateAsync((extensions) =>
    extensions.map((ext) => {
      if (ext.name === 'basicConstraints') {
        ext.pathLenConstraint = 0; // no subsequent intermediate certificates allowed
      }
      return ext;
    })
  );
  await exportCertificateAndKeysAsync(chainPathLenViolationRoot, 'chainPathLenViolationRoot');
  const chainPathLenViolationIntermediate = await generateExpoGoIntermediateCertificate(
    chainPathLenViolationRoot,
    (extensions) => extensions
  );
  await exportCertificateAndKeysAsync(
    chainPathLenViolationIntermediate,
    'chainPathLenViolationIntermediate'
  );
  const chainPathLenViolationLeafCSR = await generateDevelopmentCSR(testAppId);
  const chainPathLenViolationLeaf = await generateTestDevelopmentCertificate(
    chainPathLenViolationLeafCSR,
    chainPathLenViolationIntermediate
  );
  await exportCertificateAndKeysAsync(chainPathLenViolationLeaf, 'chainPathLenViolationLeaf');

  // chain expo project information mismatch
  const chainExpoProjectInformationViolationRoot = await generateExpoRootCertificateAsync(
    (extensions) => extensions
  );
  await exportCertificateAndKeysAsync(
    chainExpoProjectInformationViolationRoot,
    'chainExpoProjectInformationViolationRoot'
  );
  const chainExpoProjectInformationViolationIntermediate =
    await generateExpoGoIntermediateCertificate(
      chainExpoProjectInformationViolationRoot,
      (extensions) => [
        ...extensions,
        {
          name: 'expoProjectInformation',
          id: expoProjectInformationOID,
          value: `${testAppId},@fake/other`,
        },
      ]
    );
  await exportCertificateAndKeysAsync(
    chainExpoProjectInformationViolationIntermediate,
    'chainExpoProjectInformationViolationIntermediate'
  );
  const chainExpoProjectInformationViolationLeafCSR = await generateDevelopmentCSR(testAppId);
  const chainExpoProjectInformationViolationLeaf = await generateTestDevelopmentCertificate(
    chainExpoProjectInformationViolationLeafCSR,
    chainExpoProjectInformationViolationIntermediate
  );
  await exportCertificateAndKeysAsync(
    chainExpoProjectInformationViolationLeaf,
    'chainExpoProjectInformationViolationLeaf'
  );

  // signatures

  const testNewManifestBody =
    '{"id":"0754dad0-d200-d634-113c-ef1f26106028","createdAt":"2021-11-23T00:57:14.437Z","runtimeVersion":"1","assets":[{"hash":"cb65fafb5ed456fc3ed8a726cf4087d37b875184eba96f33f6d99104e6e2266d","key":"489ea2f19fa850b65653ab445637a181.jpg","contentType":"image/jpeg","url":"http://192.168.64.1:3000/api/assets?asset=updates/1/assets/489ea2f19fa850b65653ab445637a181&runtimeVersion=1&platform=android","fileExtension":".jpg"}],"launchAsset":{"hash":"323ddd1968ee76d4ddbb16b04fb2c3f1b6d1ab9b637d819699fecd6fa0ffb1a8","key":"696a70cf7035664c20ea86f67dae822b.bundle","contentType":"application/javascript","url":"http://192.168.64.1:3000/api/assets?asset=updates/1/bundles/android-696a70cf7035664c20ea86f67dae822b.js&runtimeVersion=1&platform=android","fileExtension":".bundle"},"extra":{"scopeKey":"@test/app","eas":{"projectId":"285dc9ca-a25d-4f60-93be-36dc312266d7"}}}';

  const testDigestSignature = sign('RSA-SHA256', Buffer.from(testNewManifestBody), test.privateKey);
  console.log(
    `testNewManifestBodySignature = "sig=\\"${testDigestSignature.toString('base64')}\\""`
  );

  const chainLeafDigestSignature = sign(
    'RSA-SHA256',
    Buffer.from(testNewManifestBody),
    chainLeaf.privateKey
  );
  console.log(
    `testNewManifestBodyValidChainLeafSignature = "sig=\\"${chainLeafDigestSignature.toString('base64')}\\""`
  );

  const testNewManifestBodyIncorrectProjectId =
    '{"id":"0754dad0-d200-d634-113c-ef1f26106028","createdAt":"2021-11-23T00:57:14.437Z","runtimeVersion":"1","assets":[{"hash":"cb65fafb5ed456fc3ed8a726cf4087d37b875184eba96f33f6d99104e6e2266d","key":"489ea2f19fa850b65653ab445637a181.jpg","contentType":"image/jpeg","url":"http://192.168.64.1:3000/api/assets?asset=updates/1/assets/489ea2f19fa850b65653ab445637a181&runtimeVersion=1&platform=android","fileExtension":".jpg"}],"launchAsset":{"hash":"323ddd1968ee76d4ddbb16b04fb2c3f1b6d1ab9b637d819699fecd6fa0ffb1a8","key":"696a70cf7035664c20ea86f67dae822b.bundle","contentType":"application/javascript","url":"http://192.168.64.1:3000/api/assets?asset=updates/1/bundles/android-696a70cf7035664c20ea86f67dae822b.js&runtimeVersion=1&platform=android","fileExtension":".bundle"},"extra":{"scopeKey":"@test/app","eas":{"projectId":"485dc9ca-a25d-4f60-93be-36dc312266d8"}}}';
  const chainLeafIncorrectProjectIdDigestSignature = sign(
    'RSA-SHA256',
    Buffer.from(testNewManifestBodyIncorrectProjectId),
    chainLeaf.privateKey
  );
  console.log(
    `testNewManifestBodyValidChainLeafSignatureIncorrectProjectId = "sig=\\"${chainLeafIncorrectProjectIdDigestSignature.toString('base64')}\\""`
  );
}

async function exportCertificateAndKeysAsync(
  { privateKey, certificate }: KeysAndCertificate,
  testCase: string
): Promise<void> {
  await Promise.all([
    fs.writeFile(
      `generated-test-data/privatekeys/${testCase}-privateKey.pem`,
      privateKey.export({ type: 'pkcs1', format: 'pem' })
    ),
    fs.writeFile(
      `generated-test-data/${testCase}.pem`,
      convertCertificateToCertificatePEM(certificate)
    ),
  ]);
}

async function generateSelfSigned(
  validityBlock: (notBefore: Date, notAfter: Date) => void,
  extensionsModifierBlock: (extensions: CertificateExtension[]) => CertificateExtension[]
): Promise<KeysAndCertificate> {
  const keyPair = generateKeyPair();
  const validityNotBefore = new Date();
  const validityNotAfter = new Date();
  validityBlock(validityNotBefore, validityNotAfter);

  const attrs = [
    {
      name: 'commonName',
      value: 'test',
    },
  ];

  const extensions: CertificateExtension[] = extensionsModifierBlock([
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
  ]);

  const cert = createCertificate({
    publicKey: keyPair.publicKey,
    signingKey: keyPair.privateKey,
    subject: attrs,
    issuer: attrs,
    notBefore: validityNotBefore,
    notAfter: validityNotAfter,
    extensions,
  });

  return {
    ...keyPair,
    certificate: cert,
  };
}

async function generateExpoRootCertificateAsync(
  extensionsModifierBlock: (extensions: CertificateExtension[]) => CertificateExtension[]
): Promise<KeysAndCertificate> {
  const { privateKey, publicKey } = generateKeyPair();

  // 100 year validity
  const validityNotBefore = new Date();
  const validityNotAfter = new Date();
  validityNotAfter.setFullYear(validityNotBefore.getFullYear() + 100);

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

  const extensions: CertificateExtension[] = extensionsModifierBlock([
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
  rootKeysAndCert: KeysAndCertificate,
  extensionsModifierBlock: (extensions: CertificateExtension[]) => CertificateExtension[]
): Promise<KeysAndCertificate> {
  const { privateKey, publicKey } = generateKeyPair();

  // 100 year validity
  const validityNotBefore = new Date();
  const validityNotAfter = new Date();
  validityNotAfter.setFullYear(validityNotBefore.getFullYear() + 100);

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

  const extensions: CertificateExtension[] = extensionsModifierBlock([
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
  const csr = csrKeysAndCSR.csr;
  const issuerCertificate = intermediate.certificate;
  const issuerPrivateKey = intermediate.privateKey;

  // 100 year validity
  const validityNotBefore = new Date();
  const validityNotAfter = new Date();
  validityNotAfter.setFullYear(validityNotBefore.getFullYear() + 100);

  const extensions: CertificateExtension[] = [
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
  ];

  const certificate = createCertificate({
    publicKey: csrKeysAndCSR.publicKey,
    signingKey: issuerPrivateKey,
    subject: getCSRData(csr).parsed.certificationRequestInfo.subject,
    issuer: getCertificateData(issuerCertificate).parsed.tbsCertificate.subject,
    notBefore: validityNotBefore,
    notAfter: validityNotAfter,
    extensions,
  });

  return {
    privateKey: csrKeysAndCSR.privateKey,
    publicKey: csrKeysAndCSR.publicKey,
    certificate,
  };
}

void run();
