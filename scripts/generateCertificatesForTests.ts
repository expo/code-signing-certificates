#!/usr/bin/env node

import fs from 'fs/promises';
import { pki as PKI, util, random, md, pki } from 'node-forge';

import {
  convertCertificateToCertificatePEM,
  expoProjectInformationOID,
  generateCSR,
  generateKeyPair,
} from '../src/main';
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

function replaceCharAt(str: string, index: number, replacement: string): string {
  return str.substring(0, index) + replacement + str.substring(index + replacement.length);
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
    () => {
      // no-op to set not after to be in the past
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

  // self-signed signature invalid (manually modified random character towards the end)
  const signatureInvalidPEMInitial = convertCertificateToCertificatePEM(test.certificate);
  const signatureInvalidPEM = replaceCharAt(
    signatureInvalidPEMInitial,
    signatureInvalidPEMInitial.length - 41,
    'a'
  );
  fs.writeFile(`generated-test-data/signatureInvalid.pem`, signatureInvalidPEM);

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
  const invalidSignatureChainLeafPEMInitial = convertCertificateToCertificatePEM(
    chainLeaf.certificate
  );
  const invalidSignatureChainLeafPEM = replaceCharAt(
    invalidSignatureChainLeafPEMInitial,
    invalidSignatureChainLeafPEMInitial.length - 41,
    'a'
  );
  fs.writeFile(`generated-test-data/invalidSignatureChainLeaf.pem`, invalidSignatureChainLeafPEM);

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

  const testDigest = md.sha256.create().update(testNewManifestBody);
  const testDigestSignature = test.privateKey.sign(testDigest);
  console.log(`testNewManifestBodySignature = "sig=\\"${util.encode64(testDigestSignature)}\\""`);

  const chainLeafDigest = md.sha256.create().update(testNewManifestBody);
  const chainLeafDigestSignature = chainLeaf.privateKey.sign(chainLeafDigest);
  console.log(
    `testNewManifestBodyValidChainLeafSignature = "sig=\\"${util.encode64(
      chainLeafDigestSignature
    )}\\""`
  );

  const testNewManifestBodyIncorrectProjectId =
    '{"id":"0754dad0-d200-d634-113c-ef1f26106028","createdAt":"2021-11-23T00:57:14.437Z","runtimeVersion":"1","assets":[{"hash":"cb65fafb5ed456fc3ed8a726cf4087d37b875184eba96f33f6d99104e6e2266d","key":"489ea2f19fa850b65653ab445637a181.jpg","contentType":"image/jpeg","url":"http://192.168.64.1:3000/api/assets?asset=updates/1/assets/489ea2f19fa850b65653ab445637a181&runtimeVersion=1&platform=android","fileExtension":".jpg"}],"launchAsset":{"hash":"323ddd1968ee76d4ddbb16b04fb2c3f1b6d1ab9b637d819699fecd6fa0ffb1a8","key":"696a70cf7035664c20ea86f67dae822b.bundle","contentType":"application/javascript","url":"http://192.168.64.1:3000/api/assets?asset=updates/1/bundles/android-696a70cf7035664c20ea86f67dae822b.js&runtimeVersion=1&platform=android","fileExtension":".bundle"},"extra":{"scopeKey":"@test/app","eas":{"projectId":"485dc9ca-a25d-4f60-93be-36dc312266d8"}}}';
  const chainLeafIncorrectProjectIdDigest = md.sha256
    .create()
    .update(testNewManifestBodyIncorrectProjectId);
  const chainLeafIncorrectProjectIdDigestSignature = chainLeaf.privateKey.sign(
    chainLeafIncorrectProjectIdDigest
  );
  console.log(
    `testNewManifestBodyValidChainLeafSignatureIncorrectProjectId = "sig=\\"${util.encode64(
      chainLeafIncorrectProjectIdDigestSignature
    )}\\""`
  );
}

async function exportCertificateAndKeysAsync(
  { privateKey, certificate }: KeysAndCertificate,
  testCase: string
): Promise<void> {
  await Promise.all([
    fs.writeFile(
      `generated-test-data/privatekeys/${testCase}-privateKey.pem`,
      PKI.privateKeyToPem(privateKey)
    ),
    fs.writeFile(`generated-test-data/${testCase}.pem`, PKI.certificateToPem(certificate)),
  ]);
}

async function generateSelfSigned(
  validityBlock: (notBefore: Date, notAfter: Date) => void,
  extensionsModifierBlock: (extensions: any[]) => any[]
): Promise<KeysAndCertificate> {
  const keyPair = generateKeyPair();
  const validityNotBefore = new Date();
  const validityNotAfter = new Date();
  validityBlock(validityNotBefore, validityNotAfter);

  const cert = PKI.createCertificate();
  cert.publicKey = keyPair.publicKey;
  cert.serialNumber = toPositiveHex(util.bytesToHex(random.getBytesSync(9)));
  cert.validity.notBefore = validityNotBefore;
  cert.validity.notAfter = validityNotAfter;

  const attrs = [
    {
      name: 'commonName',
      value: 'test',
    },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions(
    extensionsModifierBlock([
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
    ])
  );

  cert.sign(keyPair.privateKey, md.sha256.create());

  return {
    ...keyPair,
    certificate: cert,
  };
}

async function generateExpoRootCertificateAsync(
  extensionsModifierBlock: (extensions: any[]) => any[]
): Promise<KeysAndCertificate> {
  const { privateKey, publicKey } = generateKeyPair();

  const certificate = PKI.createCertificate();
  certificate.publicKey = publicKey;
  certificate.serialNumber = toPositiveHex(util.bytesToHex(random.getBytesSync(9)));

  // 100 year validity
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setFullYear(certificate.validity.notBefore.getFullYear() + 100);

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

  certificate.setExtensions(
    extensionsModifierBlock([
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
    ])
  );

  certificate.sign(privateKey, md.sha256.create());

  return {
    privateKey,
    publicKey,
    certificate,
  };
}

async function generateExpoGoIntermediateCertificate(
  rootKeysAndCert: KeysAndCertificate,
  extensionsModifierBlock: (extensions: any[]) => any[]
): Promise<KeysAndCertificate> {
  const { privateKey, publicKey } = generateKeyPair();

  const certificate = PKI.createCertificate();
  certificate.publicKey = publicKey;
  certificate.serialNumber = toPositiveHex(util.bytesToHex(random.getBytesSync(9)));

  // 100 year validity
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setFullYear(certificate.validity.notBefore.getFullYear() + 100);

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

  certificate.setExtensions(
    extensionsModifierBlock([
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
    ])
  );

  certificate.sign(rootKeysAndCert.privateKey, md.sha256.create());

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

  const certificate = PKI.createCertificate();
  certificate.publicKey = csr.publicKey;
  certificate.serialNumber = toPositiveHex(util.bytesToHex(random.getBytesSync(9)));

  // set certificate subject attrs from CSR
  certificate.setSubject(csr.subject.attributes);

  // 100 year validity
  certificate.validity.notBefore = new Date();
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setFullYear(certificate.validity.notBefore.getFullYear() + 100);

  certificate.setIssuer(issuerCertificate.subject.attributes);

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

  certificate.sign(issuerPrivateKey, md.sha256.create());

  return {
    privateKey: csrKeysAndCSR.privateKey,
    publicKey: csrKeysAndCSR.publicKey,
    certificate,
  };
}

run();
