import * as crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import * as api from '../main';

let other: typeof api;
jest.isolateModules(() => {
  other = jest.requireActual<typeof api>('../main');
});

const keys = api.convertPrivateKeyPEMToPrivateKey(
  readFileSync(path.join(__dirname, 'fixtures/test-private-key.pem'), 'utf8')
);
const keyPair = { privateKey: keys, publicKey: crypto.createPublicKey(keys) };

// Both directions matter: each copy owns its own classes and private state.
describe.each([
  ['first to second', () => [api, other] as const],
  ['second to first', () => [other, api] as const],
])('objects shared between package instances: %s', (_name, implementations) => {
  it('exports, validates, signs, and issues using foreign certificates and CSRs', () => {
    const [source, receiver] = implementations();
    expect(source.CodeSigningCertificate).not.toBe(receiver.CodeSigningCertificate);
    const certificate = source.generateSelfSignedCodeSigningCertificate({
      keyPair,
      commonName: 'Cross-instance issuer',
      validityNotBefore: new Date('2020-01-01Z'),
      validityNotAfter: new Date('2100-01-01Z'),
    });
    const csr = source.generateCSR(keyPair, 'Cross-instance requester');
    const certificatePEM = source.convertCertificateToCertificatePEM(certificate);
    const csrPEM = source.convertCSRToCSRPEM(csr);
    expect(receiver.convertCertificateToCertificatePEM(certificate)).toBe(certificatePEM);
    expect(receiver.convertCSRToCSRPEM(csr)).toBe(csrPEM);
    receiver.validateSelfSignedCertificate(certificate, keyPair);
    const message = Buffer.from('Cross-instance signing\0');
    expect(receiver.signBufferRSASHA256AndVerify(keys, certificate, message)).toBe(
      source.signBufferRSASHA256AndVerify(keys, certificate, message)
    );
    const issued = receiver.generateDevelopmentCertificateFromCSR(
      keys,
      certificate,
      csr,
      'authorized-project',
      '@authorized/scope'
    );
    const native = new crypto.X509Certificate(receiver.convertCertificateToCertificatePEM(issued));
    expect(native.verify(keyPair.publicKey)).toBe(true);
    expect(native.subject).toBe('CN=Cross-instance requester');
    expect(source.convertCertificateToCertificatePEM(certificate)).toBe(certificatePEM);
    expect(source.convertCSRToCSRPEM(csr)).toBe(csrPEM);
  });

  it('copies exported bytes and revalidates transferred certificate and CSR encodings', () => {
    const [source, receiver] = implementations();
    const certificate = source.convertCertificatePEMToCertificate(
      readFileSync(path.join(__dirname, 'fixtures/valid-certificate.pem'), 'utf8')
    );
    const csr = source.generateCSR(keyPair, 'Transfer isolation');
    const cases = [
      {
        object: certificate,
        symbol: Symbol.for('@expo/code-signing-certificates/certificate/der/v1'),
        exportPEM: () => source.convertCertificateToCertificatePEM(certificate),
        receive: () => receiver.convertCertificateToCertificatePEM(certificate),
      },
      {
        object: csr,
        symbol: Symbol.for('@expo/code-signing-certificates/csr/der/v1'),
        exportPEM: () => source.convertCSRToCSRPEM(csr),
        receive: () => receiver.convertCSRToCSRPEM(csr),
      },
    ];
    for (const entry of cases) {
      const originalPEM = entry.exportPEM();
      const exportDER = Reflect.get(entry.object, entry.symbol) as () => Buffer;
      const originalDER = exportDER.call(entry.object);
      const copiedDER = exportDER.call(entry.object);
      copiedDER.fill(0);
      expect(entry.exportPEM()).toBe(originalPEM);
      expect(entry.receive()).toBe(originalPEM);

      Object.defineProperty(entry.object, entry.symbol, {
        value: () => Buffer.concat([originalDER, Buffer.from([0])]),
      });
      expect(entry.receive).toThrow('Trailing ASN.1 data');
      expect(entry.exportPEM()).toBe(originalPEM);
    }
  });

  it('still rejects a foreign CSR with a tampered signature', () => {
    const [source, receiver] = implementations();
    const certificate = source.convertCertificatePEMToCertificate(
      readFileSync(path.join(__dirname, 'fixtures/valid-certificate.pem'), 'utf8')
    );
    const csr = source.convertCSRPEMToCSR(
      readFileSync(path.join(__dirname, 'fixtures/tampered-csr.pem'), 'utf8')
    );
    expect(() =>
      receiver.generateDevelopmentCertificateFromCSR(
        keys,
        certificate,
        csr,
        'authorized-project',
        '@authorized/scope'
      )
    ).toThrow('CSR not self-signed');
  });
});
