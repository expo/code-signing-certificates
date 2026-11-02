import { Time } from '@peculiar/asn1-x509';
import { Sequence, fromBER } from 'asn1js';
import * as crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import * as asn1 from '../asn1';
import * as api from '../main';
import { getCertificateData } from '../x509';

const privateKey = crypto.createPrivateKey(
  readFileSync(path.join(__dirname, 'fixtures/test-private-key.pem'))
);
const keyPair = { privateKey, publicKey: crypto.createPublicKey(privateKey) };

describe('runtime date compatibility boundaries', () => {
  test.each([
    ['notBefore', '200101000000Z', '201301000000Z'],
    ['notAfter', '400101000000Z', '001301000000Z'],
    ['notBefore', '200101000000Z', '200100000000Z'],
    ['notAfter', '400101000000Z', '000100000000Z'],
  ])(
    'rejects a correctly signed malformed %s (%s → %s) at construction',
    (_field, original, malformed) => {
      const der = new crypto.X509Certificate(
        readFileSync(path.join(__dirname, 'fixtures/valid-certificate.pem'))
      ).raw;
      const offset = der.indexOf(original!);
      expect(offset).toBeGreaterThan(-1);
      Buffer.from(malformed!).copy(der, offset);
      const tree = fromBER(der).result as Sequence;
      const signature = crypto.sign(
        'sha256',
        tree.valueBlock.value[0]!.valueBeforeDecodeView,
        privateKey
      );
      signature.copy(der, der.length - signature.length);
      // Verify the exact mutated TBS independently: rejection must not depend on a bad signature.
      expect(new crypto.X509Certificate(der).verify(keyPair.publicKey)).toBe(true);
      expect(() => new api.CodeSigningCertificate(der)).toThrow('Invalid certificate date');
    }
  );
  test.each(['0001', '0027', '0099', '0100'])('preserves the literal year %s', (year) => {
    const before = new Date(`${year}-01-01T00:00:00.000Z`);
    const after = new Date(`${year}-12-31T23:59:59.000Z`);
    const c = api.generateSelfSignedCodeSigningCertificate({
      keyPair,
      commonName: 'Date boundary',
      validityNotBefore: before,
      validityNotAfter: after,
    });
    expect(c.validity.notBefore.toISOString()).toBe(before.toISOString());
    expect(c.validity.notAfter.toISOString()).toBe(after.toISOString());
  });
  it('matches native whole-second interpretation of fractional GeneralizedTime', () => {
    const c = api.generateSelfSignedCodeSigningCertificate({
      keyPair,
      commonName: 'Fractional date',
      validityNotBefore: new Date('2050-01-01Z'),
      validityNotAfter: new Date('2100-01-01Z'),
    });
    const tbs = getCertificateData(c).parsed.tbsCertificate;
    tbs.validity.notBefore = new Time({ generalTime: new Date('2050-01-01T00:00:00.500Z') });
    const parsed = new api.CodeSigningCertificate(asn1.signedDER(tbs, privateKey));
    expect(parsed.validity.notBefore.toISOString()).toBe('2050-01-01T00:00:00.000Z');
  });
  it('rejects a certificate that expired in year 27 instead of interpreting it as 2027', () => {
    const c = api.generateSelfSignedCodeSigningCertificate({
      keyPair,
      commonName: 'Ancient expired',
      validityNotBefore: new Date('0001-01-01T00:00:00Z'),
      validityNotAfter: new Date('0027-01-01T00:00:00Z'),
    });
    expect(() => api.validateSelfSignedCertificate(c, keyPair)).toThrow(
      'Certificate validity expired'
    );
  });
});
