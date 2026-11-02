import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate, ExtendedKeyUsage, KeyUsage, KeyUsageFlags } from '@peculiar/asn1-x509';
import { fromBER, ObjectIdentifier, Sequence } from 'asn1js';
import {
  constants,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  sign,
  verify,
  X509Certificate,
} from 'crypto';
import { readFileSync } from 'fs';
import path from 'path';

import {
  convertCertificatePEMToCertificate,
  convertCertificateToCertificatePEM,
  convertCSRPEMToCSR,
  convertCSRToCSRPEM,
  convertKeyPairPEMToKeyPair,
  convertKeyPairToPEM,
  convertPrivateKeyPEMToPrivateKey,
  convertPublicKeyPEMToPublicKey,
  expoProjectInformationOID,
  generateCSR,
  generateDevelopmentCertificateFromCSR,
  generateKeyPair,
  generateSelfSignedCodeSigningCertificate,
  signBufferRSASHA256AndVerify,
  validateSelfSignedCertificate,
} from '../main';

const fixture = (name: string) => readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');
const privateKeyPEM = fixture('test-private-key.pem');
const publicKeyPEM = createPublicKey(privateKeyPEM)
  .export({ type: 'spki', format: 'pem' })
  .toString();
const keyPair = convertKeyPairPEMToKeyPair({ privateKeyPEM, publicKeyPEM });
const otherPrivateKeyPEM = fixture('other-private-key.pem');
const otherKeyPair = convertKeyPairPEMToKeyPair({
  privateKeyPEM: otherPrivateKeyPEM,
  publicKeyPEM: createPublicKey(otherPrivateKeyPEM)
    .export({ type: 'spki', format: 'pem' })
    .toString(),
});
const der = (pem: string) => Buffer.from(pem.replace(/-----[^\n]+-----|\s/g, ''), 'base64');
const spki = (pem: string) => createPublicKey(pem).export({ type: 'spki', format: 'der' });
const certificateFixture = (name = 'valid') =>
  convertCertificatePEMToCertificate(fixture(`${name}-certificate.pem`));
const roundtripCertificate = (certificate: ReturnType<typeof certificateFixture>) =>
  convertCertificatePEMToCertificate(convertCertificateToCertificatePEM(certificate));

beforeEach(() => {
  jest.useFakeTimers({ now: new Date('2030-06-15T12:34:56Z') });
});
afterEach(() => jest.useRealTimers());

describe('RSA keys and PEM boundaries', () => {
  it('generates RSA-2048 with exponent 65537 and matching public/private components', () => {
    const pem = convertKeyPairToPEM(generateKeyPair());
    const privateKey = createPrivateKey(pem.privateKeyPEM);
    const publicKey = createPublicKey(pem.publicKeyPEM);
    expect(publicKey.asymmetricKeyType).toBe('rsa');
    expect(publicKey.asymmetricKeyDetails).toMatchObject({
      modulusLength: 2048,
      publicExponent: 65537n,
    });
    expect(spki(pem.privateKeyPEM)).toEqual(spki(pem.publicKeyPEM));
    expect(
      verify(
        'sha256',
        Buffer.from('key proof'),
        publicKey,
        sign('sha256', Buffer.from('key proof'), privateKey)
      )
    ).toBe(true);
  });

  it('exports PKCS#1 private and SPKI public PEM and preserves key material', () => {
    const pem = convertKeyPairToPEM(keyPair);
    expect(pem.privateKeyPEM).toMatch(/^-----BEGIN RSA PRIVATE KEY-----/);
    expect(pem.publicKeyPEM).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(spki(pem.privateKeyPEM)).toEqual(spki(privateKeyPEM));
    expect(spki(pem.publicKeyPEM)).toEqual(spki(publicKeyPEM));
  });

  test.each(['pkcs1', 'pkcs8'] as const)('accepts %s private PEM', (type) => {
    const pem = createPrivateKey(privateKeyPEM).export({ type, format: 'pem' }).toString();
    const result = convertKeyPairToPEM({
      ...keyPair,
      privateKey: convertPrivateKeyPEMToPrivateKey(pem),
    });
    expect(spki(result.privateKeyPEM)).toEqual(spki(privateKeyPEM));
  });

  test.each(['spki', 'pkcs1'] as const)('accepts %s public PEM', (type) => {
    const pem = createPublicKey(privateKeyPEM).export({ type, format: 'pem' }).toString();
    const result = convertKeyPairToPEM({
      ...keyPair,
      publicKey: convertPublicKeyPEMToPublicKey(pem),
    });
    expect(spki(result.publicKeyPEM)).toEqual(spki(publicKeyPEM));
  });

  it('accepts indented key PEMs used by existing Expo consumers', () => {
    const indent = (pem: string) =>
      pem
        .split('\n')
        .map((line) => `  ${line}  `)
        .join('\r\n');
    const result = convertKeyPairToPEM(
      convertKeyPairPEMToKeyPair({
        privateKeyPEM: indent(privateKeyPEM),
        publicKeyPEM: indent(publicKeyPEM),
      })
    );
    expect(spki(result.privateKeyPEM)).toEqual(spki(privateKeyPEM));
    expect(spki(result.publicKeyPEM)).toEqual(spki(publicKeyPEM));
  });

  it('converts a mismatched pair without prematurely validating it', () => {
    const result = convertKeyPairPEMToKeyPair({ privateKeyPEM: otherPrivateKeyPEM, publicKeyPEM });
    expect(() => validateSelfSignedCertificate(certificateFixture(), result)).toThrow(
      'keyPair key mismatch'
    );
  });
});

describe('self-signed certificate validation through signed PEM', () => {
  it('accepts a valid serialized certificate and both exact validity endpoints', () => {
    const certificate = certificateFixture();
    for (const now of [
      certificate.validity.notBefore,
      certificate.validity.notAfter,
      new Date('2030-06-15T12:34:56Z'),
    ]) {
      jest.setSystemTime(now);
      expect(() => validateSelfSignedCertificate(certificate, keyPair)).not.toThrow();
    }
  });

  test.each([
    ['expired', 'Certificate validity expired'],
    ['future', 'Certificate validity expired'],
    ['issuer-mismatch', 'Certificate issuer hash does not match subject hash'],

    ['false-ku', 'X509v3 Key Usage: Digital Signature not present'],
    ['false-eku', 'X509v3 Extended Key Usage: Code Signing not present'],
  ])('rejects %s', (name, message) => {
    expect(() => validateSelfSignedCertificate(certificateFixture(name), keyPair)).toThrow(message);
  });

  test.each([
    ['absent-ku', 'X509v3 Key Usage: Digital Signature not present'],
    ['absent-eku', 'X509v3 Extended Key Usage: Code Signing not present'],
  ])('rejects truly %s with the intended usage diagnostic', (name, message) => {
    const certificate = certificateFixture(name);
    expect(() => validateSelfSignedCertificate(certificate, keyPair)).toThrow(message);
  });

  it('rejects a serialized invalid signature', () => {
    expect(() =>
      validateSelfSignedCertificate(certificateFixture('invalid-signature'), keyPair)
    ).toThrow();
  });

  it('rejects a certificate for another key before checking the private/public pair', () => {
    expect(() => validateSelfSignedCertificate(certificateFixture(), otherKeyPair)).toThrow(
      'Certificate pubic key does not match key pair public key'
    );
  });

  it('preserves original certificate DER and encoded dates', () => {
    const pem = fixture('test-certificate.pem');
    const certificate = convertCertificatePEMToCertificate(pem);
    const output = convertCertificateToCertificatePEM(certificate);
    expect(der(output)).toEqual(der(pem));
    const native = new X509Certificate(output);
    expect(certificate.validity.notBefore.toISOString()).toBe(
      new Date(native.validFrom).toISOString()
    );
    expect(certificate.validity.notAfter.toISOString()).toBe(
      new Date(native.validTo).toISOString()
    );
  });

  test.each([
    ['2049-12-31T23:59:59.987Z', '2050-01-01T00:00:00.123Z'],
    ['2050-01-01T00:00:00.123Z', '2051-01-01T00:00:00.987Z'],
  ])(
    'generates independently verifiable certificates across time encoding boundaries (%s)',
    (before, after) => {
      const certificate = roundtripCertificate(
        generateSelfSignedCodeSigningCertificate({
          keyPair,
          commonName: 'Boundary',
          validityNotBefore: new Date(before),
          validityNotAfter: new Date(after),
        })
      );
      const native = new X509Certificate(convertCertificateToCertificatePEM(certificate));
      expect(native.verify(native.publicKey)).toBe(true);
      expect(certificate.validity.notBefore.toISOString()).toBe(
        before.replace(/\.\d{3}Z$/, '.000Z')
      );
      expect(certificate.validity.notAfter.toISOString()).toBe(after.replace(/\.\d{3}Z$/, '.000Z'));
      expect(
        spki(convertKeyPairToPEM({ ...keyPair, publicKey: certificate.publicKey }).publicKeyPEM)
      ).toEqual(spki(publicKeyPEM));
    }
  );
});

describe(signBufferRSASHA256AndVerify, () => {
  const certificate = convertCertificatePEMToCertificate(fixture('test-certificate.pem'));
  it('signs and verifies', () => {
    const signature = signBufferRSASHA256AndVerify(
      keyPair.privateKey,
      certificate,
      Buffer.from('hello', 'utf8')
    );
    expect(signature).toMatchSnapshot();
    expect(
      verify(
        'sha256',
        Buffer.from('hello'),
        new X509Certificate(fixture('test-certificate.pem')).publicKey,
        Buffer.from(signature, 'base64')
      )
    ).toBe(true);
  });

  test.each([
    Buffer.alloc(0),
    Buffer.from([0, 255, 128, 0, 65]),
    Buffer.from('öäå 🌍 漢字 e\u0301', 'utf8'),
  ])('signs exact message bytes %p', (message) => {
    const signature = Buffer.from(
      signBufferRSASHA256AndVerify(keyPair.privateKey, certificate, message),
      'base64'
    );
    expect(verify('sha256', message, publicKeyPEM, signature)).toBe(true);
    expect(
      verify('sha256', Buffer.concat([message, Buffer.from([1])]), publicKeyPEM, signature)
    ).toBe(false);
  });

  it('rejects signing with a key that does not match the certificate', () => {
    expect(() =>
      signBufferRSASHA256AndVerify(otherKeyPair.privateKey, certificate, Buffer.from('hello'))
    ).toThrow();
  });
});

// Extract original signed bytes independently of the package's CSR verifier.
function verifyCSR(pem: string, algorithm = 'sha256') {
  const sequence = fromBER(der(pem)).result as Sequence;
  const fields = sequence.valueBlock.value;
  const signed = Buffer.from(fields[0]!.valueBeforeDecodeView);
  const signature = Buffer.from((fields[2] as import('asn1js').BitString).valueBlock.valueHexView);
  return verify(
    algorithm === 'pss' ? 'sha256' : algorithm,
    signed,
    algorithm === 'pss'
      ? { key: publicKeyPEM, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }
      : publicKeyPEM,
    signature
  );
}

function extensions(certificate: ReturnType<typeof certificateFixture>) {
  return AsnParser.parse(der(convertCertificateToCertificatePEM(certificate)), Certificate)
    .tbsCertificate.extensions!;
}

function extension(certificate: ReturnType<typeof certificateFixture>, oid: string) {
  return extensions(certificate).find((value) => value.extnID === oid);
}

function issue(
  csrPEM = fixture('historical-csr.pem'),
  appId = 'testApp',
  scopeKey = 'testScopeKey'
) {
  return roundtripCertificate(
    generateDevelopmentCertificateFromCSR(
      otherKeyPair.privateKey,
      certificateFixture('other-issuer'),
      convertCSRPEMToCSR(csrPEM),
      appId,
      scopeKey
    )
  );
}

describe('CSR proof of possession and issuer policy', () => {
  it('verifies PSS with an independent MGF hash without changing the issued public key', () => {
    const pem = fixture('pss-mgf384-csr.pem');
    const info = (fromBER(der(pem), { parseEmbedded: false }).result as Sequence).valueBlock
      .value[0] as Sequence;
    const publicKeyDER = Buffer.from(info.valueBlock.value[2]!.valueBeforeDecodeView);
    const certificate = new X509Certificate(convertCertificateToCertificatePEM(issue(pem)));
    expect(certificate.verify(createPublicKey(otherPrivateKeyPEM))).toBe(true);
    expect(certificate.publicKey.export({ type: 'spki', format: 'der' })).toEqual(publicKeyDER);
    expect(der(convertCSRToCSRPEM(convertCSRPEMToCSR(pem)))).toEqual(der(pem));
  });

  it('generates a CSR verified by native crypto and preserves its DER', () => {
    const pem = convertCSRToCSRPEM(generateCSR(keyPair, 'Test common name'));
    expect(verifyCSR(pem)).toBe(true);
    expect(der(convertCSRToCSRPEM(convertCSRPEMToCSR(pem)))).toEqual(der(pem));
  });

  test.each(['historical', 'external', 'pss', 'sha1', 'sha384', 'sha512', 'md5'])(
    'accepts historical %s signed CSR and preserves its signed bytes',
    (name) => {
      const pem = fixture(`${name}-csr.pem`);
      expect(verifyCSR(pem, ['historical', 'external'].includes(name) ? 'sha256' : name)).toBe(
        true
      );
      const exported = convertCSRToCSRPEM(convertCSRPEMToCSR(pem));
      expect(verifyCSR(exported, ['historical', 'external'].includes(name) ? 'sha256' : name)).toBe(
        true
      );
      expect(der(exported)).toEqual(der(pem));
      const signedBytes = (input: string) =>
        Buffer.from(
          (fromBER(der(input)).result as Sequence).valueBlock.value[0]!.valueBeforeDecodeView
        );
      expect(signedBytes(exported)).toEqual(signedBytes(pem));
      const certificate = issue(pem);
      expect(
        new X509Certificate(convertCertificateToCertificatePEM(certificate)).verify(
          createPublicKey(otherPrivateKeyPEM)
        )
      ).toBe(true);
    }
  );

  it('rejects tampered signed request content and malformed/truncated DER', () => {
    const original = der(fixture('historical-csr.pem'));
    const tampered = Buffer.from(original);
    const offset = tampered.indexOf(Buffer.from('Historical CSR'));
    expect(offset).toBeGreaterThan(0);
    tampered[offset] = tampered[offset]! ^ 1;
    const pem = (bytes: Buffer) =>
      `-----BEGIN CERTIFICATE REQUEST-----\n${bytes.toString('base64')}\n-----END CERTIFICATE REQUEST-----`;
    expect(() => issue(pem(tampered))).toThrow('CSR not self-signed');
    expect(() => convertCSRPEMToCSR(pem(original.subarray(0, original.length - 12)))).toThrow();
    expect(() =>
      convertCSRPEMToCSR(pem(Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff])))
    ).toThrow();
  });

  it('accepts the legacy NEW CERTIFICATE REQUEST label', () => {
    const pem = fixture('historical-csr.pem').replace(
      /CERTIFICATE REQUEST/g,
      'NEW CERTIFICATE REQUEST'
    );
    expect(der(convertCSRToCSRPEM(convertCSRPEMToCSR(pem)))).toEqual(
      der(fixture('historical-csr.pem'))
    );
  });

  it('rejects serialized tampering and a CSR signed by a different private key', () => {
    expect(verifyCSR(fixture('tampered-csr.pem'))).toBe(false);
    expect(() => issue(fixture('tampered-csr.pem'))).toThrow();
    const csr = generateCSR(
      { publicKey: keyPair.publicKey, privateKey: otherKeyPair.privateKey },
      'Wrong proof'
    );
    expect(() => issue(convertCSRToCSRPEM(csr))).toThrow();
  });

  test.each(['historical', 'requested-extensions'])(
    'copies subject/key but enforces issuer-owned usages and scope for %s',
    (name) => {
      const certificate = issue(fixture(`${name}-csr.pem`));
      const pem = convertCertificateToCertificatePEM(certificate);
      const native = new X509Certificate(pem);
      expect(native.verify(createPublicKey(otherPrivateKeyPEM))).toBe(true);
      expect(native.subject).toContain('CN=Historical CSR');
      expect(native.subject).toContain('O=Expo test fixtures');
      expect(native.issuer).toBe('CN=Fixture signing key');
      expect(native.publicKey.export({ type: 'spki', format: 'der' })).toEqual(spki(publicKeyPEM));
      const ku = extension(certificate, '2.5.29.15')!;
      expect(ku.critical).toBe(true);
      expect(AsnParser.parse(ku.extnValue, KeyUsage).toNumber()).toBe(
        KeyUsageFlags.digitalSignature
      );
      const eku = extension(certificate, '2.5.29.37')!;
      expect(eku.critical).toBe(true);
      expect(Array.from(AsnParser.parse(eku.extnValue, ExtendedKeyUsage))).toEqual([
        '1.3.6.1.5.5.7.3.3',
      ]);
      expect(extension(certificate, '2.5.29.19')).toBeUndefined();
      const expo = extension(certificate, expoProjectInformationOID)!;
      expect(expo.critical).toBe(false);
      expect(Buffer.from(expo.extnValue.buffer).toString()).toBe('testApp,testScopeKey');
    }
  );

  it('keeps long Expo payloads as raw bytes without ASN.1 string wrapping', () => {
    const scope = 'scope'.repeat(80);
    const certificate = issue(undefined, 'app', scope);
    const expo = extension(certificate, expoProjectInformationOID)!;
    expect(expo.critical).toBe(false);
    expect(Buffer.from(expo.extnValue.buffer).toString()).toBe(`app,${scope}`);
    expect(
      der(convertCertificateToCertificatePEM(certificate)).includes(Buffer.from(`app,${scope}`))
    ).toBe(true);
  });

  test.each([
    ['2030-06-15T12:34:56.789Z', '2030-06-14T12:34:56.000Z', '2030-07-14T12:34:56.000Z'],
    ['2030-03-01T12:34:56.789Z', '2030-02-28T12:34:56.000Z', '2030-04-27T12:34:56.000Z'],
    ['2030-01-01T12:34:56.789Z', '2029-12-31T12:34:56.000Z', '2030-03-02T12:34:56.000Z'],
    ['2030-03-31T12:34:56.789Z', '2030-03-30T12:34:56.000Z', '2030-04-29T12:34:56.000Z'],
  ])(
    'preserves existing calendar calculation at %s without mutating dates',
    (now, before, after) => {
      jest.setSystemTime(new Date(now.replace('Z', '')));
      const certificate = issue();
      expect(certificate.validity.notBefore.toISOString()).toBe(
        new Date(before.replace('Z', '')).toISOString()
      );
      expect(certificate.validity.notAfter.toISOString()).toBe(
        new Date(after.replace('Z', '')).toISOString()
      );
      expect(roundtripCertificate(certificate).validity.notBefore.toISOString()).toBe(
        new Date(before.replace('Z', '')).toISOString()
      );
    }
  );
});

describe('native public representation', () => {
  it('exposes native key roles and no Forge methods', () => {
    expect(keyPair.publicKey).toBeInstanceOf(KeyObject);
    expect(keyPair.privateKey).toBeInstanceOf(KeyObject);
    expect(keyPair.publicKey.type).toBe('public');
    expect(keyPair.privateKey.type).toBe('private');
    const certificate = certificateFixture();
    expect(certificate.publicKey).toBeInstanceOf(KeyObject);
    expect('verify' in certificate).toBe(false);
    expect('getExtension' in certificate).toBe(false);
    const csr = generateCSR(keyPair, 'Opaque CSR');
    expect('verify' in csr).toBe(false);
    expect('subject' in csr).toBe(false);
  });

  it('returns defensive dates derived from whole-second encoded validity', () => {
    const before = new Date('2030-01-01T00:00:00.987Z');
    const after = new Date('2031-01-01T00:00:00.123Z');
    const certificate = generateSelfSignedCodeSigningCertificate({
      keyPair,
      commonName: 'Dates',
      validityNotBefore: before,
      validityNotAfter: after,
    });
    expect(certificate.validity.notBefore.toISOString()).toBe('2030-01-01T00:00:00.000Z');
    expect(certificate.validity.notAfter.toISOString()).toBe('2031-01-01T00:00:00.000Z');
    before.setFullYear(1990);
    after.setFullYear(1990);
    certificate.validity.notBefore.setFullYear(1990);
    certificate.validity.notAfter.setFullYear(1990);
    expect(certificate.validity.notBefore.getUTCFullYear()).toBe(2030);
    expect(certificate.validity.notAfter.getUTCFullYear()).toBe(2031);
  });

  it('rejects private PEM at the public conversion boundary', () => {
    expect(() => convertPublicKeyPEMToPublicKey(privateKeyPEM)).toThrow();
    expect(() => convertPrivateKeyPEMToPrivateKey(publicKeyPEM)).toThrow();
    expect(() => convertPublicKeyPEMToPublicKey(privateKeyPEM + publicKeyPEM)).toThrow();
  });

  it('rejects non-RSA keys and incorrect key roles', () => {
    const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    expect(() =>
      convertPublicKeyPEMToPublicKey(
        ec.publicKey.export({ type: 'spki', format: 'pem' }).toString()
      )
    ).toThrow('RSA');
    expect(() =>
      convertPrivateKeyPEMToPrivateKey(
        ec.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
      )
    ).toThrow('RSA');
    for (const badPair of [ec, { publicKey: keyPair.privateKey, privateKey: keyPair.publicKey }]) {
      expect(() => generateCSR(badPair, 'Wrong key')).toThrow();
      expect(() => convertKeyPairToPEM(badPair)).toThrow();
      expect(() =>
        generateSelfSignedCodeSigningCertificate({
          keyPair: badPair,
          commonName: 'Wrong key',
          validityNotBefore: new Date('2030-01-01'),
          validityNotAfter: new Date('2031-01-01'),
        })
      ).toThrow();
    }
    expect(() =>
      signBufferRSASHA256AndVerify(keyPair.publicKey, certificateFixture(), Buffer.alloc(0))
    ).toThrow();
  });
});

it('rejects restricted RSA-PSS keys at PEM conversion boundaries', () => {
  // Reuse the fixed RSA material with the standard restricted RSA-PSS algorithm identifier.
  for (const [key, type, label, convert] of [
    [createPublicKey(privateKeyPEM), 'spki', 'PUBLIC KEY', convertPublicKeyPEMToPublicKey],
    [createPrivateKey(privateKeyPEM), 'pkcs8', 'PRIVATE KEY', convertPrivateKeyPEMToPrivateKey],
  ] as const) {
    const parsed = fromBER(key.export({ type, format: 'der' })).result as Sequence;
    const algorithmIndex = type === 'spki' ? 0 : 1;
    (parsed.valueBlock.value[algorithmIndex] as Sequence).valueBlock.value = [
      new ObjectIdentifier({ value: '1.2.840.113549.1.1.10' }),
    ];
    const pem = `-----BEGIN ${label}-----\n${Buffer.from(parsed.toBER(false)).toString('base64')}\n-----END ${label}-----`;
    const native = type === 'spki' ? createPublicKey(pem) : createPrivateKey(pem);
    expect(native.asymmetricKeyType).toBe('rsa-pss');
    expect(() => convert(pem)).toThrow('Expected an RSA key');
  }
});
