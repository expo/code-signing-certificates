import { CertificationRequest } from '@peculiar/asn1-csr';
import { AsnParser, AsnSerializer, OctetString } from '@peculiar/asn1-schema';
import {
  AttributeTypeAndValue,
  AttributeValue,
  BasicConstraints,
  Certificate,
  KeyUsage,
  KeyUsageFlags,
  Name,
  RelativeDistinguishedName,
} from '@peculiar/asn1-x509';
import { fromBER, Sequence } from 'asn1js';
import { createPublicKey, X509Certificate } from 'crypto';
import { readFileSync } from 'fs';
import path from 'path';

import {
  convertCertificatePEMToCertificate,
  convertCertificateToCertificatePEM,
  convertCSRToCSRPEM,
  convertKeyPairPEMToKeyPair,
  generateCSR,
  validateSelfSignedCertificate,
} from '../main';
import { getCertificateData, getCSRData } from '../x509';
import { createCertificate } from '../x509Generation';

const privateKeyPEM = readFileSync(path.join(__dirname, 'fixtures/test-private-key.pem'), 'utf8');
const keyPair = convertKeyPairPEMToKeyPair({
  privateKeyPEM,
  publicKeyPEM: createPublicKey(privateKeyPEM).export({ type: 'spki', format: 'pem' }).toString(),
});
const der = (pem: string) => Buffer.from(pem.replace(/-----[^\n]+-----|\s/g, ''), 'base64');
const signatureParameters = (pem: string) => {
  const outer = fromBER(der(pem)).result as Sequence;
  const algorithm = outer.valueBlock.value[1] as Sequence;
  return Buffer.from(algorithm.valueBlock.value[1]!.valueBeforeDecodeView);
};
const attribute = (type: string, value: AttributeValue) =>
  new AttributeTypeAndValue({ type, value });
const name = new Name([
  new RelativeDistinguishedName([
    attribute('2.5.4.3', new AttributeValue({ utf8String: 'Expo root' })),
    attribute('2.5.4.10', new AttributeValue({ printableString: 'Expo' })),
  ]),
  new RelativeDistinguishedName([attribute('2.5.4.11', new AttributeValue({ utf8String: 'one' }))]),
  new RelativeDistinguishedName([
    attribute('2.5.4.11', new AttributeValue({ printableString: 'two' })),
  ]),
]);
const parameters = {
  publicKey: keyPair.publicKey,
  signingKey: keyPair.privateKey,
  subject: name,
  issuer: name,
  notBefore: new Date('2049-12-31T23:59:59.987Z'),
  notAfter: new Date('2050-01-01T00:00:01.123Z'),
  serialNumber: '0123456789abcdef01',
};

describe('generated ASN.1 contracts', () => {
  it('uses GeneralizedTime before 1950 and UTCTime from 1950 at whole-second precision', () => {
    const certificate = createCertificate({
      ...parameters,
      notBefore: new Date('1949-12-31T23:59:59.987Z'),
      notAfter: new Date('1950-01-01T00:00:01.123Z'),
    });
    const pem = convertCertificateToCertificatePEM(certificate);
    const validity = AsnParser.parse(der(pem), Certificate).tbsCertificate.validity;
    expect(validity.notBefore.generalTime?.toISOString()).toBe('1949-12-31T23:59:59.000Z');
    expect(validity.notAfter.utcTime?.toISOString()).toBe('1950-01-01T00:00:01.000Z');
    expect(certificate.validity.notBefore.toISOString()).toBe('1949-12-31T23:59:59.000Z');
    expect(certificate.validity.notAfter.toISOString()).toBe('1950-01-01T00:00:01.000Z');
    expect(new X509Certificate(pem).verify(keyPair.publicKey)).toBe(true);
  });

  test.each([
    ['007f123456789abcde', '7f123456789abcde'],
    ['000080', '0080'],
    ['000001', '01'],
  ])('encodes serial %s as a minimal positive INTEGER', (serialNumber, expected) => {
    const certificate = createCertificate({ ...parameters, serialNumber });
    const native = new X509Certificate(convertCertificateToCertificatePEM(certificate));
    expect(native.verify(keyPair.publicKey)).toBe(true);
    expect(
      Buffer.from(getCertificateData(certificate).parsed.tbsCertificate.serialNumber).toString(
        'hex'
      )
    ).toBe(expected);
  });

  it('does not expose certificate backing bytes or usage state through deep imports', () => {
    const certificate = createCertificate({
      ...parameters,
      notBefore: new Date('2020-01-01Z'),
      notAfter: new Date('2040-01-01Z'),
      extensions: [
        { name: 'keyUsage', critical: true, digitalSignature: false },
        { name: 'extKeyUsage', critical: true, codeSigning: true },
      ],
    });
    const original = convertCertificateToCertificatePEM(certificate);
    const exposed = getCertificateData(certificate);
    exposed.parsed.tbsCertificate.extensions!.find((ext) => ext.extnID === '2.5.29.15')!.extnValue =
      new OctetString(AsnSerializer.serialize(new KeyUsage(KeyUsageFlags.digitalSignature)));
    exposed.der.fill(0);
    exposed.native.raw.fill(0);
    expect(convertCertificateToCertificatePEM(certificate)).toBe(original);
    expect(() => validateSelfSignedCertificate(certificate, keyPair)).toThrow(
      'X509v3 Key Usage: Digital Signature not present'
    );
  });

  it('does not expose CSR backing bytes through deep imports', () => {
    const csr = generateCSR(keyPair, 'Owned CSR');
    const original = convertCSRToCSRPEM(csr);
    const exposed = getCSRData(csr);
    exposed.der.fill(0);
    exposed.parsed.certificationRequestInfo.subject.length = 0;
    expect(convertCSRToCSRPEM(csr)).toBe(original);
  });

  it('preserves name grouping/string tags, serials, CA usages and unknown extension bytes', () => {
    const certificate = createCertificate({
      ...parameters,
      extensions: [
        { name: 'basicConstraints', critical: true, cA: true, pathLenConstraint: 1 },
        { name: 'keyUsage', critical: true, keyCertSign: true, cRLSign: true },
        { id: '1.2.3.4.5', value: new Uint8Array([0, 255, 128, 1]) },
      ],
    });
    const pem = convertCertificateToCertificatePEM(certificate);
    const parsed = AsnParser.parse(der(pem), Certificate);
    const tbs = parsed.tbsCertificate;
    const native = new X509Certificate(pem);
    expect(native.verify(keyPair.publicKey)).toBe(true);
    expect(tbs.version).toBe(2);
    expect(Buffer.from(tbs.serialNumber).toString('hex')).toBe(parameters.serialNumber);
    expect(Buffer.from(AsnSerializer.serialize(tbs.subject))).toEqual(
      Buffer.from(AsnSerializer.serialize(name))
    );
    expect(Buffer.from(AsnSerializer.serialize(tbs.issuer))).toEqual(
      Buffer.from(AsnSerializer.serialize(name))
    );
    expect(tbs.validity.notBefore.utcTime?.toISOString()).toBe('2049-12-31T23:59:59.000Z');
    expect(tbs.validity.notAfter.generalTime?.toISOString()).toBe('2050-01-01T00:00:01.000Z');
    expect(parsed.signatureAlgorithm.algorithm).toBe('1.2.840.113549.1.1.11');
    expect(signatureParameters(pem)).toEqual(Buffer.from([5, 0]));
    expect(tbs.signature).toEqual(parsed.signatureAlgorithm);
    const basic = tbs.extensions!.find((extension) => extension.extnID === '2.5.29.19')!;
    expect(basic.critical).toBe(true);
    expect(AsnParser.parse(basic.extnValue, BasicConstraints)).toMatchObject({
      cA: true,
      pathLenConstraint: 1,
    });
    const usage = tbs.extensions!.find((extension) => extension.extnID === '2.5.29.15')!;
    expect(AsnParser.parse(usage.extnValue, KeyUsage).toNumber()).toBe(
      KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign
    );
    expect(
      Buffer.from(
        tbs.extensions!.find((extension) => extension.extnID === '1.2.3.4.5')!.extnValue.buffer
      )
    ).toEqual(Buffer.from([0, 255, 128, 1]));
    expect(
      der(convertCertificateToCertificatePEM(convertCertificatePEMToCertificate(pem)))
    ).toEqual(der(pem));
  });

  it('generates CSR v1 with explicit SHA256/RSA parameters and empty attributes', () => {
    const pem = convertCSRToCSRPEM(generateCSR(keyPair, 'Generated CSR'));
    const parsed = AsnParser.parse(der(pem), CertificationRequest);
    expect(parsed.certificationRequestInfo.version).toBe(0);
    expect(parsed.certificationRequestInfo.attributes).toHaveLength(0);
    expect(parsed.signatureAlgorithm.algorithm).toBe('1.2.840.113549.1.1.11');
    expect(signatureParameters(pem)).toEqual(Buffer.from([5, 0]));
    // The required empty [0] attributes field must be encoded, not merely supplied by parser defaults.
    expect(Buffer.from(parsed.certificationRequestInfoRaw!).subarray(-2)).toEqual(
      Buffer.from([0xa0, 0])
    );
  });

  it('compares encoded issuer/subject names even when their native display strings match', () => {
    const subject = new Name([
      new RelativeDistinguishedName([
        attribute('2.5.4.3', new AttributeValue({ utf8String: 'Same name' })),
      ]),
    ]);
    const issuer = new Name([
      new RelativeDistinguishedName([
        attribute('2.5.4.3', new AttributeValue({ printableString: 'Same name' })),
      ]),
    ]);
    const certificate = createCertificate({
      ...parameters,
      subject,
      issuer,
      extensions: [
        { name: 'keyUsage', critical: true, digitalSignature: true },
        { name: 'extKeyUsage', critical: true, codeSigning: true },
      ],
    });
    const native = new X509Certificate(convertCertificateToCertificatePEM(certificate));
    expect(native.subject).toBe(native.issuer);
    expect(() => validateSelfSignedCertificate(certificate, keyPair)).toThrow(
      'Certificate issuer hash does not match subject hash'
    );
  });
});
