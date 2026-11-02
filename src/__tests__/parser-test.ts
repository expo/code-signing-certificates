import { CertificationRequest } from '@peculiar/asn1-csr';
import { AsnParser, AsnSerializer, OctetString } from '@peculiar/asn1-schema';
import { Certificate, Extension } from '@peculiar/asn1-x509';
import { BitString, fromBER, Sequence } from 'asn1js';
import { readFileSync } from 'fs';
import path from 'path';

import { convertCertificatePEMToCertificate, convertCSRPEMToCSR } from '../main';

const fixtureDER = (name: string) =>
  Buffer.from(
    readFileSync(path.join(__dirname, 'fixtures', name), 'utf8').replace(
      /-----[^\n]+-----|\s/g,
      ''
    ),
    'base64'
  );
const pem = (bytes: Buffer | ArrayBuffer, label: string) =>
  `-----BEGIN ${label}-----\n${Buffer.from(bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes).toString('base64')}\n-----END ${label}-----`;
const certificateDER = fixtureDER('valid-certificate.pem');
const csrDER = fixtureDER('historical-csr.pem');
const certificate = () => AsnParser.parse(certificateDER, Certificate);
const csr = () => AsnParser.parse(csrDER, CertificationRequest);
const parseCertificate = (value: Certificate) =>
  convertCertificatePEMToCertificate(pem(AsnSerializer.serialize(value), 'CERTIFICATE'));
const parseCSR = (value: CertificationRequest) =>
  convertCSRPEMToCSR(pem(AsnSerializer.serialize(value), 'CERTIFICATE REQUEST'));

describe('strict certificate and CSR parser boundaries', () => {
  test.each([
    [certificateDER, 'CERTIFICATE', convertCertificatePEMToCertificate],
    [csrDER, 'CERTIFICATE REQUEST', convertCSRPEMToCSR],
  ] as const)('rejects trailing bytes and truncated input', (bytes, label, parse) => {
    expect(() => parse(pem(Buffer.concat([bytes, Buffer.from([0])]), label))).toThrow();
    expect(() => parse(pem(Buffer.concat([bytes, bytes]), label))).toThrow();
    expect(() => parse(pem(bytes.subarray(0, bytes.length - 1), label))).toThrow();
  });

  test.each(['2.5.29.15', '2.5.29.37'])('rejects duplicate usage extension %s', (oid) => {
    const value = certificate();
    value.tbsCertificate.extensions!.push(
      value.tbsCertificate.extensions!.find((ext) => ext.extnID === oid)!
    );
    expect(() => parseCertificate(value)).toThrow();
  });

  test.each(['2.5.29.15', '2.5.29.37'])('rejects malformed usage extension %s', (oid) => {
    const value = certificate();
    const index = value.tbsCertificate.extensions!.findIndex((ext) => ext.extnID === oid);
    value.tbsCertificate.extensions![index] = new Extension({
      extnID: oid,
      critical: true,
      extnValue: new OctetString(new Uint8Array([0x05, 0x00])),
    });
    expect(() => parseCertificate(value)).toThrow();
  });

  test.each([
    [0x03, 0x02, 0x07, 0x81],
    [0x03, 0x01, 0x01],
  ])('rejects malformed Key Usage padding %p', (...bytes) => {
    const value = certificate();
    value.tbsCertificate.extensions!.find((ext) => ext.extnID === '2.5.29.15')!.extnValue =
      new OctetString(Uint8Array.from(bytes));
    expect(() => parseCertificate(value)).toThrow('Invalid Key Usage BIT STRING');
  });

  it('rejects inner/outer certificate signature algorithm disagreement', () => {
    const value = certificate();
    value.signatureAlgorithm.algorithm = '1.2.840.113549.1.1.12';
    expect(() => parseCertificate(value)).toThrow();
  });

  it('rejects unsupported CSR signature algorithms and inappropriate parameters', () => {
    const unknown = csr();
    unknown.signatureAlgorithm.algorithm = '1.2.3.4.5';
    expect(() => parseCSR(unknown)).toThrow();
    const parameters = csr();
    parameters.signatureAlgorithm.parameters = new Uint8Array([0x04, 0x01, 0x00]).buffer;
    expect(() => parseCSR(parameters)).toThrow();
  });

  test.each([
    [certificateDER, 'CERTIFICATE', convertCertificatePEMToCertificate],
    [csrDER, 'CERTIFICATE REQUEST', convertCSRPEMToCSR],
  ] as const)('rejects nonzero signature BIT STRING unused bits', (bytes, label, parse) => {
    const value = fromBER(bytes).result as Sequence;
    (value.valueBlock.value[2] as BitString).valueBlock.unusedBits = 1;
    expect(() => parse(pem(value.toBER(false), label))).toThrow();
  });
});
