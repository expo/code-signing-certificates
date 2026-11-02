import * as asn1CSR from '@peculiar/asn1-csr';
import * as asn1X509 from '@peculiar/asn1-x509';
import assert from 'node:assert';
import * as crypto from 'node:crypto';

import * as asn1 from './asn1';

type CertificateData = {
  native: crypto.X509Certificate;
  parsed: asn1X509.Certificate;
  der: Buffer;
};
type CSRData = {
  parsed: asn1CSR.CertificationRequest;
  der: Buffer;
  publicKey: crypto.KeyObject;
};
const certificates = new WeakMap<CodeSigningCertificate, CertificateData>();
const requests = new WeakMap<CertificateSigningRequest, CSRData>();
// Versioned symbols let independent package copies exchange bytes, never parsed state.
const certificateDER = Symbol.for('@expo/code-signing-certificates/certificate/der/v1');
const csrDER = Symbol.for('@expo/code-signing-certificates/csr/der/v1');

function certificateDate(date: Date | undefined, text: string): Date {
  const parsed = new Date(date ?? text);
  if (!date) {
    // Node <22.10 has only text getters; preserve OpenSSL's literal year and whole seconds.
    const year = Number(text.trim().split(/\s+/).at(-2));
    assert(Number.isInteger(year), 'Invalid certificate date');
    parsed.setUTCFullYear(year);
    parsed.setUTCMilliseconds(0);
  }
  assert(Number.isFinite(parsed.getTime()), 'Invalid certificate date');
  return parsed;
}

export class CodeSigningCertificate {
  readonly #data: CertificateData;
  readonly #validity: { notBefore: Date; notAfter: Date };

  constructor(pemOrDER: string | Uint8Array) {
    const der =
      typeof pemOrDER === 'string'
        ? asn1.decodePEM(pemOrDER, ['CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE'])
        : Buffer.from(pemOrDER);
    const { parsed } = asn1.parseSignedASN(der, 'certificate', asn1X509.Certificate);
    const inner = asn1.signatureParameters(parsed.tbsCertificate.signature);
    const outer = asn1.signatureParameters(parsed.signatureAlgorithm);
    if (JSON.stringify(inner) !== JSON.stringify(outer))
      throw new Error('Certificate signature algorithms do not match');
    asn1.validateRSAAlgorithm(parsed.tbsCertificate.subjectPublicKeyInfo.algorithm);
    const native = new crypto.X509Certificate(der);
    assert(native.publicKey.asymmetricKeyType === 'rsa', 'Expected RSA public key');
    if (!native.raw.equals(der))
      throw new Error('Certificate encoding does not match native representation');
    this.#validity = {
      notBefore: certificateDate(native.validFromDate, native.validFrom),
      notAfter: certificateDate(native.validToDate, native.validTo),
    };
    const seen = new Set<string>();
    for (const extension of parsed.tbsCertificate.extensions ?? []) {
      if (seen.has(extension.extnID)) throw new Error('Duplicate certificate extension');
      seen.add(extension.extnID);
      if (extension.extnID === asn1.keyUsageOID) {
        asn1.parseKeyUsage(extension.extnValue.buffer);
      } else if (extension.extnID === asn1.extendedKeyUsageOID) {
        asn1.parseASN(extension.extnValue.buffer, asn1X509.ExtendedKeyUsage);
      }
    }
    this.#data = { native, parsed, der };
    certificates.set(this, this.#data);
  }

  [certificateDER](): Buffer {
    return Buffer.from(this.#data.der);
  }

  get publicKey(): crypto.KeyObject {
    return this.#data.native.publicKey;
  }

  get validity(): { notBefore: Date; notAfter: Date } {
    return {
      notBefore: new Date(this.#validity.notBefore),
      notAfter: new Date(this.#validity.notAfter),
    };
  }
}

export class CertificateSigningRequest {
  readonly #data: CSRData;

  constructor(pemOrDER: string | Uint8Array) {
    const der =
      typeof pemOrDER === 'string'
        ? asn1.decodePEM(pemOrDER, ['CERTIFICATE REQUEST', 'NEW CERTIFICATE REQUEST'])
        : Buffer.from(pemOrDER);
    const { parsed, publicKeyDER } = asn1.parseSignedASN(der, 'csr', asn1CSR.CertificationRequest);
    if (parsed.certificationRequestInfo.version !== 0) throw new Error('Unsupported CSR version');
    asn1.signatureParameters(parsed.signatureAlgorithm);
    const publicKey = asn1.publicKeyFromSPKI(
      parsed.certificationRequestInfo.subjectPKInfo,
      publicKeyDER
    );
    this.#data = { parsed, der, publicKey };
    requests.set(this, this.#data);
  }

  [csrDER](): Buffer {
    return Buffer.from(this.#data.der);
  }
}

function ownedCertificateData(certificate: CodeSigningCertificate): CertificateData {
  const data = certificates.get(certificate);
  if (!data) {
    assert(
      typeof certificate?.[certificateDER] === 'function',
      'Expected package-owned certificate'
    );
    // Treat transferred bytes as fresh input, applying every local parser check.
    return ownedCertificateData(new CodeSigningCertificate(certificate[certificateDER]()));
  }
  return data;
}

export function getCertificateData(certificate: CodeSigningCertificate): CertificateData {
  const data = ownedCertificateData(certificate);
  const der = Buffer.from(data.der);
  return {
    der,
    native: new crypto.X509Certificate(der),
    parsed: asn1.parseASN(der, asn1X509.Certificate),
  };
}

function ownedCSRData(request: CertificateSigningRequest): CSRData {
  const data = requests.get(request);
  if (!data) {
    assert(typeof request?.[csrDER] === 'function', 'Expected package-owned CSR');
    return ownedCSRData(new CertificateSigningRequest(request[csrDER]()));
  }
  return data;
}

export function getCSRData(request: CertificateSigningRequest): Pick<CSRData, 'parsed' | 'der'> {
  const data = ownedCSRData(request);
  const der = Buffer.from(data.der);
  return { der, parsed: asn1.parseASN(der, asn1CSR.CertificationRequest) };
}

export function parseCertificate(pem: string): CodeSigningCertificate {
  return new CodeSigningCertificate(pem);
}

export function parseCSR(pem: string): CertificateSigningRequest {
  return new CertificateSigningRequest(pem);
}

export function certificateToPEM(certificate: CodeSigningCertificate): string {
  return asn1.encodePEM('CERTIFICATE', ownedCertificateData(certificate).der);
}

export function csrToPEM(request: CertificateSigningRequest): string {
  return asn1.encodePEM('CERTIFICATE REQUEST', ownedCSRData(request).der);
}

export function verifyCSR(request: CertificateSigningRequest): boolean {
  const { parsed, publicKey } = ownedCSRData(request);
  const parameters = asn1.signatureParameters(parsed.signatureAlgorithm);
  let key = publicKey;
  if (parameters.padding === crypto.constants.RSA_PKCS1_PSS_PADDING) {
    // Node has no independent MGF hash option. A validated RSA-PSS SPKI lets
    // OpenSSL apply the CSR's hash/MGF/salt constraints to the same RSA key.
    const constrained = new asn1X509.SubjectPublicKeyInfo({
      algorithm: parsed.signatureAlgorithm,
      subjectPublicKey: parsed.certificationRequestInfo.subjectPKInfo.subjectPublicKey,
    });
    key = crypto.createPublicKey({ key: asn1.encodeASN(constrained), format: 'der', type: 'spki' });
  }
  assert(parsed.certificationRequestInfoRaw, 'CSR signed content missing');
  return crypto.verify(
    parameters.hash,
    Buffer.from(parsed.certificationRequestInfoRaw),
    {
      key,
      padding: parameters.padding,
      ...(parameters.saltLength !== undefined ? { saltLength: parameters.saltLength } : {}),
    },
    Buffer.from(parsed.signature)
  );
}

export function hasKeyUsage(
  certificate: CodeSigningCertificate,
  flag: asn1X509.KeyUsageFlags
): boolean {
  const extension = ownedCertificateData(certificate).parsed.tbsCertificate.extensions?.find(
    (extension) => extension.extnID === asn1.keyUsageOID
  );
  return !!extension && (asn1.parseKeyUsage(extension.extnValue.buffer).toNumber() & flag) !== 0;
}

export function hasExtendedKeyUsage(certificate: CodeSigningCertificate, oid: string): boolean {
  const extension = ownedCertificateData(certificate).parsed.tbsCertificate.extensions?.find(
    (extension) => extension.extnID === asn1.extendedKeyUsageOID
  );
  return (
    !!extension &&
    asn1.parseASN(extension.extnValue.buffer, asn1X509.ExtendedKeyUsage).includes(oid)
  );
}

export function isCertificateSelfIssued(certificate: CodeSigningCertificate): boolean {
  const { parsed } = ownedCertificateData(certificate);
  return asn1
    .encodeASN(parsed.tbsCertificate.issuer)
    .equals(asn1.encodeASN(parsed.tbsCertificate.subject));
}

export function verifyCertificateSelfSignature(certificate: CodeSigningCertificate): boolean {
  const { native } = ownedCertificateData(certificate);
  return native.verify(native.publicKey);
}
