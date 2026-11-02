import * as asn1CSR from '@peculiar/asn1-csr';
import * as asn1Schema from '@peculiar/asn1-schema';
import * as asn1X509 from '@peculiar/asn1-x509';
import * as bytes from '@peculiar/utils/bytes';
import * as asn1js from 'asn1js';
import assert from 'node:assert';
import * as crypto from 'node:crypto';

import * as asn1 from './asn1';
import { toPositiveHex } from './utils';
import * as x509 from './x509';

export function createCSR(
  keyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject },
  commonName: string
): x509.CertificateSigningRequest {
  const info = new asn1CSR.CertificationRequestInfo({
    version: 0,
    subject: nameFromAttributes([{ name: 'commonName', value: commonName }]),
    subjectPKInfo: asn1.parseASN(
      keyPair.publicKey.export({ type: 'spki', format: 'der' }),
      asn1X509.SubjectPublicKeyInfo
    ),
  });
  return new x509.CertificateSigningRequest(asn1.signedDER(info, keyPair.privateKey));
}

export type NameAttribute = {
  name?: string;
  shortName?: string;
  value: string;
};
const nameOIDs: Record<string, string> = {
  commonName: '2.5.4.3',
  countryName: '2.5.4.6',
  localityName: '2.5.4.7',
  ST: '2.5.4.8',
  organizationName: '2.5.4.10',
  OU: '2.5.4.11',
};

export function nameFromAttributes(attributes: NameAttribute[]): asn1X509.Name {
  return new asn1X509.Name(
    attributes.map((attribute) => {
      const type = nameOIDs[attribute.name ?? attribute.shortName ?? ''];
      assert(type, 'Unknown distinguished name attribute');
      const value = new asn1X509.AttributeValue({ printableString: attribute.value });
      return new asn1X509.RelativeDistinguishedName([
        new asn1X509.AttributeTypeAndValue({ type, value }),
      ]);
    })
  );
}

export type CertificateExtension = {
  name?: string;
  id?: string;
  critical?: boolean;
  value?: string | Uint8Array;
  digitalSignature?: boolean;
  keyCertSign?: boolean;
  cRLSign?: boolean;
  codeSigning?: boolean;
  cA?: boolean;
  pathLenConstraint?: number;
};
const keyUsageNames = ['digitalSignature', 'keyCertSign', 'cRLSign'] as const;

function extensionFromParameters(parameters: CertificateExtension): asn1X509.Extension {
  let id = parameters.id;
  let value: Buffer;
  if (parameters.name === 'keyUsage') {
    id = asn1.keyUsageOID;
    const flags = keyUsageNames.reduce(
      (flags, name) => flags | (parameters[name] ? asn1X509.KeyUsageFlags[name] : 0),
      0
    );
    value = asn1.encodeASN(new asn1X509.KeyUsage(flags));
  } else if (parameters.name === 'extKeyUsage') {
    id = asn1.extendedKeyUsageOID;
    const usages = parameters.codeSigning ? [asn1X509.id_kp_codeSigning] : [];
    value = asn1.encodeASN(new asn1X509.ExtendedKeyUsage(usages));
  } else if (parameters.name === 'basicConstraints') {
    id = '2.5.29.19';
    value = asn1.encodeASN(
      new asn1X509.BasicConstraints({
        cA: parameters.cA ?? false,
        ...(parameters.pathLenConstraint !== undefined
          ? { pathLenConstraint: parameters.pathLenConstraint }
          : {}),
      })
    );
  } else {
    assert(parameters.value !== undefined, 'Extension value required');
    value =
      typeof parameters.value === 'string'
        ? Buffer.from(parameters.value, 'latin1')
        : Buffer.from(parameters.value);
  }
  assert(id, 'Extension OID required');
  return new asn1X509.Extension({
    extnID: id,
    critical: parameters.critical ?? false,
    extnValue: new asn1Schema.OctetString(value),
  });
}

export type CertificateParameters = {
  publicKey: crypto.KeyObject;
  signingKey: crypto.KeyObject;
  subject: asn1X509.Name | NameAttribute[];
  issuer: asn1X509.Name | NameAttribute[];
  notBefore: Date;
  notAfter: Date;
  extensions?: CertificateExtension[];
  serialNumber?: string;
};

function certificateTime(date: Date): asn1X509.Time {
  assert(Number.isFinite(date.getTime()), 'Invalid certificate date');
  const encodedDate = new Date(Math.floor(date.getTime() / 1000) * 1000);
  return encodedDate.getUTCFullYear() < 1950 || encodedDate.getUTCFullYear() >= 2050
    ? new asn1X509.Time({ generalTime: encodedDate })
    : new asn1X509.Time({ utcTime: encodedDate });
}

export function createCertificate(parameters: CertificateParameters): x509.CodeSigningCertificate {
  assert(
    parameters.publicKey.type === 'public' && parameters.publicKey.asymmetricKeyType === 'rsa',
    'Expected RSA public key'
  );
  const serial = parameters.serialNumber ?? toPositiveHex(crypto.randomBytes(9).toString('hex'));
  const validity = new asn1X509.Validity();
  validity.notBefore = certificateTime(parameters.notBefore);
  validity.notAfter = certificateTime(parameters.notAfter);
  const certificate = new asn1X509.TBSCertificate({
    version: asn1X509.Version.v3,
    serialNumber: bytes.toArrayBuffer(
      asn1js.Integer.fromBigInt(BigInt(`0x${serial}`)).valueBlock.valueHexView
    ),
    signature: asn1.rsaSHA256(),
    subject:
      parameters.subject instanceof asn1X509.Name
        ? parameters.subject
        : nameFromAttributes(parameters.subject),
    issuer:
      parameters.issuer instanceof asn1X509.Name
        ? parameters.issuer
        : nameFromAttributes(parameters.issuer),
    validity,
    subjectPublicKeyInfo: asn1.parseASN(
      parameters.publicKey.export({ format: 'der', type: 'spki' }),
      asn1X509.SubjectPublicKeyInfo
    ),
    ...(parameters.extensions?.length
      ? { extensions: new asn1X509.Extensions(parameters.extensions.map(extensionFromParameters)) }
      : {}),
  });
  return new x509.CodeSigningCertificate(asn1.signedDER(certificate, parameters.signingKey));
}
