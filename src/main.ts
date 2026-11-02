import * as asn1X509 from '@peculiar/asn1-x509';
import assert from 'assert';
import * as crypto from 'crypto';

import * as asn1 from './asn1';
import * as x509 from './x509';
import * as x509Generation from './x509Generation';

export { CodeSigningCertificate } from './x509';
export type { CertificateSigningRequest } from './x509';

export type RSAKeyPair = { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };

function requireRSAKey(key: crypto.KeyObject, role: 'public' | 'private'): void {
  assert(key instanceof crypto.KeyObject && key.type === role, `Expected a ${role} key`);
  assert(key.asymmetricKeyType === 'rsa', 'Expected an RSA key');
}

function requireKeyPair(keyPair: RSAKeyPair): void {
  requireRSAKey(keyPair.publicKey, 'public');
  requireRSAKey(keyPair.privateKey, 'private');
}

function normalizeKeyPEM(pem: string): string {
  return pem
    .split(/\r\n|\r|\n/)
    .map((line) => line.trim())
    .join('\n');
}

const codeSigningExtensions = [
  { name: 'keyUsage', critical: true, digitalSignature: true },
  { name: 'extKeyUsage', critical: true, codeSigning: true },
];

/**
 * Custom X.509 extension that stores information about the Expo project that a code signing certificate is valid for.
 * Used to prevent spoofing of scoping identifiers in Expo Go.
 *
 * Note: Generated with oidgen script. Resides in the Microsoft OID space. Could apply for Expo space but would take time: https://pen.iana.org/pen/PenApplication.page
 */
export const expoProjectInformationOID =
  '1.2.840.113556.1.8000.2554.43437.254.128.102.157.7894389.20439.2.1';

/**
 * Generate a public and private RSA key pair.
 * @returns RSA key pair
 */
export function generateKeyPair(): RSAKeyPair {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
}

/**
 * Convert a key RSA key pair generated using {@link generateKeyPair} to PEM strings.
 * @param keyPair RSA key pair
 * @returns PEM formatted key pair
 */
export function convertKeyPairToPEM(keyPair: RSAKeyPair): {
  privateKeyPEM: string;
  publicKeyPEM: string;
} {
  requireKeyPair(keyPair);
  return {
    privateKeyPEM: keyPair.privateKey.export({ type: 'pkcs1', format: 'pem' }).toString(),
    publicKeyPEM: keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

/**
 * Convert a X.509 certificate generated using {@link generateSelfSignedCodeSigningCertificate} to a PEM string.
 * @param certificate X.509 certificate
 * @returns
 */
export function convertCertificateToCertificatePEM(
  certificate: x509.CodeSigningCertificate
): string {
  return x509.certificateToPEM(certificate);
}

/**
 * Convert a PEM-formatted RSA key pair to a key pair for use with this library.
 * @param keyPair PEM-formatted private key and public key
 * @returns RSA key pair
 */
export function convertKeyPairPEMToKeyPair({
  privateKeyPEM,
  publicKeyPEM,
}: {
  privateKeyPEM: string;
  publicKeyPEM: string;
}): RSAKeyPair {
  return {
    privateKey: convertPrivateKeyPEMToPrivateKey(privateKeyPEM),
    publicKey: convertPublicKeyPEMToPublicKey(publicKeyPEM),
  };
}

/**
 * Convert a PEM-formatted RSA public key to a public key for use with this library.
 * @param publicKeyPEM PEM formatted public key
 * @returns RSA public key
 */
export function convertPublicKeyPEMToPublicKey(publicKeyPEM: string): crypto.KeyObject {
  const label = publicKeyPEM.match(/-----BEGIN ([^-]+)-----/)?.[1];
  assert(label === 'PUBLIC KEY' || label === 'RSA PUBLIC KEY', 'Expected a public key PEM');
  const key = crypto.createPublicKey(normalizeKeyPEM(publicKeyPEM));
  requireRSAKey(key, 'public');
  return key;
}

/**
 * Convert a PEM-formatted RSA private key to a private key for use with this library.
 * @param privateKeyPEM PEM formatted private key
 * @returns RSA private key
 */
export function convertPrivateKeyPEMToPrivateKey(privateKeyPEM: string): crypto.KeyObject {
  const label = privateKeyPEM.match(/-----BEGIN ([^-]+)-----/)?.[1];
  assert(label === 'PRIVATE KEY' || label === 'RSA PRIVATE KEY', 'Expected a private key PEM');
  const key = crypto.createPrivateKey(normalizeKeyPEM(privateKeyPEM));
  requireRSAKey(key, 'private');
  return key;
}

/**
 * Convert a PEM-formatted X.509 certificate to a certificate for use with this library.
 * @param certificatePEM PEM formatted X.509 certificate
 * @returns  X.509 Certificate
 */
export function convertCertificatePEMToCertificate(
  certificatePEM: string
): x509.CodeSigningCertificate {
  return x509.parseCertificate(certificatePEM);
}

/**
 * Convert a CSR to PEM-formatted X.509 CSR
 * @param csr CSR
 * @returns X.509 CSR
 */
export function convertCSRToCSRPEM(csr: x509.CertificateSigningRequest): string {
  return x509.csrToPEM(csr);
}

/**
 * Convert a PEM-formatted X.509 CSR to a CSR
 * @param CSRPEM PEM-formatted X.509 CSR
 * @returns CSR
 */
export function convertCSRPEMToCSR(CSRPEM: string): x509.CertificateSigningRequest {
  return x509.parseCSR(CSRPEM);
}

type GenerateParameters = {
  /**
   * Public/private key pair generated via {@link generateKeyPair}.
   */
  keyPair: RSAKeyPair;

  /**
   * Certificate validity range start.
   */
  validityNotBefore: Date;

  /**
   * Certificate validity range end.
   */
  validityNotAfter: Date;

  /**
   * CN issuer and subject Distinguished Name (DN).
   * Used for both issuer and subject in the case of self-signed certificates.
   */
  commonName: string;
};

/**
 * Generate a self-signed (root) code-signing certificate valid for use with expo-updates.
 *
 * @returns CodeSigningCertificate valid for expo-updates code signing
 */
export function generateSelfSignedCodeSigningCertificate({
  keyPair: { publicKey, privateKey },
  validityNotBefore,
  validityNotAfter,
  commonName,
}: GenerateParameters): x509.CodeSigningCertificate {
  requireKeyPair({ publicKey, privateKey });
  assert(
    validityNotAfter > validityNotBefore,
    'validityNotAfter must be later than validityNotBefore'
  );
  const name = [{ name: 'commonName', value: commonName }];
  return x509Generation.createCertificate({
    publicKey,
    signingKey: privateKey,
    subject: name,
    issuer: name,
    notBefore: validityNotBefore,
    notAfter: validityNotAfter,
    extensions: codeSigningExtensions,
  });
}

function arePublicKeysEqual(key1: crypto.KeyObject, key2: crypto.KeyObject): boolean {
  return key1
    .export({ type: 'spki', format: 'der' })
    .equals(key2.export({ type: 'spki', format: 'der' }));
}

/**
 * Validate that a certificate and corresponding key pair can be used for expo-updates code signing.
 * @param certificate X.509 certificate
 * @param keyPair RSA key pair
 */
export function validateSelfSignedCertificate(
  certificate: x509.CodeSigningCertificate,
  keyPair: RSAKeyPair
): void {
  if (!x509.isCertificateSelfIssued(certificate)) {
    throw new Error(
      'Certificate issuer hash does not match subject hash, indicating certificate is not self-signed.'
    );
  }

  const now = new Date();
  if (certificate.validity.notBefore > now || certificate.validity.notAfter < now) {
    throw new Error('Certificate validity expired');
  }

  if (!x509.hasKeyUsage(certificate, asn1X509.KeyUsageFlags.digitalSignature)) {
    throw new Error('X509v3 Key Usage: Digital Signature not present');
  }
  if (!x509.hasExtendedKeyUsage(certificate, asn1X509.id_kp_codeSigning)) {
    throw new Error('X509v3 Extended Key Usage: Code Signing not present');
  }
  const isValid = x509.verifyCertificateSelfSignature(certificate);
  if (!isValid) {
    throw new Error('Certificate signature not valid');
  }

  requireKeyPair(keyPair);
  requireRSAKey(certificate.publicKey, 'public');
  const certificatePublicKey = certificate.publicKey;
  if (!arePublicKeysEqual(certificatePublicKey, keyPair.publicKey)) {
    throw new Error('Certificate pubic key does not match key pair public key');
  }

  if (!arePublicKeysEqual(crypto.createPublicKey(keyPair.privateKey), keyPair.publicKey)) {
    throw new Error('keyPair key mismatch');
  }
}

/**
 * Sign a SHA-256 hash of the provided string with an RSA private key and verify that the signature
 * is valid for the RSA public key in the certificate. The verification part is most useful for
 * debugging, so while this may be used in server implementation for expo-updates code signing,
 * a similar method without verification can be created for efficiency for use in production.
 *
 * @param privateKey RSA private key
 * @param certificate X.509 certificate
 * @param bufferToSign buffer to hash, generate a signature for, and verify
 * @returns base64-encoded RSA signature
 */
export function signBufferRSASHA256AndVerify(
  privateKey: crypto.KeyObject,
  certificate: x509.CodeSigningCertificate,
  bufferToSign: Buffer
): string {
  requireRSAKey(privateKey, 'private');
  requireRSAKey(certificate.publicKey, 'public');
  const digestSignature = crypto.sign('sha256', bufferToSign, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });
  const isValidSignature = crypto.verify(
    'sha256',
    bufferToSign,
    {
      key: certificate.publicKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    digestSignature
  );

  if (!isValidSignature) {
    throw new Error('Signature generated with private key not valid for certificate');
  }

  return digestSignature.toString('base64');
}

/**
 * Generate a self-signed CSR for a given key pair. Most commonly used with {@link generateDevelopmentCertificateFromCSR}.
 * @param keyPair RSA key pair
 * @param commonName commonName attribute of the subject of the resulting certificate (human readable name of the certificate)
 * @returns CSR
 */
export function generateCSR(
  keyPair: RSAKeyPair,
  commonName: string
): x509.CertificateSigningRequest {
  requireKeyPair(keyPair);
  return x509Generation.createCSR(keyPair, commonName);
}

/**
 * For use by a server to generate a development certificate (good for 30 days) for a particular
 * appId and scopeKey (Expo project manifest fields verified by the client during certificate validation).
 *
 * Note that this function assumes the issuer is trusted, and that the user that created the CSR and issued
 * the request has permission to sign manifests for the appId and scopeKey. This constraint must be
 * verified on the server before calling this method.
 *
 * @param issuerPrivateKey private key to sign the resulting certificate with
 * @param issuerCertificate parent certificate (should be a CA) of the resulting certificate
 * @param csr certificate signing request containing the user's public key
 * @param appId app ID (UUID) of the app that the resulting certificate will sign the development manifest for
 * @param scopeKey scope key of the app that the resuting certificate will sign the development manifest for
 * @returns certificate to use to sign development manifests
 */
export function generateDevelopmentCertificateFromCSR(
  issuerPrivateKey: crypto.KeyObject,
  issuerCertificate: x509.CodeSigningCertificate,
  csr: x509.CertificateSigningRequest,
  appId: string,
  scopeKey: string
): x509.CodeSigningCertificate {
  assert(x509.verifyCSR(csr), 'CSR not self-signed');
  const request = x509.getCSRData(csr).parsed.certificationRequestInfo;
  const publicKey = asn1.publicKeyFromSPKI(request.subjectPKInfo);
  requireRSAKey(issuerPrivateKey, 'private');

  // Preserve the existing local calendar arithmetic, including month overflow.
  const notBefore = new Date();
  notBefore.setDate(notBefore.getDate() - 1);
  const notAfter = new Date();
  notAfter.setDate(notBefore.getDate() + 30);

  return x509Generation.createCertificate({
    publicKey,
    signingKey: issuerPrivateKey,
    subject: request.subject,
    issuer: x509.getCertificateData(issuerCertificate).parsed.tbsCertificate.subject,
    notBefore,
    notAfter,
    extensions: [
      ...codeSigningExtensions,
      { id: expoProjectInformationOID, value: `${appId},${scopeKey}` },
    ],
  });
}
