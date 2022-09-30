import assert from 'assert';
import { md, pki as PKI, random, util } from 'node-forge';

import { toPositiveHex } from './utils';

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
export function generateKeyPair(): PKI.rsa.KeyPair {
  return PKI.rsa.generateKeyPair();
}

/**
 * Convert a key RSA key pair generated using {@link generateKeyPair} to PEM strings.
 * @param keyPair RSA key pair
 * @returns PEM formatted key pair
 */
export function convertKeyPairToPEM(keyPair: PKI.rsa.KeyPair): {
  privateKeyPEM: string;
  publicKeyPEM: string;
} {
  return {
    privateKeyPEM: PKI.privateKeyToPem(keyPair.privateKey),
    publicKeyPEM: PKI.publicKeyToPem(keyPair.publicKey),
  };
}

/**
 * Convert a X.509 certificate generated using {@link generateSelfSignedCodeSigningCertificate} to a PEM string.
 * @param certificate X.509 certificate
 * @returns
 */
export function convertCertificateToCertificatePEM(certificate: PKI.Certificate): string {
  return PKI.certificateToPem(certificate);
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
}): PKI.rsa.KeyPair {
  return {
    privateKey: PKI.privateKeyFromPem(privateKeyPEM),
    publicKey: PKI.publicKeyFromPem(publicKeyPEM),
  };
}

/**
 * Convert a PEM-formatted RSA public key to a public key for use with this library.
 * @param publicKeyPEM PEM formatted public key
 * @returns RSA public key
 */
export function convertPublicKeyPEMToPublicKey(publicKeyPEM: string): PKI.rsa.PublicKey {
  return PKI.publicKeyFromPem(publicKeyPEM);
}

/**
 * Convert a PEM-formatted RSA private key to a private key for use with this library.
 * @param privateKeyPEM PEM formatted private key
 * @returns RSA private key
 */
export function convertPrivateKeyPEMToPrivateKey(privateKeyPEM: string): PKI.rsa.PrivateKey {
  return PKI.privateKeyFromPem(privateKeyPEM);
}

/**
 * Convert a PEM-formatted X.509 certificate to a certificate for use with this library.
 * @param certificatePEM PEM formatted X.509 certificate
 * @returns  X.509 Certificate
 */
export function convertCertificatePEMToCertificate(certificatePEM: string): PKI.Certificate {
  return PKI.certificateFromPem(certificatePEM, true);
}

/**
 * Convert a CSR to PEM-formatted X.509 CSR
 * @param csr CSR
 * @returns X.509 CSR
 */
export function convertCSRToCSRPEM(csr: PKI.CertificateRequest): string {
  return PKI.certificationRequestToPem(csr);
}

/**
 * Convert a PEM-formatted X.509 CSR to a CSR
 * @param CSRPEM PEM-formatted X.509 CSR
 * @returns CSR
 */
export function convertCSRPEMToCSR(CSRPEM: string): PKI.CertificateRequest {
  return PKI.certificationRequestFromPem(CSRPEM, true) as PKI.CertificateRequest;
}

type GenerateParameters = {
  /**
   * Public/private key pair generated via {@link generateKeyPair}.
   */
  keyPair: PKI.rsa.KeyPair;

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
 * @returns PKI.Certificate valid for expo-updates code signing
 */
export function generateSelfSignedCodeSigningCertificate({
  keyPair: { publicKey, privateKey },
  validityNotBefore,
  validityNotAfter,
  commonName,
}: GenerateParameters): PKI.Certificate {
  const cert = PKI.createCertificate();
  cert.publicKey = publicKey;
  cert.serialNumber = toPositiveHex(util.bytesToHex(random.getBytesSync(9)));

  assert(
    validityNotAfter > validityNotBefore,
    'validityNotAfter must be later than validityNotBefore'
  );
  cert.validity.notBefore = validityNotBefore;
  cert.validity.notAfter = validityNotAfter;

  const attrs = [
    {
      name: 'commonName',
      value: commonName,
    },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
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

  cert.sign(privateKey, md.sha256.create());
  return cert;
}

function arePublicKeysEqual(key1: PKI.rsa.PublicKey, key2: PKI.rsa.PublicKey): boolean {
  return key1.n.equals(key2.n) && key1.e.equals(key2.e);
}

function doPrivateAndPublicKeysMatch(
  privateKey: PKI.rsa.PrivateKey,
  publicKey: PKI.rsa.PublicKey
): boolean {
  return publicKey.n.equals(privateKey.n) && publicKey.e.equals(privateKey.e);
}

/**
 * Validate that a certificate and corresponding key pair can be used for expo-updates code signing.
 * @param certificate X.509 certificate
 * @param keyPair RSA key pair
 */
export function validateSelfSignedCertificate(
  certificate: PKI.Certificate,
  keyPair: PKI.rsa.KeyPair
): void {
  if (certificate.issuer.hash !== certificate.subject.hash) {
    throw new Error(
      'Certificate issuer hash does not match subject hash, indicating certificate is not self-signed.'
    );
  }

  const now = new Date();
  if (certificate.validity.notBefore > now || certificate.validity.notAfter < now) {
    throw new Error('Certificate validity expired');
  }

  const keyUsage = certificate.getExtension('keyUsage');
  const digitalSignature = (keyUsage as any).digitalSignature;
  if (!keyUsage || !digitalSignature) {
    throw new Error('X509v3 Key Usage: Digital Signature not present');
  }

  const extKeyUsage = certificate.getExtension('extKeyUsage');
  const codeSigning = (extKeyUsage as any).codeSigning;
  if (!extKeyUsage || !codeSigning) {
    throw new Error('X509v3 Extended Key Usage: Code Signing not present');
  }

  const isValid = certificate.verify(certificate);
  if (!isValid) {
    throw new Error('Certificate signature not valid');
  }

  const certificatePublicKey = certificate.publicKey as PKI.rsa.PublicKey;
  if (!arePublicKeysEqual(certificatePublicKey, keyPair.publicKey)) {
    throw new Error('Certificate pubic key does not match key pair public key');
  }

  if (!doPrivateAndPublicKeysMatch(keyPair.privateKey, keyPair.publicKey)) {
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
 * @param stringToSign string to hash, generate a signature for, and verify
 * @returns base64-encoded RSA signature
 */
export function signStringRSASHA256AndVerify(
  privateKey: PKI.rsa.PrivateKey,
  certificate: PKI.Certificate,
  stringToSign: string
): string {
  const digest = md.sha256.create().update(stringToSign);
  const digestSignature = privateKey.sign(digest);
  const isValidSignature = (certificate.publicKey as PKI.rsa.PublicKey).verify(
    digest.digest().getBytes(),
    digestSignature
  );

  if (!isValidSignature) {
    throw new Error('Signature generated with private key not valid for certificate');
  }

  return util.encode64(digestSignature);
}

/**
 * Generate a self-signed CSR for a given key pair. Most commonly used with {@link generateDevelopmentCertificateFromCSR}.
 * @param keyPair RSA key pair
 * @param commonName commonName attribute of the subject of the resulting certificate (human readable name of the certificate)
 * @returns CSR
 */
export function generateCSR(keyPair: PKI.rsa.KeyPair, commonName: string): PKI.CertificateRequest {
  const csr = PKI.createCertificationRequest();
  csr.publicKey = keyPair.publicKey;
  const attrs = [
    {
      name: 'commonName',
      value: commonName,
    },
  ];
  csr.setSubject(attrs);
  csr.sign(keyPair.privateKey, md.sha256.create());
  return csr;
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
  issuerPrivateKey: PKI.rsa.PrivateKey,
  issuerCertificate: PKI.Certificate,
  csr: PKI.CertificateRequest,
  appId: string,
  scopeKey: string
): PKI.Certificate {
  assert(csr.verify(csr), 'CSR not self-signed');

  const certificate = PKI.createCertificate();
  certificate.publicKey = csr.publicKey;
  certificate.serialNumber = toPositiveHex(util.bytesToHex(random.getBytesSync(9)));

  // set certificate subject attrs from CSR
  certificate.setSubject(csr.subject.attributes);

  // 30 day validity into the future, 5 days in the past just in case of clock skew at callsite
  certificate.validity.notBefore = new Date();
  certificate.validity.notBefore.setDate(certificate.validity.notBefore.getDate() - 5);
  certificate.validity.notAfter = new Date();
  certificate.validity.notAfter.setDate(certificate.validity.notBefore.getDate() + 30);

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
      value: `${appId},${scopeKey}`,
    },
  ]);

  certificate.sign(issuerPrivateKey, md.sha256.create());
  return certificate;
}
