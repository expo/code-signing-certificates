import * as asn1Schema from '@peculiar/asn1-schema';
import * as asn1X509 from '@peculiar/asn1-x509';
import * as byteUtils from '@peculiar/utils/bytes';
import * as pemUtils from '@peculiar/utils/pem';
import * as asn1js from 'asn1js';
import assert from 'node:assert';
import * as crypto from 'node:crypto';

const rsaOID = '1.2.840.113549.1.1.1';
const pssOID = '1.2.840.113549.1.1.10';
const sha256RSAOID = '1.2.840.113549.1.1.11';
const mgf1OID = '1.2.840.113549.1.1.8';
export const keyUsageOID = '2.5.29.15';
export const extendedKeyUsageOID = '2.5.29.37';
const parseOptions = { parseEmbedded: false };

const signatureHashes: Record<string, string> = {
  '1.2.840.113549.1.1.4': 'md5',
  '1.2.840.113549.1.1.5': 'sha1',
  '1.3.14.3.2.29': 'sha1',
  [sha256RSAOID]: 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
};
const hashOIDs: Record<string, string> = {
  '1.2.840.113549.2.5': 'md5',
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

export function encodeASN(value: unknown): Buffer {
  return Buffer.from(asn1Schema.AsnSerializer.serialize(value));
}

function decodeASN(bytes: Uint8Array | ArrayBuffer): asn1js.AsnType {
  const parsed = asn1js.fromBER(bytes, parseOptions);
  if (parsed.result.error || parsed.offset !== bytes.byteLength) {
    throw new Error(parsed.result.error || 'Trailing ASN.1 data');
  }
  return parsed.result;
}

export function parseASN<T>(bytes: Uint8Array | ArrayBuffer, type: new () => T): T {
  return asn1Schema.AsnParser.fromASN(decodeASN(bytes), type, { berOptions: parseOptions });
}

export function decodePEM(pem: string, labels: readonly string[]): Buffer {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----\s*([\s\S]*?)\s*-----END \1-----/.exec(pem);
  if (!match || !labels.includes(match[1]!)) {
    throw new Error(`Expected ${labels.join(' or ')} PEM`);
  }
  // Keep first-block selection and whitespace compatibility; the codec validates Base64.
  const [block] = pemUtils.decode(match[0].replace(/\s/g, ' '), { strict: true });
  if (!block || block.headers || !block.data.length) {
    throw new Error('Invalid PEM encoding');
  }
  return Buffer.from(block.data);
}

export function encodePEM(label: string, bytes: Buffer): string {
  return pemUtils.encode(label, bytes, { lineLength: 64, newline: '\n' });
}

// Re-emit the exact signed SEQUENCE instead of serializing its model again.
class EncodedSequence extends asn1js.Sequence {
  constructor(private readonly encoded: Buffer) {
    super();
  }

  override toBER(sizeOnly = false, writer?: asn1js.ViewWriter): ArrayBuffer {
    const output = sizeOnly
      ? new ArrayBuffer(this.encoded.length)
      : byteUtils.toArrayBuffer(this.encoded);
    if (writer) {
      writer.write(output);
      return new ArrayBuffer(0);
    }
    return output;
  }
}

export function signedDER(content: unknown, signingKey: crypto.KeyObject): Buffer {
  assert(
    signingKey.type === 'private' && signingKey.asymmetricKeyType === 'rsa',
    'Expected RSA private key'
  );
  const bytes = encodeASN(content);
  const signature = crypto.sign('sha256', bytes, {
    key: signingKey,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });
  return Buffer.from(
    new asn1js.Sequence({
      value: [
        new EncodedSequence(bytes),
        asn1Schema.AsnSerializer.toASN(rsaSHA256()),
        new asn1js.BitString({ valueHex: byteUtils.toArrayBuffer(signature) }),
      ],
    }).toBER(false)
  );
}

export function rsaSHA256(): asn1X509.AlgorithmIdentifier {
  return new asn1X509.AlgorithmIdentifier({
    algorithm: sha256RSAOID,
    parameters: Uint8Array.of(5, 0).buffer,
  });
}

function validateNullParameters(algorithm: asn1X509.AlgorithmIdentifier): void {
  if (algorithm.parameters && !Buffer.from(algorithm.parameters).equals(Buffer.from([5, 0]))) {
    throw new Error('Invalid RSA algorithm parameters');
  }
}

type SignatureParameters = { hash: string; padding: number; mgfHash?: string; saltLength?: number };

function hashAlgorithm(algorithm: asn1X509.AlgorithmIdentifier): string {
  validateNullParameters(algorithm);
  const hash = hashOIDs[algorithm.algorithm];
  if (!hash) throw new Error('Unsupported signature hash algorithm');
  return hash;
}

export function signatureParameters(algorithm: asn1X509.AlgorithmIdentifier): SignatureParameters {
  if (algorithm.algorithm !== pssOID) {
    const hash = signatureHashes[algorithm.algorithm];
    if (!hash) throw new Error('Unsupported RSA signature algorithm');
    validateNullParameters(algorithm);
    return { hash, padding: crypto.constants.RSA_PKCS1_PADDING };
  }

  let hash = 'sha1';
  let mgfHash = 'sha1';
  let saltLength = 20;
  if (algorithm.parameters) {
    const parameters = decodeASN(algorithm.parameters);
    if (!(parameters instanceof asn1js.Sequence)) throw new Error('Invalid RSA-PSS parameters');
    const seen = new Set<number>();
    for (const field of parameters.valueBlock.value) {
      const tag = field.idBlock.tagNumber;
      if (
        !(field instanceof asn1js.Constructed) ||
        field.idBlock.tagClass !== 3 ||
        tag > 3 ||
        seen.has(tag) ||
        field.valueBlock.value.length !== 1
      ) {
        throw new Error('Invalid RSA-PSS parameter');
      }
      seen.add(tag);
      const value = field.valueBlock.value[0]!;
      if (tag === 0) {
        hash = hashAlgorithm(parseASN(value.valueBeforeDecodeView, asn1X509.AlgorithmIdentifier));
      } else if (tag === 1) {
        const mgf = parseASN(value.valueBeforeDecodeView, asn1X509.AlgorithmIdentifier);
        if (mgf.algorithm !== mgf1OID || !mgf.parameters)
          throw new Error('Unsupported RSA-PSS mask generation');
        mgfHash = hashAlgorithm(parseASN(mgf.parameters, asn1X509.AlgorithmIdentifier));
      } else {
        if (
          !(value instanceof asn1js.Integer) ||
          value.valueBlock.isHexOnly ||
          !Number.isSafeInteger(value.valueBlock.valueDec) ||
          value.valueBlock.valueDec < 0
        ) {
          throw new Error('Invalid RSA-PSS integer parameter');
        }
        if (tag === 2) saltLength = value.valueBlock.valueDec;
        else if (value.valueBlock.valueDec !== 1) throw new Error('Unsupported RSA-PSS trailer');
      }
    }
  }
  // Forge's incoming PSS digest dispatch always used SHA-256. Supporting other
  // PSS message hashes here would broaden the old verification policy.
  if (hash !== 'sha256') throw new Error('Unsupported RSA-PSS signature hash');
  return { hash, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, mgfHash, saltLength };
}

function sequence(value: asn1js.AsnType): asn1js.AsnType[] {
  if (!(value instanceof asn1js.Sequence)) throw new Error('Expected ASN.1 SEQUENCE');
  return value.valueBlock.value;
}

function validateBitString(value: asn1js.AsnType): void {
  if (
    !(value instanceof asn1js.BitString) ||
    value.idBlock.isConstructed ||
    value.valueBlock.unusedBits !== 0
  ) {
    throw new Error('Invalid RSA key or signature BIT STRING');
  }
}

export function parseSignedASN<T>(
  der: Buffer,
  kind: 'certificate' | 'csr',
  type: new () => T
): { parsed: T; publicKeyDER: Buffer } {
  const decoded = decodeASN(der);
  const outer = sequence(decoded);
  if (outer.length !== 3) throw new Error('Invalid signed ASN.1 object');
  validateBitString(outer[2]!);
  const content = sequence(outer[0]!);
  const spkiIndex = kind === 'csr' ? 2 : content[0]?.idBlock.tagClass === 3 ? 6 : 5;
  const spki = sequence(content[spkiIndex]!);
  if (spki.length !== 2) throw new Error('Invalid SubjectPublicKeyInfo');
  validateBitString(spki[1]!);
  return {
    parsed: asn1Schema.AsnParser.fromASN(decoded, type, { berOptions: parseOptions }),
    publicKeyDER: Buffer.from(content[spkiIndex]!.valueBeforeDecodeView),
  };
}

export function validateRSAAlgorithm(algorithm: asn1X509.AlgorithmIdentifier): void {
  if (algorithm.algorithm !== rsaOID) throw new Error('Expected RSA public key');
  validateNullParameters(algorithm);
}

export function publicKeyFromSPKI(
  spki: asn1X509.SubjectPublicKeyInfo,
  encoded = encodeASN(spki)
): crypto.KeyObject {
  validateRSAAlgorithm(spki.algorithm);
  const publicKey = crypto.createPublicKey({ key: encoded, type: 'spki', format: 'der' });
  assert(publicKey.asymmetricKeyType === 'rsa', 'Expected RSA public key');
  return publicKey;
}

export function parseKeyUsage(bytes: ArrayBuffer): asn1X509.KeyUsage {
  const encoded = decodeASN(bytes);
  if (!(encoded instanceof asn1js.BitString) || encoded.idBlock.isConstructed) {
    throw new Error('Invalid Key Usage BIT STRING');
  }
  const usage = asn1Schema.AsnParser.fromASN(encoded, asn1X509.KeyUsage);
  const value = Buffer.from(usage.value);
  if (
    usage.unusedBits < 0 ||
    usage.unusedBits > 7 ||
    (!value.length && usage.unusedBits !== 0) ||
    (value.length > 0 && (value[value.length - 1]! & ((1 << usage.unusedBits) - 1)) !== 0)
  ) {
    throw new Error('Invalid Key Usage BIT STRING');
  }
  return usage;
}
