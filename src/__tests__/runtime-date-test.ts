import { Sequence, fromBER } from 'asn1js';
import * as crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';

import * as api from '../main';

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
});
