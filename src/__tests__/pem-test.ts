import { readFileSync } from 'node:fs';
import path from 'node:path';

import { decodePEM, encodePEM } from '../asn1';

describe.each([
  ['valid-certificate.pem', 'CERTIFICATE', ['X509 CERTIFICATE', 'TRUSTED CERTIFICATE']],
  ['historical-csr.pem', 'CERTIFICATE REQUEST', ['NEW CERTIFICATE REQUEST']],
] as const)('PEM compatibility: %s', (file, label, aliases) => {
  const original = readFileSync(path.join(__dirname, 'fixtures', file), 'utf8');
  const expectedPEM = original.replace(/\r\n/g, '\n').trim() + '\n';
  const expectedDER = Buffer.from(original.replace(/-----[^\n]+-----|\s/g, ''), 'base64');
  const labels = [label, ...aliases];

  it('preserves DER and canonical 64-column LF output including its final newline', () => {
    expect(decodePEM(original, labels)).toEqual(expectedDER);
    expect(encodePEM(label, expectedDER)).toBe(expectedPEM);
  });

  it('accepts legacy labels without changing the bytes', () => {
    for (const alias of aliases) {
      expect(decodePEM(original.replaceAll(label, alias), labels)).toEqual(expectedDER);
    }
  });

  test.each([
    ['CRLF', (value: string) => value.replace(/\n/g, '\r\n')],
    ['indentation', (value: string) => value.replace(/^/gm, '  \t')],
    ['surrounding text', (value: string) => `preamble\n${value}\ntrailer`],
  ] as const)('accepts %s', (_description, transform) => {
    expect(decodePEM(transform(original), labels)).toEqual(expectedDER);
  });

  it('accepts internal whitespace supported by the previous decoder', () => {
    const value = original.replace(
      /\n([A-Za-z0-9+/=]+)(?=\n)/g,
      (_line, body: string) => '\n' + body.replace(/(.{8})/g, '$1\v\f\u00a0')
    );
    expect(decodePEM(value, labels)).toEqual(expectedDER);
  });

  it('reads the first complete block even when later blocks are malformed', () => {
    const malformed = `-----BEGIN ${label}-----\n!!!!\n-----END ${label}-----`;
    expect(decodePEM(original + malformed, labels)).toEqual(expectedDER);
    expect(() => decodePEM(malformed + original, labels)).toThrow();
  });

  it('rejects an unexpected first label instead of searching for an allowed later block', () => {
    const wrongLabel = original.replaceAll(label, 'PUBLIC KEY');
    expect(() => decodePEM(wrongLabel + original, labels)).toThrow();
  });

  it('rejects mismatched delimiters', () => {
    expect(() => decodePEM(original.replace(`END ${label}`, 'END PUBLIC KEY'), labels)).toThrow();
  });

  test.each(['', '!!!!', 'A===', 'AAA', 'AAAA====', 'Proc-Type: 4,ENCRYPTED\n\nAAAA'])(
    'rejects an empty, malformed or header-bearing body: %p',
    (body) => {
      expect(() =>
        decodePEM(`-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`, labels)
      ).toThrow();
    }
  );
});
