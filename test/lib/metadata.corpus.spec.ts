import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import { parseMetadata } from '../../lib/metadata';

// IdP metadata collected from other SAML libraries' test fixtures (see
// MANIFEST.json for where each document came from). expected.json holds what
// @boxyhq/saml20 1.22.0 returned for every document, so this suite pins the
// parser to the behaviour that was in production before xml2js was replaced.
const dir = path.resolve('./test/assets/idp-metadata-corpus');
const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8')) as {
  documents: Record<string, { result?: unknown; error?: string }>;
};
const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'MANIFEST.json'), 'utf8')) as {
  documents: { file: string }[];
};

// Documents where this parser intentionally differs from 1.22.0.
const intendedDifferences: Record<string, RegExp> = {
  // Two root elements: xml2js read the first and ignored the rest; xmldom
  // rejects the document as not well-formed.
  'samlify--test_misc_multiple_entitydescriptor.xml': /multirooted xml not allowed/,
};

// OpenSSL error messages carry a version-specific hex code.
const normalizeError = (message: string) => message.replace(/error:[0-9A-Fa-f]+:/g, 'error:*:');

const files = fs
  .readdirSync(dir)
  .filter((f) => f.endsWith('.xml'))
  .sort();

describe('parseMetadata over the public IdP metadata corpus', function () {
  it('has an expectation and a manifest entry for every document', function () {
    assert.deepStrictEqual(Object.keys(expected.documents).sort(), files);
    assert.deepStrictEqual(manifest.documents.map((d) => d.file).sort(), files);
  });

  for (const file of files) {
    it(file, async function () {
      const xml = fs.readFileSync(path.join(dir, file), 'utf8');
      const intended = intendedDifferences[file];
      if (intended) {
        await assert.rejects(parseMetadata(xml), intended);
        return;
      }

      const want = expected.documents[file];
      if (want.error !== undefined) {
        await assert.rejects(parseMetadata(xml), (err: Error) => {
          assert.strictEqual(normalizeError(err.message), want.error);
          return true;
        });
      } else {
        assert.deepStrictEqual(await parseMetadata(xml), want.result);
      }
    });
  }
});
