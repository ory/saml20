import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import { parseIssuer, validate } from '../../lib/response';
import { parseSAMLRequest } from '../../lib/request';
import { parseLogoutRequest, parseLogoutResponse } from '../../lib/logout';
import type { ValidateOptions } from '../../lib/typings';

// SAML messages collected from other libraries' test fixtures (MANIFEST.json
// says where each came from). expected.json holds what @boxyhq/saml20 2.0.1
// returned for every applicable entry point, so this suite pins the parsers
// to the release immediately before xml2js was replaced. validate() runs with
// the options recorded per document: the certificate embedded in the message
// and its own Audience, with expiry bypassed, so a self-consistently signed
// response verifies and a tampered one is rejected.
const dir = path.resolve('./test/assets/saml-message-corpus');

type Outcome = { result?: unknown; error?: string; options?: ValidateOptions };
const expected = JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8')) as {
  documents: Record<string, Record<string, Outcome>>;
};
const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'MANIFEST.json'), 'utf8')) as {
  documents: { file: string; root: string }[];
};

// Documents where this parser intentionally differs from 2.0.1. None at
// present: the one upstream fixture that differed (CRLF inside element text,
// which xmldom normalises to LF as the XML specification requires and xml2js
// kept) is stored with LF here because .gitattributes normalises *.xml.
const intendedDifferences: Record<string, Record<string, (actual: Outcome) => void>> = {};

const normalizeError = (message: string) => message.replace(/error:[0-9A-Fa-f]+:/g, 'error:*:');

const entryPoints: Record<string, (xml: string, outcome: Outcome) => Promise<unknown>> = {
  parseIssuer: async (xml) => parseIssuer(xml),
  validate: async (xml, outcome) => validate(xml, outcome.options as ValidateOptions),
  parseSAMLRequestPost: async (xml) => parseSAMLRequest(xml, true),
  parseSAMLRequestRedirect: async (xml) => parseSAMLRequest(xml, false),
  parseLogoutRequest: async (xml) => parseLogoutRequest(xml),
  parseLogoutResponse: async (xml) => parseLogoutResponse(xml),
};

// expected.json went through JSON, which drops undefined-valued keys; do the
// same to the live result so the two compare on content.
const outcomeOf = async (fn: () => Promise<unknown>): Promise<Outcome> => {
  try {
    const value = await fn();
    return { result: value === undefined ? undefined : JSON.parse(JSON.stringify(value)) };
  } catch (err) {
    return { error: normalizeError((err as Error).message) };
  }
};

const files = fs
  .readdirSync(dir)
  .filter((f) => f.endsWith('.xml'))
  .sort();

describe('message parsers over the public SAML message corpus', function () {
  it('has an expectation and a manifest entry for every document', function () {
    assert.deepStrictEqual(Object.keys(expected.documents).sort(), files);
    assert.deepStrictEqual(manifest.documents.map((d) => d.file).sort(), files);
  });

  for (const file of files) {
    for (const [entryPoint, want] of Object.entries(expected.documents[file])) {
      it(`${entryPoint}: ${file}`, async function () {
        const xml = fs.readFileSync(path.join(dir, file), 'utf8');
        const actual = await outcomeOf(() => entryPoints[entryPoint](xml, want));
        const intended = intendedDifferences[file]?.[entryPoint];
        if (intended) {
          intended(actual);
          return;
        }
        if (want.error !== undefined) {
          assert.deepStrictEqual(actual, { error: want.error });
        } else {
          assert.deepStrictEqual(actual, { result: want.result });
        }
      });
    }
  }
});
