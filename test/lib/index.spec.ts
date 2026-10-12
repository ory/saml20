import assert from 'assert';
import { default as saml } from '../../lib/index';
import * as namedExports from '../../lib/index';
import type { AssertionReplayInfo, SAMLProfile, SAMLReq, ValidateOptions } from '../../lib/index';

// Locks the public API surface consumers rely on. containsDoctype is exported so
// callers (e.g. Ory Polis) can reject a DTD before their own XML parsing instead
// of duplicating the check. See https://github.com/ory/polis/issues/4071.
describe('index.ts', function () {
  it('should expose containsDoctype on the default export', function () {
    assert.strictEqual(typeof saml.containsDoctype, 'function');
  });

  it('should expose DEFAULT_MAX_SIGNATURE_REFERENCES on the default export', function () {
    assert.strictEqual(saml.DEFAULT_MAX_SIGNATURE_REFERENCES, 16);
  });

  it('containsDoctype should detect a DTD and be false for clean XML', function () {
    assert.strictEqual(saml.containsDoctype('<!DOCTYPE r><r/>'), true);
    assert.strictEqual(saml.containsDoctype('<?xml version="1.0"?><root><a>hi</a></root>'), false);
  });
});

describe('exported types', function () {
  // These assertions are checked by `npm run typecheck`; at runtime they only
  // build plain objects.
  it('describes validate() options and results', async function () {
    const seen = new Set<string>();
    const options: ValidateOptions = {
      publicKey: 'MIIC...',
      audience: ['https://sp.example.com', 'https://sp2.example.com'],
      inResponseTo: '_request',
      recipient: 'https://sp.example.com/acs',
      allowedSignatureAlgorithms: ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'],
      maxSignatureReferences: 1,
      assertionReplayValidator: async (info: AssertionReplayInfo) => {
        const used = seen.has(info.assertionId ?? '');
        seen.add(info.assertionId ?? '');
        return used;
      },
    };
    // @ts-expect-error strictAudienceValidation was removed in 2.0; audiences always match exactly
    const removed: ValidateOptions = { publicKey: 'MIIC...', strictAudienceValidation: true };
    // @ts-expect-error audience is required
    const noAudience: ValidateOptions = { publicKey: 'MIIC...' };
    // @ts-expect-error audience must be a string or a list of strings
    const invalid: ValidateOptions = { publicKey: 'MIIC...', audience: 42 };
    const profile: SAMLProfile = {
      audience: 'a',
      audiences: ['a'],
      claims: {},
      issuer: 'i',
      sessionIndex: 's',
    };
    const request: SAMLReq = { entityID: 'e', callbackUrl: 'c', signingKey: 'k', publicKey: 'p' };

    assert.strictEqual(await options.assertionReplayValidator!({ assertionId: '_a' }), false);
    assert.strictEqual(await options.assertionReplayValidator!({ assertionId: '_a' }), true);
    assert(removed && noAudience && invalid && profile && request);
  });
});

describe('named exports', function () {
  it('match the default export one for one', function () {
    const named = { ...namedExports } as Record<string, unknown>;
    delete named.default;
    assert.deepStrictEqual(Object.keys(named).sort(), Object.keys(saml).sort());
    for (const [name, value] of Object.entries(saml)) {
      assert.strictEqual(named[name], value, name);
    }
  });

  it('work with a CommonJS require of the built package shape', function () {
    // The compiled module keeps `exports.default` for require('...').default.
    assert.strictEqual(namedExports.default, saml);
    assert.strictEqual(typeof namedExports.validate, 'function');
  });
});
