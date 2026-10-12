import assert from 'assert';
import { isMultiRootedXMLError } from '../../lib/utils';
import { hasValidSignature } from '../../lib/validateSignature';
import { ASSERTION_XPATH, buildAssertion, signXml, testIdpCert } from '../helpers/fixtures';

// Everything each module exported in 1.21.0. Consumers can import any built
// module directly (dist/<module>), so removing one of these is a breaking change.
const published: Record<string, { named: string[]; defaultKeys?: string[] }> = {
  cert: { named: ['PubKeyInfo', 'stripCertHeaderAndFooter'] },
  decrypt: { named: ['decryptXml'] },
  getVersion: { named: ['getVersion'] },
  index: {
    named: ['default'],
    defaultKeys: [
      'DEFAULT_MAX_SIGNATURE_REFERENCES',
      'MAX_ENCODED_REQUEST_LENGTH',
      'MAX_INFLATED_REQUEST_BYTES',
      'PubKeyInfo',
      'WrapError',
      'certToPEM',
      'containsDoctype',
      'createIdPMetadataXML',
      'createLogoutRequest',
      'createLogoutResponse',
      'createPostForm',
      'createSAMLResponse',
      'createSPMetadataXML',
      'decodeBase64',
      'decryptXml',
      'parse',
      'parseIssuer',
      'parseLogoutRequest',
      'parseLogoutResponse',
      'parseMetadata',
      'parseSAMLRequest',
      'request',
      'samlRequestDecodeError',
      'samlRequestTooLargeError',
      'sign',
      'stripCertHeaderAndFooter',
      'validate',
      'validateSignature',
    ],
  },
  logout: {
    named: ['createLogoutRequest', 'createLogoutResponse', 'parseLogoutRequest', 'parseLogoutResponse'],
  },
  metadata: { named: ['createIdPMetadataXML', 'createSPMetadataXML', 'parseMetadata'] },
  post: { named: ['createPostForm'] },
  request: {
    named: [
      'MAX_ENCODED_REQUEST_LENGTH',
      'MAX_INFLATED_REQUEST_BYTES',
      'decodeBase64',
      'parseSAMLRequest',
      'request',
      'samlRequestDecodeError',
      'samlRequestTooLargeError',
    ],
  },
  response: { named: ['WrapError', 'createSAMLResponse', 'parse', 'parseIssuer', 'validate'] },
  saml20: {
    named: ['default'],
    defaultKeys: [
      'getAssertionId',
      'getDestination',
      'getInResponseTo',
      'getNotOnOrAfter',
      'getSubjectConfirmationInResponseTo',
      'parse',
      'validateAudience',
      'validateExpiration',
      'validateRecipient',
    ],
  },
  sign: { named: ['sign'] },
  typings: { named: [] },
  utils: {
    named: [
      'containsDoctype',
      'doctypeNotAllowedError',
      'getAttribute',
      'isMultiRootedXMLError',
      'multiRootedXMLError',
      'parseFromString',
      'thumbprint',
    ],
  },
  validateSignature: {
    named: [
      'DEFAULT_MAX_SIGNATURE_REFERENCES',
      'certToPEM',
      'hasValidSignature',
      'sanitizeXML',
      'validateSignature',
    ],
  },
};

describe('published module exports', function () {
  for (const [name, { named, defaultKeys }] of Object.entries(published)) {
    it(`lib/${name} still exports everything 1.21.0 did`, function () {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const mod = require(`../../lib/${name}`);
      assert.deepStrictEqual(
        named.filter((key) => mod[key] === undefined),
        [],
        'missing named exports'
      );
      if (defaultKeys) {
        assert.deepStrictEqual(
          defaultKeys.filter((key) => mod.default?.[key] === undefined),
          [],
          'missing keys on the default export'
        );
      }
    });
  }
});

describe('deprecated module exports keep working', function () {
  it('utils.isMultiRootedXMLError recognises the parser message', function () {
    assert.strictEqual(
      isMultiRootedXMLError({ message: 'Only one element can be added and only after doctype' }),
      true
    );
    assert.strictEqual(isMultiRootedXMLError({ message: 'Other error' }), false);
  });

  it('validateSignature.hasValidSignature verifies a signature', function () {
    const signed = signXml(buildAssertion(), ASSERTION_XPATH);
    assert(hasValidSignature(signed, testIdpCert, null));
    assert.strictEqual(
      hasValidSignature(signed.replace('jo@example.com', 'eve@example.com'), testIdpCert, null),
      null
    );
  });
});
