import assert from 'assert';

// Everything each module exports as of 2.0.0. Consumers can import any built
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
  response: { named: ['WrapError', 'createSAMLResponse', 'parseIssuer', 'validate'] },
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
      'multiRootedXMLError',
      'parseFromString',
      'thumbprint',
    ],
  },
  validateSignature: {
    named: ['DEFAULT_MAX_SIGNATURE_REFERENCES', 'certToPEM', 'sanitizeXML', 'validateSignature'],
  },
};

describe('published module exports', function () {
  for (const [name, { named, defaultKeys }] of Object.entries(published)) {
    it(`lib/${name} still exports everything 2.0.0 does`, function () {
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

// Removed on purpose in 2.0.0. Bringing one back is a decision, not an accident.
const removed: Record<string, { named?: string[]; defaultKeys?: string[] }> = {
  index: {
    named: ['parse', 'decryptXml', 'PubKeyInfo'],
    defaultKeys: ['parse', 'decryptXml', 'PubKeyInfo'],
  },
  response: { named: ['parse'] },
  utils: { named: ['isMultiRootedXMLError'] },
  validateSignature: { named: ['hasValidSignature'] },
};

describe('exports removed in 2.0.0', function () {
  for (const [name, { named = [], defaultKeys = [] }] of Object.entries(removed)) {
    it(`lib/${name} no longer exports them`, function () {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const mod = require(`../../lib/${name}`);
      assert.deepStrictEqual(
        named.filter((key) => mod[key] !== undefined),
        [],
        'named exports that should be gone'
      );
      assert.deepStrictEqual(
        defaultKeys.filter((key) => mod.default?.[key] !== undefined),
        [],
        'default export keys that should be gone'
      );
    });
  }
});
