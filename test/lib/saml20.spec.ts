import assert from 'assert';
import { default as saml20 } from '../../lib/saml20';
import fs from 'fs';

const assertion = fs.readFileSync('./test/assets/saml20.validResponseSignedMessage.xml').toString();

const validateOpts = {
  thumbprint: 'e606eced42fa3abd0c5693456384f5931b174707',
  audience: 'http://sp.example.com/demo1/metadata.php',
  inResponseTo: 'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
};

const validateOptsArray = [
  'e606eced42fa3abd0c5693456384f5931b174707',
  'http://sp.example.com/demo1/metadata.php',
  'ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685',
];

const assertion1 = {
  Conditions: {
    AudienceRestriction: {
      Audience: 'https://saml.boxyhq.com/f46e93394c5a51d36715d95d910872ac7372d4d9',
    },
  },
};

describe('saml20.ts', function () {
  it('parse assertion ok', function () {
    const value = saml20.parse(assertion);
    assert.strictEqual(value.audience, undefined);
    assert.deepEqual(value.claims, {});
    assert.strictEqual(value.issuer, undefined);
    assert.strictEqual(value.sessionIndex, undefined);
    assert(saml20.parse(assertion));
  });

  it('parse assertion not ok', function () {
    try {
      const value = saml20.parse('assertion');
      assert.strictEqual(value.audience, undefined);
      assert.deepEqual(value.claims, {});
      assert.strictEqual(value.issuer, undefined);
      assert.strictEqual(value.sessionIndex, undefined);
    } catch (error) {
      assert(error);
    }
  });

  it('validateAudience false', function () {
    const value = saml20.validateAudience(assertion, validateOpts);
    assert.strictEqual(value, false);
    assert.strictEqual(saml20.validateAudience(assertion, validateOpts), false);
  });

  it('validateAudience assertion  not ok', function () {
    try {
      const value = saml20.validateAudience('assertion', validateOpts);
      assert.strictEqual(value, false);
    } catch (error) {
      assert(error);
    }
  });

  it('validateAudience empty Array not ok', function () {
    try {
      const value = saml20.validateAudience(assertion, []);
      assert.strictEqual(value, false);
    } catch (error) {
      assert(error);
    }
  });

  it('validateAudience empty Array ok', function () {
    try {
      const value = saml20.validateAudience(assertion, validateOptsArray);
      assert.strictEqual(value, false);
    } catch (error) {
      assert(error);
    }
  });

  it('validateAudience with Suffix ok', async function () {
    try {
      const value = saml20.validateAudience(assertion1, 'https://saml.boxyhq.com');
      assert.strictEqual(value, true);
    } catch (error) {
      assert(error);
    }
  });

  it('validateAudience with Suffix Array ok', async function () {
    try {
      const value = saml20.validateAudience(assertion1, [...validateOptsArray, 'https://saml.boxyhq.com']);
      assert.strictEqual(value, true);
    } catch (error) {
      assert(error);
    }
  });

  it('validateAudience with Suffix Array not ok', async function () {
    try {
      const value = saml20.validateAudience(assertion1, validateOptsArray);
      assert.strictEqual(value, false);
    } catch (error) {
      assert(error);
    }
  });

  it('validateAudience not ok', function () {
    try {
      const value = saml20.validateAudience('assertion', 'validateOpts');
      assert.strictEqual(value, false);
    } catch (error) {
      assert(error);
    }
  });

  it('validateExpiration ok', function () {
    const value = saml20.validateExpiration(assertion);
    assert.strictEqual(value, true);
    assert(saml20.validateExpiration(assertion));
  });

  it('validateExpiration not ok', function () {
    try {
      const value = saml20.validateExpiration('assertion');
      assert.strictEqual(value, true);
    } catch (error) {
      assert(error);
    }
  });
  it('getClaims with friendly names', function () {
    const attributes = [
      {
        '@': { Name: 'name', FriendlyName: 'email' },
        AttributeValue: { _: 'test@example.com' },
      },
      {
        '@': { Name: 'givenName', FriendlyName: 'givenName' },
        AttributeValue: { _: 'John' },
      },
      {
        '@': { Name: 'surname', FriendlyName: 'sn' },
        AttributeValue: { _: 'Doe' },
      },
    ];

    const assertionWithFriendlyNames = {
      AttributeStatement: {
        Attribute: attributes,
      },
    };

    const result = saml20.parse(assertionWithFriendlyNames);
    const claims = result.claims as any;
    assert.strictEqual(
      claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],
      'test@example.com'
    );
    assert.strictEqual(claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'], 'John');
    assert.strictEqual(claims['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'], 'Doe');
  });
});
