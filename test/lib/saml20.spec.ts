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

  it('validateAudience accepts the exact audience', function () {
    const value = saml20.validateAudience(
      assertion1,
      'https://saml.boxyhq.com/f46e93394c5a51d36715d95d910872ac7372d4d9'
    );
    assert.strictEqual(value, true);
  });

  it('validateAudience rejects an expected audience that is only a prefix', function () {
    assert.strictEqual(saml20.validateAudience(assertion1, 'https://saml.boxyhq.com'), false);
  });

  it('validateAudience accepts the exact audience in a list', function () {
    const value = saml20.validateAudience(assertion1, [
      ...validateOptsArray,
      'https://saml.boxyhq.com/f46e93394c5a51d36715d95d910872ac7372d4d9',
    ]);
    assert.strictEqual(value, true);
  });

  it('validateAudience rejects a prefix in a list', function () {
    const value = saml20.validateAudience(assertion1, [...validateOptsArray, 'https://saml.boxyhq.com']);
    assert.strictEqual(value, false);
  });

  it('validateAudience rejects a list without the audience', function () {
    assert.strictEqual(saml20.validateAudience(assertion1, validateOptsArray), false);
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
    // A parsed assertion with a current, bounded validity window is valid.
    const assertionWithWindow = {
      Conditions: {
        '@': {
          NotBefore: new Date(Date.now() - 3600_000).toISOString(),
          NotOnOrAfter: new Date(Date.now() + 3600_000).toISOString(),
        },
      },
    };
    assert.strictEqual(saml20.validateExpiration(assertionWithWindow), true);
  });

  it('validateExpiration not ok', function () {
    // A missing validity window must be treated as invalid (expired), not as
    // "never expires".
    assert.strictEqual(saml20.validateExpiration('assertion'), false);
    assert.strictEqual(saml20.validateExpiration({}), false);
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

describe('validateAudience with several Audience values', function () {
  const sp = 'https://sp.example.com/metadata';
  const withAudiences = (...restrictions: unknown[]) => ({
    Conditions: { AudienceRestriction: restrictions },
  });

  it('accepts when any Audience in an AudienceRestriction matches', function () {
    const assertion = {
      Conditions: { AudienceRestriction: { Audience: [{ _: 'https://other' }, { _: sp }] } },
    };
    assert.strictEqual(saml20.validateAudience(assertion, sp), true);
  });

  it('accepts several plain-string Audience values', function () {
    const assertion = { Conditions: { AudienceRestriction: { Audience: ['https://other', sp] } } };
    assert.strictEqual(saml20.validateAudience(assertion, sp), true);
  });

  it('rejects when no Audience in the AudienceRestriction matches', function () {
    const assertion = { Conditions: { AudienceRestriction: { Audience: ['https://a', 'https://b'] } } };
    assert.strictEqual(saml20.validateAudience(assertion, sp), false);
  });

  it('requires every AudienceRestriction to be satisfied', function () {
    assert.strictEqual(
      saml20.validateAudience(withAudiences({ Audience: sp }, { Audience: ['https://x', sp] }), sp),
      true
    );
    assert.strictEqual(
      saml20.validateAudience(withAudiences({ Audience: sp }, { Audience: 'https://x' }), sp),
      false
    );
  });

  it('matches against any of several expected audiences', function () {
    const assertion = { Conditions: { AudienceRestriction: { Audience: ['https://a', sp] } } };
    assert.strictEqual(saml20.validateAudience(assertion, ['https://z', sp]), true);
    assert.strictEqual(saml20.validateAudience(assertion, ['https://z']), false);
  });

  it('rejects an AudienceRestriction with no Audience', function () {
    assert.strictEqual(saml20.validateAudience(withAudiences({}), sp), false);
  });
});

describe('saml20 time windows, recipients and expiry edges', function () {
  const minutes = (n: number) => new Date(Date.now() + n * 60 * 1000).toISOString();
  const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
  const ACS = 'https://sp.example.com/acs';

  describe('validateExpiration', function () {
    it('rejects an unparseable Conditions NotBefore', function () {
      assert.strictEqual(
        saml20.validateExpiration({
          Conditions: { '@': { NotBefore: 'not-a-date', NotOnOrAfter: minutes(10) } },
        }),
        false
      );
    });

    it('rejects a Conditions NotBefore beyond the clock-skew allowance', function () {
      assert.strictEqual(
        saml20.validateExpiration({
          Conditions: { '@': { NotBefore: minutes(11), NotOnOrAfter: minutes(30) } },
        }),
        false
      );
    });

    it('accepts a Conditions NotBefore within the clock-skew allowance', function () {
      assert.strictEqual(
        saml20.validateExpiration({
          Conditions: { '@': { NotBefore: minutes(9), NotOnOrAfter: minutes(30) } },
        }),
        true
      );
    });

    it('rejects when the only bearer window has not started yet', function () {
      assert.strictEqual(
        saml20.validateExpiration({
          Subject: {
            SubjectConfirmation: {
              '@': { Method: BEARER },
              SubjectConfirmationData: { '@': { NotBefore: minutes(11), NotOnOrAfter: minutes(30) } },
            },
          },
        }),
        false
      );
    });
  });

  describe('validateRecipient', function () {
    it('relies on a signed Destination when there is no SubjectConfirmation', function () {
      assert.strictEqual(saml20.validateRecipient({}, ACS, ACS), true);
      assert.strictEqual(saml20.validateRecipient({}, undefined, ACS), false);
      assert.strictEqual(saml20.validateRecipient({}, 'https://other/acs', ACS), false);
    });

    it('ignores the Recipient of a non-bearer confirmation', function () {
      const assertion = {
        Subject: {
          SubjectConfirmation: {
            '@': { Method: 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key' },
            SubjectConfirmationData: { '@': { Recipient: ACS, NotOnOrAfter: minutes(10) } },
          },
        },
      };
      assert.strictEqual(saml20.validateRecipient(assertion, undefined, ACS), false);
      assert.strictEqual(saml20.validateRecipient(assertion, ACS, ACS), true);
    });

    it('skips a bearer confirmation without SubjectConfirmationData', function () {
      const assertion = {
        Subject: {
          SubjectConfirmation: [
            { '@': { Method: BEARER } },
            {
              '@': { Method: BEARER },
              SubjectConfirmationData: { '@': { Recipient: ACS, NotOnOrAfter: minutes(10) } },
            },
          ],
        },
      };
      assert.strictEqual(saml20.validateRecipient(assertion, undefined, ACS), true);
    });
  });

  describe('getNotOnOrAfter', function () {
    it('ignores SubjectConfirmationData without a NotOnOrAfter', function () {
      const conditionsBound = minutes(5);
      const assertion = {
        Conditions: { '@': { NotOnOrAfter: conditionsBound } },
        Subject: { SubjectConfirmation: { SubjectConfirmationData: { '@': { Recipient: ACS } } } },
      };
      assert.strictEqual(saml20.getNotOnOrAfter(assertion), conditionsBound);
    });

    it('returns the earlier of Conditions and the latest bearer bound', function () {
      const early = minutes(3);
      const middle = minutes(6);
      const late = minutes(9);
      const assertion = {
        Conditions: { '@': { NotOnOrAfter: late } },
        Subject: {
          SubjectConfirmation: [
            { SubjectConfirmationData: { '@': { NotOnOrAfter: early } } },
            { SubjectConfirmationData: { '@': { NotOnOrAfter: middle } } },
          ],
        },
      };
      assert.strictEqual(saml20.getNotOnOrAfter(assertion), middle);
    });

    it('returns undefined when there is no bound at all', function () {
      assert.strictEqual(saml20.getNotOnOrAfter({}), undefined);
    });
  });

  describe('validateAudience', function () {
    it('returns false for an expected audience that is not a string', function () {
      const assertion = { Conditions: { AudienceRestriction: { Audience: 'https://sp' } } };
      assert.strictEqual(saml20.validateAudience(assertion, 42), false);
      assert.strictEqual(saml20.validateAudience(assertion, { url: 'https://sp' }), false);
    });
  });
});

describe('saml20.parse leaves its input untouched', function () {
  it('does not rewrite attribute value arrays in the parsed assertion', function () {
    const assertion = {
      Subject: {
        NameID: {
          _: 'jo@example.com',
          '@': { Format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' },
        },
      },
      AttributeStatement: {
        Attribute: [
          { '@': { Name: 'groups' }, AttributeValue: [{ _: ' admins ' }, { _: 'users' }] },
          { '@': { Name: 'email', FriendlyName: 'email' }, AttributeValue: 'jo@example.com' },
        ],
      },
      Conditions: { AudienceRestriction: { Audience: ['https://a', 'https://b'] } },
    };
    const before = JSON.parse(JSON.stringify(assertion));

    const profile = saml20.parse(assertion);

    assert.deepStrictEqual((profile.claims as Record<string, unknown>).groups, ['admins', 'users']);
    assert.strictEqual(profile.audience, 'https://a');
    assert.deepStrictEqual(profile.audiences, ['https://a', 'https://b']);
    assert.deepStrictEqual(assertion, before);
    // Parsing twice gives the same result.
    assert.deepStrictEqual(saml20.parse(assertion), profile);
  });
});

describe('saml20.parse audience fields', function () {
  const parseWith = (Conditions: unknown) => saml20.parse({ Conditions });
  const sp = 'https://sp.example.com/metadata';

  it('returns a single Audience as a string', function () {
    const profile = parseWith({ AudienceRestriction: { Audience: { _: ` ${sp} ` } } });
    assert.strictEqual(profile.audience, sp);
    assert.deepStrictEqual(profile.audiences, [sp]);
  });

  it('returns the first of several Audience values as audience, never an array', function () {
    const profile = parseWith({ AudienceRestriction: { Audience: ['https://a', sp] } });
    assert.strictEqual(profile.audience, 'https://a');
    assert.deepStrictEqual(profile.audiences, ['https://a', sp]);
  });

  it('reads every AudienceRestriction', function () {
    const profile = parseWith({ AudienceRestriction: [{ Audience: sp }, { Audience: ['https://b', sp] }] });
    assert.strictEqual(profile.audience, sp);
    assert.deepStrictEqual(profile.audiences, [sp, 'https://b', sp]);
  });

  it('has no audience when the assertion names none', function () {
    for (const Conditions of [undefined, {}, { AudienceRestriction: {} }, { AudienceRestriction: '' }]) {
      const profile = parseWith(Conditions);
      assert.strictEqual(profile.audience, undefined);
      assert.deepStrictEqual(profile.audiences, []);
    }
  });
});

describe('saml20.parse nameId', function () {
  it('returns the NameID with its attributes', function () {
    const profile = saml20.parse({
      Subject: {
        NameID: {
          _: 'jo@example.com',
          '@': {
            Format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            NameQualifier: 'https://idp.example.com',
            SPNameQualifier: 'https://sp.example.com',
          },
        },
      },
    });
    assert.deepStrictEqual(profile.nameId, {
      value: 'jo@example.com',
      format: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      nameQualifier: 'https://idp.example.com',
      spNameQualifier: 'https://sp.example.com',
    });
  });

  it('keeps the value exactly as asserted, whitespace included', function () {
    const profile = saml20.parse({ Subject: { NameID: { _: ' jo  doe ', '@': {} } } });
    assert.deepStrictEqual(profile.nameId, { value: ' jo  doe ' });
  });

  it('reads a NameID without attributes', function () {
    assert.deepStrictEqual(saml20.parse({ Subject: { NameID: 'jo' } }).nameId, { value: 'jo' });
  });

  it('is undefined without a NameID', function () {
    assert.strictEqual(saml20.parse({}).nameId, undefined);
    assert.strictEqual(saml20.parse({ Subject: { NameID: { _: '', '@': {} } } }).nameId, undefined);
  });
});
