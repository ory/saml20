import assert from 'assert';
import fs from 'fs';
import { sign } from '../../lib/sign';
import { validate } from '../../lib/response';
import saml20 from '../../lib/saml20';

// Regression tests for the SP-initiated assertion-injection / InResponseTo
// replay-binding bypass and the validateExpiration NaN defect.
//
// Threat model: an attacker captures one validly signed (assertion-only-signed)
// victim assertion and replays it into their own freshly started SP-initiated
// login, where the caller enforces inResponseTo = attackerSessionId. The outer
// <Response> wrapper is unsigned, so the attacker can edit it freely.

const privateKey = fs.readFileSync('./test/assets/certificates/testIdpKey.pem').toString();
const cert = fs.readFileSync('./test/assets/certificates/testIdpCert.crt').toString();

const AUDIENCE = 'https://sp.jackson.example/saml';
const VICTIM_REQ_ID = 'ORIGINAL_IDP_REQUEST_ID';
const ATTACKER_SESSION_ID = '_attacker_fresh_session';
const NAME_ID_CLAIM = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier';

interface BuildOpts {
  // Include InResponseTo on the outer <Response> wrapper (unsigned).
  responseInResponseTo?: string | null;
  // Include InResponseTo inside the signed bearer SubjectConfirmationData.
  subjectInResponseTo?: string | null;
  // Emit a Conditions validity window.
  withConditionsWindow?: boolean;
  // Emit NotOnOrAfter on the bearer SubjectConfirmationData.
  withSubjectNotOnOrAfter?: boolean;
  // Override the bearer SubjectConfirmationData NotOnOrAfter with an explicit
  // (signed) value, e.g. to build a lapsed bearer window.
  subjectNotOnOrAfter?: string;
}

// Build an assertion-only-signed SAML Response. Only the <Assertion> is signed,
// which is the SAML default and what most IdPs emit.
function buildAssertionOnlySigned({
  responseInResponseTo = VICTIM_REQ_ID,
  subjectInResponseTo = null,
  withConditionsWindow = true,
  withSubjectNotOnOrAfter = true,
  subjectNotOnOrAfter,
}: BuildOpts = {}): string {
  const now = new Date();
  const past = new Date(now.getTime() - 3600_000).toISOString();
  const future = new Date(now.getTime() + 3600_000).toISOString();
  const t = now.toISOString();

  const responseIrtAttr = responseInResponseTo ? ` InResponseTo="${responseInResponseTo}"` : '';
  const subjectIrtAttr = subjectInResponseTo ? ` InResponseTo="${subjectInResponseTo}"` : '';
  const bearerNotOnOrAfter = subjectNotOnOrAfter ?? (withSubjectNotOnOrAfter ? future : undefined);
  const subjectNotOnOrAfterAttr = bearerNotOnOrAfter ? ` NotOnOrAfter="${bearerNotOnOrAfter}"` : '';
  const conditions = withConditionsWindow
    ? `<saml:Conditions NotBefore="${past}" NotOnOrAfter="${future}"><saml:AudienceRestriction><saml:Audience>${AUDIENCE}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
    : `<saml:Conditions><saml:AudienceRestriction><saml:Audience>${AUDIENCE}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`;

  const xml =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="${t}"${responseIrtAttr} Destination="${AUDIENCE}">` +
    `<saml:Issuer>https://idp</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    `<saml:Assertion ID="_assert1" Version="2.0" IssueInstant="${t}">` +
    `<saml:Issuer>https://idp</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">victim@target.com</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${subjectIrtAttr}${subjectNotOnOrAfterAttr} Recipient="${AUDIENCE}"/></saml:SubjectConfirmation></saml:Subject>` +
    conditions +
    `<saml:AuthnStatement AuthnInstant="${t}" SessionIndex="_idx1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `<saml:AttributeStatement><saml:Attribute Name="email" FriendlyName="email"><saml:AttributeValue>victim@target.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` +
    `</saml:Assertion>` +
    `</samlp:Response>`;

  return sign(xml, privateKey, cert, '//*[local-name(.)="Assertion"]');
}

function stripResponseInResponseTo(xml: string): string {
  return xml.replace(new RegExp(`(<samlp:Response[^>]*?) InResponseTo="${VICTIM_REQ_ID}"`), '$1');
}

async function expectReject(xml: string, message: string, opts: Record<string, any>) {
  await assert.rejects(
    () => validate(xml, { audience: AUDIENCE, publicKey: cert, ...opts }),
    (err: Error) => {
      assert.strictEqual(err.message, message);
      return true;
    }
  );
}

describe('saml20.attacks: InResponseTo replay binding (SP-initiated)', () => {
  it('rejects an unchanged captured assertion replayed into a different session (negative control)', async () => {
    const signed = buildAssertionOnlySigned({ subjectInResponseTo: VICTIM_REQ_ID });
    await expectReject(signed, 'Invalid InResponseTo.', { inResponseTo: ATTACKER_SESSION_ID });
  });

  it('rejects when the outer <Response> InResponseTo is stripped and no signed InResponseTo is present', async () => {
    // PoC: InResponseTo lived only on the unsigned wrapper. Stripping it must
    // not silently skip the binding check.
    const signed = buildAssertionOnlySigned({ subjectInResponseTo: null });
    await expectReject(stripResponseInResponseTo(signed), 'Invalid InResponseTo.', {
      inResponseTo: ATTACKER_SESSION_ID,
    });
  });

  it('rejects when the outer InResponseTo is stripped but the signed assertion binds to the victim request', async () => {
    // The signed SubjectConfirmationData still names the victim's request id,
    // which does not match the attacker's session.
    const signed = buildAssertionOnlySigned({ subjectInResponseTo: VICTIM_REQ_ID });
    await expectReject(stripResponseInResponseTo(signed), 'Invalid InResponseTo.', {
      inResponseTo: ATTACKER_SESSION_ID,
    });
  });

  it('accepts a legitimate SP-initiated login bound via the signed SubjectConfirmationData', async () => {
    // Outer wrapper carries no InResponseTo; the trustworthy value lives in the
    // signed assertion and matches the caller-supplied request id.
    const signed = buildAssertionOnlySigned({
      responseInResponseTo: null,
      subjectInResponseTo: VICTIM_REQ_ID,
    });
    const profile = await validate(signed, {
      audience: AUDIENCE,
      publicKey: cert,
      inResponseTo: VICTIM_REQ_ID,
    });
    assert.strictEqual(profile.claims[NAME_ID_CLAIM], 'victim@target.com');
  });

  it('does not enforce binding for IdP-initiated logins (no inResponseTo supplied)', async () => {
    const signed = buildAssertionOnlySigned({ responseInResponseTo: null, subjectInResponseTo: null });
    const profile = await validate(signed, { audience: AUDIENCE, publicKey: cert });
    assert.strictEqual(profile.claims[NAME_ID_CLAIM], 'victim@target.com');
  });
});

describe('saml20: one-time assertion replay protection', () => {
  it('rejects a second use of the same assertion when a replay validator is supplied', async () => {
    const signed = buildAssertionOnlySigned({ subjectInResponseTo: VICTIM_REQ_ID });
    const seen = new Set<string>();
    const assertionReplayValidator = async ({ assertionId }: { assertionId?: string }) => {
      if (!assertionId) return false;
      if (seen.has(assertionId)) return true;
      seen.add(assertionId);
      return false;
    };

    const opts = {
      audience: AUDIENCE,
      publicKey: cert,
      inResponseTo: VICTIM_REQ_ID,
      assertionReplayValidator,
    };

    const profile = await validate(signed, opts);
    assert.strictEqual(profile.assertionId, '_assert1');

    await assert.rejects(
      () => validate(signed, opts),
      (err: Error) => {
        assert.strictEqual(err.message, 'Assertion has already been used (replay detected).');
        return true;
      }
    );
  });

  it('passes the Conditions NotOnOrAfter to the replay validator for TTL sizing', async () => {
    const signed = buildAssertionOnlySigned({
      subjectInResponseTo: VICTIM_REQ_ID,
      withConditionsWindow: true,
    });
    let captured: { assertionId?: string; notOnOrAfter?: string } | undefined;
    const profile = await validate(signed, {
      audience: AUDIENCE,
      publicKey: cert,
      inResponseTo: VICTIM_REQ_ID,
      assertionReplayValidator: async (info: { assertionId?: string; notOnOrAfter?: string }) => {
        captured = info;
        return false;
      },
    });
    assert.ok(captured, 'replay validator was called');
    assert.strictEqual(captured!.assertionId, '_assert1');
    assert.ok(captured!.notOnOrAfter, 'notOnOrAfter is provided');
    assert.strictEqual(captured!.notOnOrAfter, profile.notOnOrAfter);
    assert.ok(new Date(captured!.notOnOrAfter!).getTime() > Date.now());
  });

  it('falls back to SubjectConfirmationData NotOnOrAfter when there is no Conditions window', async () => {
    // The assertion is bearer-bounded only; the replay validator must still get
    // a concrete expiry so it does not have to guess a TTL.
    const signed = buildAssertionOnlySigned({
      responseInResponseTo: null,
      subjectInResponseTo: VICTIM_REQ_ID,
      withConditionsWindow: false,
      withSubjectNotOnOrAfter: true,
    });
    let captured: { notOnOrAfter?: string } | undefined;
    const profile = await validate(signed, {
      audience: AUDIENCE,
      publicKey: cert,
      inResponseTo: VICTIM_REQ_ID,
      assertionReplayValidator: async (info: { notOnOrAfter?: string }) => {
        captured = info;
        return false;
      },
    });
    assert.ok(captured!.notOnOrAfter, 'notOnOrAfter is provided from SubjectConfirmationData');
    assert.strictEqual(captured!.notOnOrAfter, profile.notOnOrAfter);
    assert.ok(new Date(captured!.notOnOrAfter!).getTime() > Date.now());
  });

  it('surfaces errors thrown by the replay validator without leaking a valid profile', async () => {
    const signed = buildAssertionOnlySigned({ subjectInResponseTo: VICTIM_REQ_ID });
    await assert.rejects(
      () =>
        validate(signed, {
          audience: AUDIENCE,
          publicKey: cert,
          inResponseTo: VICTIM_REQ_ID,
          assertionReplayValidator: async () => {
            throw new Error('store unavailable');
          },
        }),
      (err: Error) => {
        assert.strictEqual(err.message, 'An error occurred during assertion replay validation.');
        return true;
      }
    );
  });
});

describe('saml20.validateExpiration: at least one enforceable upper bound required', () => {
  const past = () => new Date(Date.now() - 3600_000).toISOString();
  const future = () => new Date(Date.now() + 3600_000).toISOString();

  it('treats an assertion with no expiration anywhere as expired (was "never expires")', () => {
    assert.strictEqual(saml20.validateExpiration({}), false);
  });

  it('treats a NotBefore-only Conditions (no upper bound) as expired', () => {
    assert.strictEqual(saml20.validateExpiration({ Conditions: { '@': { NotBefore: past() } } }), false);
  });

  it('treats a present-but-unparseable bound as expired', () => {
    assert.strictEqual(
      saml20.validateExpiration({ Conditions: { '@': { NotBefore: past(), NotOnOrAfter: 'not-a-date' } } }),
      false
    );
  });

  it('accepts a current Conditions validity window', () => {
    assert.strictEqual(
      saml20.validateExpiration({ Conditions: { '@': { NotBefore: past(), NotOnOrAfter: future() } } }),
      true
    );
  });

  it('accepts a bearer assertion bounded only by SubjectConfirmationData/@NotOnOrAfter', () => {
    // No Conditions window, but a signed bearer expiration is present. This is a
    // spec-valid bearer assertion and must not be rejected.
    assert.strictEqual(
      saml20.validateExpiration({
        Subject: { SubjectConfirmation: { SubjectConfirmationData: { '@': { NotOnOrAfter: future() } } } },
      }),
      true
    );
  });

  it('accepts when one SubjectConfirmation is stale but another is still valid (alternatives, OR)', () => {
    // SAML 2.0 core 2.4.1.1: multiple SubjectConfirmations are alternatives;
    // satisfying any one is sufficient.
    assert.strictEqual(
      saml20.validateExpiration({
        Subject: {
          SubjectConfirmation: [
            { SubjectConfirmationData: { '@': { NotOnOrAfter: '2000-01-01T00:00:00Z' } } },
            { SubjectConfirmationData: { '@': { NotOnOrAfter: future() } } },
          ],
        },
      }),
      true
    );
  });

  it('rejects when every SubjectConfirmation upper bound is in the past', () => {
    assert.strictEqual(
      saml20.validateExpiration({
        Subject: {
          SubjectConfirmation: [
            { SubjectConfirmationData: { '@': { NotOnOrAfter: '2000-01-01T00:00:00Z' } } },
            { SubjectConfirmationData: { '@': { NotOnOrAfter: '2010-01-01T00:00:00Z' } } },
          ],
        },
      }),
      false
    );
  });

  it('rejects a lapsed bearer confirmation even when Conditions is still valid (profile 4.1.4.3)', () => {
    // The bearer SubjectConfirmationData NotOnOrAfter must be verified
    // independently of Conditions; a still-open Conditions window does not
    // rescue an expired bearer confirmation.
    assert.strictEqual(
      saml20.validateExpiration({
        Conditions: { '@': { NotBefore: past(), NotOnOrAfter: future() } },
        Subject: {
          SubjectConfirmation: { SubjectConfirmationData: { '@': { NotOnOrAfter: '2000-01-01T00:00:00Z' } } },
        },
      }),
      false
    );
  });

  it('accepts when Conditions is valid and at least one bearer confirmation is still valid', () => {
    assert.strictEqual(
      saml20.validateExpiration({
        Conditions: { '@': { NotBefore: past(), NotOnOrAfter: future() } },
        Subject: {
          SubjectConfirmation: [
            { SubjectConfirmationData: { '@': { NotOnOrAfter: '2000-01-01T00:00:00Z' } } },
            { SubjectConfirmationData: { '@': { NotOnOrAfter: future() } } },
          ],
        },
      }),
      true
    );
  });

  it('accepts a bearer login (no Conditions window) end-to-end via validate()', async () => {
    const signed = buildAssertionOnlySigned({
      responseInResponseTo: null,
      subjectInResponseTo: VICTIM_REQ_ID,
      withConditionsWindow: false,
      withSubjectNotOnOrAfter: true,
    });
    const profile = await validate(signed, {
      audience: AUDIENCE,
      publicKey: cert,
      inResponseTo: VICTIM_REQ_ID,
    });
    assert.strictEqual(profile.claims[NAME_ID_CLAIM], 'victim@target.com');
  });

  it('rejects an assertion with no expiration bound anywhere end-to-end via validate()', async () => {
    const signed = buildAssertionOnlySigned({
      subjectInResponseTo: VICTIM_REQ_ID,
      withConditionsWindow: false,
      withSubjectNotOnOrAfter: false,
    });
    await expectReject(signed, 'Assertion is expired.', { inResponseTo: VICTIM_REQ_ID });
  });

  it('rejects a signed lapsed bearer window even when Conditions is still valid end-to-end (profile 4.1.4.3)', async () => {
    // The bearer NotOnOrAfter is inside the signed assertion, so an attacker
    // cannot extend it; a captured assertion whose bearer window closed must be
    // rejected even though its Conditions window remains open.
    const signed = buildAssertionOnlySigned({
      subjectInResponseTo: VICTIM_REQ_ID,
      withConditionsWindow: true,
      subjectNotOnOrAfter: '2000-01-01T00:00:00Z',
    });
    await expectReject(signed, 'Assertion is expired.', { inResponseTo: VICTIM_REQ_ID });
  });
});
