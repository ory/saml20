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
}

// Build an assertion-only-signed SAML Response. Only the <Assertion> is signed,
// which is the SAML default and what most IdPs emit.
function buildAssertionOnlySigned({
  responseInResponseTo = VICTIM_REQ_ID,
  subjectInResponseTo = null,
  withConditionsWindow = true,
}: BuildOpts = {}): string {
  const now = new Date();
  const past = new Date(now.getTime() - 3600_000).toISOString();
  const future = new Date(now.getTime() + 3600_000).toISOString();
  const t = now.toISOString();

  const responseIrtAttr = responseInResponseTo ? ` InResponseTo="${responseInResponseTo}"` : '';
  const subjectIrtAttr = subjectInResponseTo ? ` InResponseTo="${subjectInResponseTo}"` : '';
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
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${subjectIrtAttr} NotOnOrAfter="${future}" Recipient="${AUDIENCE}"/></saml:SubjectConfirmation></saml:Subject>` +
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

describe('saml20.validateExpiration: bounded validity window required', () => {
  it('treats a missing Conditions window as expired (was "never expires")', () => {
    assert.strictEqual(saml20.validateExpiration({}), false);
  });

  it('treats a missing NotOnOrAfter as expired', () => {
    assert.strictEqual(
      saml20.validateExpiration({ Conditions: { '@': { NotBefore: '2020-01-01T00:00:00Z' } } }),
      false
    );
  });

  it('treats an unparseable date as expired', () => {
    assert.strictEqual(
      saml20.validateExpiration({
        Conditions: { '@': { NotBefore: 'not-a-date', NotOnOrAfter: 'also-bad' } },
      }),
      false
    );
  });

  it('accepts a current, bounded validity window', () => {
    const past = new Date(Date.now() - 3600_000).toISOString();
    const future = new Date(Date.now() + 3600_000).toISOString();
    assert.strictEqual(
      saml20.validateExpiration({ Conditions: { '@': { NotBefore: past, NotOnOrAfter: future } } }),
      true
    );
  });

  it('rejects an assertion whose signed Conditions carry no window during validate()', async () => {
    const signed = buildAssertionOnlySigned({
      subjectInResponseTo: VICTIM_REQ_ID,
      withConditionsWindow: false,
    });
    await expectReject(signed, 'Assertion is expired.', { inResponseTo: VICTIM_REQ_ID });
  });
});
