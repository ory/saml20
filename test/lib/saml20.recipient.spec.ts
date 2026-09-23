import assert from 'assert';
import fs from 'fs';
import { sign } from '../../lib/sign';
import { validate } from '../../lib/response';

// The `recipient` option binds an assertion to the ACS URL it was posted to.
//
// Threat model: several SP endpoints trust the same IdP signing key and accept
// the same audience (for example several SAML apps of one Google Workspace
// behind one SP). An attacker takes an assertion issued for endpoint A and
// posts it to endpoint B. Only signed content may decide where the assertion
// was addressed; the outer <Response> wrapper is unsigned in the common
// assertion-only-signed case and can be edited freely.

const privateKey = fs.readFileSync('./test/assets/certificates/testIdpKey.pem').toString();
const cert = fs.readFileSync('./test/assets/certificates/testIdpCert.crt').toString();

const AUDIENCE = 'https://sp.jackson.example/saml';
const ACS_A = 'https://sp.jackson.example/api/oauth/saml/provider-a';
const ACS_B = 'https://sp.jackson.example/api/oauth/saml/provider-b';

interface Confirmation {
  // Recipient attribute; null omits it.
  recipient: string | null;
  // NotOnOrAfter on this confirmation: 'valid' (default), 'expired' (beyond
  // clock skew) or 'none' to omit it.
  window?: 'valid' | 'expired' | 'none';
  // SubjectConfirmation Method; bearer by default.
  method?: string;
}

interface BuildOpts {
  // Response/@Destination; null omits it.
  destination?: string | null;
  // One entry per SubjectConfirmation. A bare string or null is a bearer
  // confirmation with a valid window.
  recipients?: (string | null | Confirmation)[];
  // Sign the whole Response instead of only the Assertion.
  signResponse?: boolean;
}

const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const HOLDER_OF_KEY = 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key';

function build({ destination = ACS_A, recipients = [ACS_A], signResponse = false }: BuildOpts = {}): string {
  const now = new Date();
  const past = new Date(now.getTime() - 3600_000).toISOString();
  const future = new Date(now.getTime() + 3600_000).toISOString();
  const t = now.toISOString();

  const destinationAttr = destination ? ` Destination="${destination}"` : '';
  const expired = new Date(now.getTime() - 3 * 3600_000).toISOString();
  const confirmations = recipients
    .map((entry) => {
      const c: Confirmation = entry === null || typeof entry === 'string' ? { recipient: entry } : entry;
      const recipientAttr = c.recipient !== null ? ` Recipient="${c.recipient}"` : '';
      const window = c.window ?? 'valid';
      const notOnOrAfterAttr =
        window === 'none' ? '' : ` NotOnOrAfter="${window === 'expired' ? expired : future}"`;
      return `<saml:SubjectConfirmation Method="${c.method ?? BEARER}"><saml:SubjectConfirmationData${notOnOrAfterAttr}${recipientAttr}/></saml:SubjectConfirmation>`;
    })
    .join('');

  const xml =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="${t}"${destinationAttr}>` +
    `<saml:Issuer>https://idp</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    `<saml:Assertion ID="_assert1" Version="2.0" IssueInstant="${t}">` +
    `<saml:Issuer>https://idp</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>` +
    confirmations +
    `</saml:Subject>` +
    `<saml:Conditions NotBefore="${past}" NotOnOrAfter="${future}"><saml:AudienceRestriction><saml:Audience>${AUDIENCE}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${t}" SessionIndex="_idx1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    `</saml:Assertion>` +
    `</samlp:Response>`;

  const xpath = signResponse ? '/*[local-name(.)="Response"]' : '//*[local-name(.)="Assertion"]';
  return sign(xml, privateKey, cert, xpath);
}

async function expectInvalidRecipient(xml: string, recipient: string) {
  await assert.rejects(
    () => validate(xml, { audience: AUDIENCE, publicKey: cert, recipient }),
    (err: Error) => {
      assert.strictEqual(err.message, 'Invalid Recipient.');
      return true;
    }
  );
}

async function expectAccepted(xml: string, recipient?: string, extra: Record<string, unknown> = {}) {
  const profile = await validate(xml, { audience: AUDIENCE, publicKey: cert, recipient, ...extra });
  assert.strictEqual(profile.issuer, 'https://idp');
}

describe('saml20: recipient binding', () => {
  describe('assertion-only signed', () => {
    it('accepts an assertion whose signed Recipient matches', async () => {
      await expectAccepted(build(), ACS_A);
    });

    it('rejects an assertion issued for another ACS URL', async () => {
      await expectInvalidRecipient(build(), ACS_B);
    });

    it('ignores an edited unsigned Destination', async () => {
      // Rewriting the wrapper to point at B must not make the assertion valid
      // at B: the signed Recipient still names A.
      const signed = build().replace(`Destination="${ACS_A}"`, `Destination="${ACS_B}"`);
      await expectInvalidRecipient(signed, ACS_B);
    });

    it('does not accept an unsigned Destination alone', async () => {
      // No signed Recipient, and the wrapper is unsigned, so nothing signed
      // names the endpoint.
      await expectInvalidRecipient(build({ destination: ACS_A, recipients: [null] }), ACS_A);
    });

    it('rejects when no signed content names an endpoint', async () => {
      await expectInvalidRecipient(build({ destination: null, recipients: [null] }), ACS_A);
    });

    it('accepts when any one of several bearer confirmations matches', async () => {
      await expectAccepted(build({ recipients: [ACS_B, ACS_A] }), ACS_A);
    });

    it('matches exactly, without normalizing', async () => {
      await expectInvalidRecipient(build(), `${ACS_A}/`);
    });

    it('rejects a matching Recipient whose own window lapsed while another confirmation is valid', async () => {
      // The expiry check is satisfied by B and the Recipient by A, but no single
      // bearer confirmation satisfies both.
      const signed = build({
        recipients: [
          { recipient: ACS_A, window: 'expired' },
          { recipient: ACS_B, window: 'valid' },
        ],
      });
      await expectInvalidRecipient(signed, ACS_A);
    });

    it('rejects a matching Recipient on a confirmation without NotOnOrAfter', async () => {
      const signed = build({
        recipients: [
          { recipient: ACS_A, window: 'none' },
          { recipient: ACS_B, window: 'valid' },
        ],
      });
      await expectInvalidRecipient(signed, ACS_A);
    });

    it('accepts when the matching confirmation is valid and another one lapsed', async () => {
      const signed = build({
        recipients: [
          { recipient: ACS_B, window: 'expired' },
          { recipient: ACS_A, window: 'valid' },
        ],
      });
      await expectAccepted(signed, ACS_A);
    });

    it('ignores the Recipient of a non-bearer confirmation', async () => {
      const signed = build({
        recipients: [
          { recipient: ACS_A, method: HOLDER_OF_KEY },
          { recipient: ACS_B, window: 'valid' },
        ],
      });
      await expectInvalidRecipient(signed, ACS_A);
    });
  });

  describe('whole Response signed', () => {
    it('accepts when the signed Destination and Recipient match', async () => {
      await expectAccepted(build({ signResponse: true }), ACS_A);
    });

    it('accepts a signed Destination when no Recipient is present', async () => {
      await expectAccepted(build({ signResponse: true, recipients: [null] }), ACS_A);
    });

    it('rejects a signed Destination for another ACS URL even if a Recipient matches', async () => {
      await expectInvalidRecipient(
        build({ signResponse: true, destination: ACS_B, recipients: [ACS_A] }),
        ACS_A
      );
    });

    it('rejects a signed Recipient for another ACS URL even if the Destination matches', async () => {
      await expectInvalidRecipient(
        build({ signResponse: true, destination: ACS_A, recipients: [ACS_B] }),
        ACS_A
      );
    });
  });

  describe('edge cases', () => {
    it('rejects an empty Recipient even when the signed Destination matches', async () => {
      // An empty attribute is present, not absent: it must not fall back to
      // the Destination.
      await expectInvalidRecipient(build({ signResponse: true, recipients: [''] }), ACS_A);
    });

    it('bypassExpiration skips the confirmation window but still requires the Recipient', async () => {
      const lapsed = build({ recipients: [{ recipient: ACS_A, window: 'expired' }] });
      // Without the bypass the expiry check rejects it first.
      await assert.rejects(
        () => validate(lapsed, { audience: AUDIENCE, publicKey: cert, recipient: ACS_A }),
        (err: Error) => {
          assert.strictEqual(err.message, 'Assertion is expired.');
          return true;
        }
      );
      // With it, the lapsed window no longer fails the recipient check either.
      await expectAccepted(lapsed, ACS_A, { bypassExpiration: true });
      await assert.rejects(
        () =>
          validate(lapsed, { audience: AUDIENCE, publicKey: cert, recipient: ACS_B, bypassExpiration: true }),
        (err: Error) => {
          assert.strictEqual(err.message, 'Invalid Recipient.');
          return true;
        }
      );
    });
  });

  it('does not check anything when no recipient is supplied', async () => {
    await expectAccepted(build({ destination: ACS_B, recipients: [ACS_B] }));
  });
});
