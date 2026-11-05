import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import { request } from '../../lib/request';
import { createSAMLResponse } from '../../lib/response';
import { createLogoutRequest, createLogoutResponse } from '../../lib/logout';
import { createIdPMetadataXML, createSPMetadataXML } from '../../lib/metadata';

// The exact XML each generator writes for a fixed input, with the values that
// change on every call (identifiers, timestamps, signatures) masked. A change
// to the serializer or to a generator has to update the file under
// test/assets/generated deliberately. Set UPDATE_GENERATED=1 to rewrite them.
const dir = path.resolve('./test/assets/generated');
const privateKey = fs.readFileSync('./test/assets/certificates/testIdpKey.pem', 'utf8');
const publicKey = fs.readFileSync('./test/assets/certificates/testIdpCert.crt', 'utf8');

const mask = (xml: string) =>
  xml
    .replace(/<(ds:)?Signature[\s>][\s\S]*?<\/\1Signature>/g, '<$1Signature>…</$1Signature>')
    .replace(/\b(ID|SessionIndex)="_[0-9a-f]+"/g, '$1="_…"')
    .replace(/\b(IssueInstant|NotBefore|NotOnOrAfter|AuthnInstant|validUntil)="[^"]+"/g, '$1="…"');

const generators: Record<string, () => string | Promise<string>> = {
  'authn-request': () =>
    request({
      ssoUrl: 'https://idp.example.com/sso?tenant=1&app=2',
      entityID: 'https://sp.example.com/saml/metadata',
      callbackUrl: 'https://sp.example.com/saml/acs',
      isPassive: true,
      forceAuthn: true,
      providerName: 'Example & Co',
      signingKey: '',
      publicKey: '',
    }).request,
  'authn-request-signed': () =>
    request({
      ssoUrl: 'https://idp.example.com/sso',
      entityID: 'https://sp.example.com/saml/metadata',
      callbackUrl: 'https://sp.example.com/saml/acs',
      signingKey: privateKey,
      publicKey,
    }).request,
  'logout-request': () =>
    createLogoutRequest({
      nameId: 'jackson@example.com',
      nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      nameQualifier: 'https://idp.example.com',
      spNameQualifier: 'https://sp.example.com',
      providerName: 'https://sp.example.com/saml/metadata',
      sloUrl: 'https://idp.example.com/slo',
      sessionIndex: ['_session1', '_session2'],
    }).xml,
  'logout-response': () =>
    createLogoutResponse({
      requestId: '_request',
      issuer: 'https://sp.example.com/saml/metadata',
      destination: 'https://idp.example.com/slo',
    }).xml,
  'idp-metadata': () =>
    createIdPMetadataXML({
      entityId: 'https://idp.example.com/saml/metadata',
      ssoUrl: 'https://idp.example.com/sso',
      sloUrl: 'https://idp.example.com/slo',
      x509cert: 'MIIC…',
      wantAuthnRequestsSigned: true,
    }),
  'sp-metadata': () =>
    createSPMetadataXML({
      entityId: 'https://sp.example.com/saml/metadata',
      publicKeyString: 'MIIC…',
      acsUrl: 'https://sp.example.com/saml/acs',
      encryption: true,
      authnRequestsSigned: true,
    }),
  'saml-response': () =>
    createSAMLResponse({
      audience: 'https://sp.example.com/saml/metadata',
      issuer: 'https://idp.example.com/saml/metadata',
      acsUrl: 'https://sp.example.com/saml/acs?x=1',
      requestId: '_request',
      privateKey,
      publicKey,
      claims: {
        email: 'jackson@example.com',
        raw: {
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': 'jackson@example.com',
          groups: ['admins', 'users'],
          'urn:oid:2.5.4.42': 'Jackson <&> "Boxy"',
          'urn:mace:dir:attribute-def:sn': 'Carriage\rReturn',
        },
      },
    }),
};

describe('generated XML', function () {
  for (const [name, generate] of Object.entries(generators)) {
    it(name, async function () {
      const file = path.join(dir, `${name}.xml`);
      const actual = mask(await generate());
      if (process.env.UPDATE_GENERATED === '1') {
        fs.writeFileSync(file, actual + '\n');
      }
      assert.strictEqual(actual, fs.readFileSync(file, 'utf8').trimEnd());
    });
  }
});
