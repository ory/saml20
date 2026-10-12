import assert from 'assert';
import * as version from '../../lib/getVersion';
import { parse } from '../../lib/response';

describe('getVersion.ts', function () {
  it('getVersion not ok', function () {
    assert.strictEqual(version.getVersion(undefined), null);
  });

  it('getVersion not 2.0', function () {
    assert.strictEqual(version.getVersion({ '@': { Version: '1.1' } }), null);
  });
});

describe('getVersion without attributes', function () {
  it('returns null for an assertion that has no attributes', function () {
    assert.strictEqual(version.getVersion({ Issuer: 'https://idp' }), null);
  });
});

describe('parse() with an Assertion that has no Version', function () {
  it('rejects with "version not supported" instead of hanging', async function () {
    const response =
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
      'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">' +
      '<saml:Assertion><saml:Issuer>https://idp</saml:Issuer></saml:Assertion></samlp:Response>';
    await assert.rejects(parse(response), { message: 'SAML Assertion version not supported.' });
  });
});
