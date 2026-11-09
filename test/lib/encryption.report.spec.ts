import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import { validate } from '../../lib/response';
import { sign } from '../../lib/sign';
import {
  ACS,
  ASSERTION_XPATH,
  REQUEST_ID,
  RESPONSE_XPATH,
  SP,
  buildAssertion,
  buildResponse,
  encryptAssertion,
  signXml,
  testIdpCert,
  testIdpKey,
} from '../helpers/fixtures';

const AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
const ASSERTION = /<saml:Assertion[\s\S]*<\/saml:Assertion>/;

const otherKey = fs.readFileSync('./test/assets/certificates/oneloginPrivateKey.pem').toString();
const otherCert = fs.readFileSync('./test/assets/certificates/oneloginPublicKey.crt').toString();

const options = (extra: Record<string, unknown> = {}) => ({
  privateKey: testIdpKey,
  publicKey: testIdpCert,
  audience: SP,
  inResponseTo: REQUEST_ID,
  recipient: ACS,
  reportEncryption: true,
  ...extra,
});

const signedAssertion = () => signXml(buildAssertion(), ASSERTION_XPATH).replace(/^<\?xml[^>]*>/, '');

const encrypted = (assertion: string) => encryptAssertion(assertion, AES128_CBC);

// The response is signed over the ciphertext.
const encryptThenSign = async (assertion: string, signer = (xml: string) => signXml(xml, RESPONSE_XPATH)) =>
  signer(buildResponse(await encrypted(assertion)));

// The response is signed over the plaintext assertion, which is encrypted afterwards.
const signThenEncrypt = async (assertion: string) => {
  const signed = signXml(buildResponse(assertion), RESPONSE_XPATH);
  return signed.replace(ASSERTION, await encrypted(signed.match(ASSERTION)![0]));
};

const placement = async (xml: string) => (await validate(xml, options())).encryption?.signaturePlacement;

describe('validate reportEncryption', function () {
  it('reports the algorithms the response names', async function () {
    const profile = await validate(await encryptThenSign(buildAssertion()), options());
    assert.deepStrictEqual(profile.encryption, {
      dataAlgorithm: AES128_CBC,
      keyTransportAlgorithm: RSA_OAEP_MGF1P,
      signaturePlacement: 'response',
    });
  });

  it('a response signed over the ciphertext is "response"', async function () {
    assert.strictEqual(await placement(await encryptThenSign(buildAssertion())), 'response');
  });

  it('so it is with the assertion inside signed too', async function () {
    assert.strictEqual(await placement(await encryptThenSign(signedAssertion())), 'response');
  });

  it('a response signed before its assertion was encrypted is "assertion_only"', async function () {
    assert.strictEqual(await placement(await signThenEncrypt(buildAssertion())), 'assertion_only');
  });

  it('so it is with the assertion inside signed too', async function () {
    assert.strictEqual(await placement(await signThenEncrypt(signedAssertion())), 'assertion_only');
  });

  it('a signed assertion in an unsigned response is "assertion_only"', async function () {
    assert.strictEqual(await placement(buildResponse(await encrypted(signedAssertion()))), 'assertion_only');
  });

  it('a response signature by an untrusted key is "assertion_only"', async function () {
    const xml = await encryptThenSign(signedAssertion(), (xml) =>
      sign(xml, otherKey, otherCert, RESPONSE_XPATH)
    );
    assert.strictEqual(await placement(xml), 'assertion_only');
  });

  it('a comment shaped like a response signature is "assertion_only"', async function () {
    const xml = buildResponse(await encrypted(signedAssertion())).replace(
      '</saml:Issuer>',
      '</saml:Issuer><!--<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>' +
        '<ds:Reference URI="#_response-1"/></ds:SignedInfo></ds:Signature>-->'
    );
    assert.strictEqual(await placement(xml), 'assertion_only');
  });

  it('is not reported unless asked for', async function () {
    const profile = await validate(
      await encryptThenSign(buildAssertion()),
      options({ reportEncryption: undefined })
    );
    assert.strictEqual(profile.encryption, undefined);
  });

  it('is not reported for an assertion that was not encrypted', async function () {
    const profile = await validate(signXml(buildResponse(buildAssertion()), RESPONSE_XPATH), options());
    assert.strictEqual(profile.encryption, undefined);
  });

  it('does not change which responses validate', async function () {
    const xml = (await encryptThenSign(buildAssertion())).replace(/(<saml:Issuer>)/, '$1x');
    await assert.rejects(validate(xml, options()));
    await assert.rejects(validate(xml, options({ reportEncryption: undefined })));
  });
});
