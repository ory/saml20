import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import { validate } from '../../lib/response';
import { sign } from '../../lib/sign';
import { decryptXml } from '../../lib/decrypt';
import { verifyRootSignature, verifySignature } from '../../lib/validateSignature';
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

const XMLENC = 'http://www.w3.org/2001/04/xmlenc#';
const ENCRYPTED_KEY = /<e:EncryptedKey[\s\S]*<\/e:EncryptedKey>/;
const unusedKey = (id: string) =>
  `<e:EncryptedKey xmlns:e="${XMLENC}" Id="${id}"><e:EncryptionMethod Algorithm="urn:unused-algorithm"/>` +
  '<e:CipherData><e:CipherValue>AAAA</e:CipherValue></e:CipherData></e:EncryptedKey>';

// The encrypted assertion with an EncryptedKey xml-encryption does not use put first in it.
const withUnusedKeyFirst = (fragment: string) =>
  fragment.replace('<saml:EncryptedAssertion>', `<saml:EncryptedAssertion>${unusedKey('_unused')}`);

// The key moved out of KeyInfo to beside the EncryptedData, where a RetrievalMethod points to it,
// after an unused one.
const withRetrievedKey = (fragment: string) => {
  const key = fragment.match(ENCRYPTED_KEY)![0].replace('<e:EncryptedKey ', '<e:EncryptedKey Id="_used" ');
  return fragment
    .replace(ENCRYPTED_KEY, `<RetrievalMethod Type="${XMLENC}EncryptedKey" URI="#_used"/>`)
    .replace('<saml:EncryptedAssertion>', `<saml:EncryptedAssertion>${unusedKey('_unused')}`)
    .replace('</saml:EncryptedAssertion>', `${key}</saml:EncryptedAssertion>`);
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

  it('reports the key the assertion was decrypted with, not the first one in it', async function () {
    const xml = signXml(buildResponse(withUnusedKeyFirst(await encrypted(buildAssertion()))), RESPONSE_XPATH);
    assert.match(xml, /urn:unused-algorithm/);
    assert.strictEqual((await validate(xml, options())).encryption?.keyTransportAlgorithm, RSA_OAEP_MGF1P);
  });

  it('nor a second one inside its KeyInfo', async function () {
    const fragment = (await encrypted(buildAssertion())).replace(
      '</e:EncryptedKey>',
      `</e:EncryptedKey>${unusedKey('_unused')}`
    );
    const xml = signXml(buildResponse(fragment), RESPONSE_XPATH);
    assert.strictEqual((await validate(xml, options())).encryption?.keyTransportAlgorithm, RSA_OAEP_MGF1P);
  });

  it('follows a RetrievalMethod to the key it names', async function () {
    const xml = signXml(buildResponse(withRetrievedKey(await encrypted(buildAssertion()))), RESPONSE_XPATH);
    assert.match(xml, /<RetrievalMethod/);
    assert.deepStrictEqual((await validate(xml, options())).encryption, {
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

  it('describes the assertion that validated: one from a signed nested response', async function () {
    const nested = signXml(
      buildResponse(
        await encryptAssertion(
          buildAssertion({ id: '_nested' }),
          'http://www.w3.org/2009/xmlenc11#aes256-gcm'
        )
      ).replace('ID="_response-1"', 'ID="_response-nested"'),
      RESPONSE_XPATH
    ).replace(/^<\?xml[^>]*>/, '');
    const outer = buildResponse(await encrypted(buildAssertion({ id: '_outer' })));
    const profile = await validate(
      outer.replace('</samlp:Response>', `${nested}</samlp:Response>`),
      options()
    );
    assert.strictEqual(profile.assertionId, '_nested');
    assert.deepStrictEqual(profile.encryption, {
      dataAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyTransportAlgorithm: RSA_OAEP_MGF1P,
      signaturePlacement: 'response',
    });
  });

  it('is not reported when the assertion that validated was in plaintext beside an encrypted one', async function () {
    const both = buildResponse(
      signXml(buildAssertion({ id: '_plain' }), ASSERTION_XPATH).replace(/^<\?xml[^>]*>/, '') +
        (await encrypted(buildAssertion({ id: '_encrypted' })))
    );
    for (const xml of [both, signXml(both, RESPONSE_XPATH)]) {
      const profile = await validate(xml, options());
      assert.strictEqual(profile.assertionId, '_plain');
      assert.strictEqual(profile.encryption, undefined);
    }
  });

  it("verifyRootSignature checks the root element's signature, whichever other one comes first", function () {
    const xml = signXml(buildResponse(signedAssertion()), RESPONSE_XPATH);
    assert.match(verifySignature(xml, testIdpCert, undefined)!, /^<saml:Assertion/);
    assert.match(verifyRootSignature(xml, testIdpCert, undefined)!, /^<samlp:Response/);
    assert.throws(
      () => verifyRootSignature(buildResponse(signedAssertion()), testIdpCert, undefined),
      /no Signature/
    );
  });

  it('handles an element with more children than a function call takes arguments', async function () {
    const wide = `<samlp:Extensions>${'<x/>'.repeat(130_000)}</samlp:Extensions>`;
    const xml = buildResponse(await encrypted(buildAssertion())).replace(
      '<samlp:Status>',
      `${wide}<samlp:Status>`
    );
    const { encrypted: report } = decryptXml(xml, { privateKey: testIdpKey, reportEncryption: true });
    assert.deepStrictEqual(report, {
      dataAlgorithm: AES128_CBC,
      keyTransportAlgorithm: RSA_OAEP_MGF1P,
      responseId: '_response-1',
      responseSigned: false,
      assertionCount: 1,
    });
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
