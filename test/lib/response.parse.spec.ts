import { describe, it, before } from 'node:test';
import assert from 'node:assert';
import { DOMParser } from '@xmldom/xmldom';
import { parseIssuer, parseResponse, validate } from '../../lib/response';
import {
  ACS,
  ASSERTION_XPATH,
  IDP,
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

const options = (extra: Record<string, unknown> = {}) => ({
  publicKey: testIdpCert,
  audience: SP,
  inResponseTo: REQUEST_ID,
  recipient: ACS,
  ...extra,
});

describe('parseResponse()', function () {
  let signed: string;
  let encrypted: string;

  before(async function () {
    signed = buildResponse(signXml(buildAssertion(), ASSERTION_XPATH));
    encrypted = signXml(buildResponse(await encryptAssertion(buildAssertion())), RESPONSE_XPATH);
  });

  it('reads the issuer as parseIssuer does', function () {
    assert.strictEqual(parseResponse(signed).issuer, parseIssuer(signed));
    assert.strictEqual(parseResponse(signed).issuer, IDP);
  });

  it('is validated to the same profile as the raw response', async function () {
    assert.deepStrictEqual(
      await validate(parseResponse(signed), options()),
      await validate(signed, options())
    );
  });

  it('saves validate() the parse parseIssuer made', async function (t) {
    const parses = t.mock.method(DOMParser.prototype, 'parseFromString');

    parseIssuer(signed);
    await validate(signed, options());
    const separately = parses.mock.callCount();

    parses.mock.resetCalls();
    await validate(parseResponse(signed), options());

    assert.strictEqual(parses.mock.callCount(), separately - 1);
  });

  it('can be validated more than once when the assertion is encrypted', async function () {
    const parsed = parseResponse(encrypted);
    const decrypting = options({ privateKey: testIdpKey });

    const first = await validate(parsed, decrypting);
    assert.deepStrictEqual(await validate(parsed, decrypting), first);
    assert.strictEqual(first.issuer, IDP);
  });

  it('cannot be changed', function () {
    assert.ok(Object.isFrozen(parseResponse(signed)));
  });
});

describe('validate() parses', function () {
  // How many times each distinct string was parsed while validating.
  const parsesDuring = async (
    t: { mock: { method: typeof import('node:test').mock.method } },
    run: () => Promise<unknown>
  ) => {
    const original = DOMParser.prototype.parseFromString;
    const counts = new Map<string, number>();
    t.mock.method(
      DOMParser.prototype,
      'parseFromString',
      function (this: DOMParser, xml: string, mime: string) {
        counts.set(xml, (counts.get(xml) ?? 0) + 1);
        return original.call(this, xml, mime as never);
      }
    );
    await run();
    return counts;
  };

  it('the signed content once when it holds no encrypted assertion', async function (t) {
    const assertion = signXml(buildAssertion(), ASSERTION_XPATH);
    const counts = await parsesDuring(t, () => validate(buildResponse(assertion), options()));

    const signedContent = [...counts.keys()].filter((xml) => xml.startsWith('<saml:Assertion'));
    assert.deepStrictEqual(
      signedContent.map((xml) => counts.get(xml)),
      [1]
    );
  });

  it('the response for its status without building objects from it', async function (t) {
    const response = buildResponse(signXml(buildAssertion(), ASSERTION_XPATH));
    const counts = await parsesDuring(t, () => validate(response, options()));

    assert.ok((counts.get(response) ?? 0) <= 2, `parsed ${counts.get(response)} times`);
  });

  it('still rejects a bare ampersand outside the signed content', async function () {
    const response = buildResponse(signXml(buildAssertion(), ASSERTION_XPATH)).replace(
      '</samlp:Response>',
      '<samlp:Extensions>a & b</samlp:Extensions></samlp:Response>'
    );

    await assert.rejects(validate(response, options()), {
      message: 'An error occurred trying to parse XML assertion.',
    });
  });

  it('still reads the status of a response that is not a success', async function () {
    const response = buildResponse(
      signXml(buildAssertion(), ASSERTION_XPATH),
      'urn:oasis:names:tc:SAML:2.0:status:Requester'
    );

    await assert.rejects(validate(response, options()), { message: 'Invalid Status Code (Requester).' });
  });
});
