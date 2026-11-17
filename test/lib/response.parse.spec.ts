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
