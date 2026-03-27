import assert from 'assert';
import fs from 'fs';
import { parseLogoutResponse, createLogoutRequest, parseLogoutRequest } from '../../lib/logout';

const response = fs.readFileSync('./test/assets/logout-response.xml').toString();
const responseFailed = fs.readFileSync('./test/assets/logout-response-failed.xml').toString();
const responseInvalid = 'invalid_data';

const request = fs.readFileSync('./test/assets/logout-request.xml').toString();
const requestWithIdToken = fs.readFileSync('./test/assets/logout-request-with-idtoken.xml').toString();
const requestInvalid = 'invalid_data';

describe('logout.ts', function () {
  it('response ok', async function () {
    const res = await parseLogoutResponse(response);
    assert.strictEqual(res.id, '_716cfa40a953610d9d68');
    assert.strictEqual(res.issuer, 'urn:dev-tyj7qyzz.auth0.com');
    assert.strictEqual(res.status, 'urn:oasis:names:tc:SAML:2.0:status:Success');
    assert.strictEqual(res.destination, 'http://localhost:3000/slo');
    assert.strictEqual(res.inResponseTo, '_a0089b303b86a97080ff');
  });

  it('response ok for failed response', async function () {
    const res = await parseLogoutResponse(responseFailed);
    assert.strictEqual(res.id, '_716cfa40a953610d9d68');
    assert.strictEqual(res.issuer, 'urn:dev-tyj7qyzz.auth0.com');
    assert.strictEqual(res.status, 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed');
    assert.strictEqual(res.destination, 'http://localhost:3000/slo');
    assert.strictEqual(res.inResponseTo, '_a0089b303b86a97080ff');
  });

  it('createLogoutRequest ok', async function () {
    const req = createLogoutRequest({
      nameId: 'test',
      providerName: 'test',
      sloUrl: 'http://localhost:3000/slo',
    });

    assert.strictEqual(!!req.id, true);
    assert.strictEqual(!!req.xml, true);
  });

  it('should throw an expected error for response containing invalid xml', async function () {
    await assert.rejects(
      async () => {
        await parseLogoutResponse(responseInvalid);
      },
      (error: any) => {
        assert.strictEqual(error.message.includes('Non-whitespace before first tag'), true);
        return true;
      }
    );
  });

  it('should parse a valid LogoutRequest', async function () {
    const parsed = await parseLogoutRequest(request);

    assert.strictEqual(
      parsed.id,
      'ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d',
      'Should extract the request ID'
    );
    assert.strictEqual(parsed.issuer, 'https://twilio.com/saml2/entityId', 'Should extract the issuer');
    assert.strictEqual(parsed.nameId, 'logout@boxyhq.com', 'Should extract the NameID');
    assert.strictEqual(
      parsed.destination,
      'http://localhost:5225/api/identity-federation/slo',
      'Should extract the destination'
    );
  });

  it('should parse a valid LogoutRequest with id_token', async function () {
    const parsed = await parseLogoutRequest(requestWithIdToken);

    assert.strictEqual(
      parsed.idToken,
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test',
      'Should extract the id_token from Extensions'
    );
    assert.strictEqual(parsed.issuer, 'https://twilio.com/saml2/entityId', 'Should extract the issuer');
    assert.strictEqual(parsed.nameId, 'logout@boxyhq.com', 'Should extract the NameID');
    assert.strictEqual(
      parsed.destination,
      'http://localhost:5225/api/identity-federation/slo',
      'Should extract the destination'
    );
  });

  it('should throw an expected error for request containing invalid xml', async function () {
    await assert.rejects(
      async () => {
        await parseLogoutRequest(requestInvalid);
      },
      (error: any) => {
        assert.strictEqual(error.message.includes('Non-whitespace before first tag'), true);
        return true;
      }
    );
  });
});
