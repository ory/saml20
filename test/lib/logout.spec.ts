import assert from 'assert';
import fs from 'fs';
import {
  parseLogoutResponse,
  createLogoutRequest,
  parseLogoutRequest,
  createLogoutResponse,
} from '../../lib/logout';
import { doctypeNotAllowedError } from '../../lib/utils';

const response = fs.readFileSync('./test/assets/logout-response.xml').toString();
const responseFailed = fs.readFileSync('./test/assets/logout-response-failed.xml').toString();
const responseInvalid = 'invalid_data';

const request = fs.readFileSync('./test/assets/logout-request.xml').toString();
const requestWithIdToken = fs.readFileSync('./test/assets/logout-request-with-idtoken.xml').toString();
const requestInvalid = 'invalid_data';

describe('logout.ts', function () {
  // See https://github.com/ory/polis/issues/4071.
  it('should reject a logout response that declares a DTD', async function () {
    const dtd =
      '<?xml version="1.0"?><!DOCTYPE LogoutResponse [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>' +
      '<LogoutResponse>&x;</LogoutResponse>';
    await assert.rejects(parseLogoutResponse(dtd), doctypeNotAllowedError);
  });

  it('should reject a logout request that declares a DTD', async function () {
    const dtd =
      '<?xml version="1.0"?><!DOCTYPE LogoutRequest [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>' +
      '<LogoutRequest>&x;</LogoutRequest>';
    await assert.rejects(parseLogoutRequest(dtd), doctypeNotAllowedError);
  });

  it('should reject a whitespace-free DOCTYPE in a logout message', async function () {
    await assert.rejects(
      parseLogoutResponse('<!DOCTYPELogoutResponse SYSTEM "file:///x"><LogoutResponse/>'),
      doctypeNotAllowedError
    );
  });

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
    assert.strictEqual(parsed.issueInstant, '2024-01-15T09:30:00Z', 'Should extract the IssueInstant');
  });

  it('should leave issueInstant undefined when the request omits it', async function () {
    const withoutIssueInstant = request.replace(' IssueInstant="2024-01-15T09:30:00Z"', '');

    assert.notStrictEqual(withoutIssueInstant, request, 'The fixture should have lost its IssueInstant');

    const parsed = await parseLogoutRequest(withoutIssueInstant);

    assert.strictEqual(parsed.issueInstant, undefined, 'Should report a missing IssueInstant as undefined');
    assert.strictEqual(
      parsed.id,
      'ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d',
      'Should still parse the rest of the request'
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

  it('should create a valid LogoutRequest', async function () {
    const { id, xml } = createLogoutResponse({
      requestId: 'original-request-id',
      issuer: 'https://saml.boxyhq.com',
      destination: 'https://twilio.com/saml2/slo',
    });

    assert.strictEqual(!!id, true, 'Should have an ID');
    assert.strictEqual(id.startsWith('_'), true, 'ID should start with underscore');
    assert.strictEqual(xml.includes('LogoutResponse'), true, 'Should contain LogoutResponse element');
    assert.strictEqual(
      xml.includes('InResponseTo="original-request-id"'),
      true,
      'Should contain InResponseTo attribute'
    );
    assert.strictEqual(
      xml.includes('Destination="https://twilio.com/saml2/slo"'),
      true,
      'Should contain the destination'
    );
    assert.strictEqual(xml.includes('saml:Issuer'), true, 'Should contain the issuer element');
    assert.strictEqual(
      xml.includes('urn:oasis:names:tc:SAML:2.0:status:Success'),
      true,
      'Should have Success status'
    );
  });

  it('should create a LogoutResponse with custom status', async function () {
    const { xml } = createLogoutResponse({
      requestId: 'test-id',
      issuer: 'https://saml.boxyhq.com',
      destination: 'https://twilio.com/saml2/slo',
      status: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
    });

    assert.strictEqual(
      xml.includes('urn:oasis:names:tc:SAML:2.0:status:Requester'),
      true,
      'Should have custom status'
    );
  });
});

describe('parseLogoutResponse edge cases', function () {
  const wrap = (inner: string, attrs = 'ID="_1" InResponseTo="_req" Destination="https://sp/slo"') =>
    `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ${attrs}>${inner}</samlp:LogoutResponse>`;
  const success =
    '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>';

  it('reads an Issuer that has no attributes of its own', async function () {
    const parsed = await parseLogoutResponse(wrap(`<saml:Issuer>https://idp</saml:Issuer>${success}`));
    assert.strictEqual(parsed.issuer, 'https://idp');
    assert.strictEqual(parsed.id, '_1');
    assert.strictEqual(parsed.inResponseTo, '_req');
    assert.strictEqual(parsed.destination, 'https://sp/slo');
    assert.strictEqual(parsed.status, 'urn:oasis:names:tc:SAML:2.0:status:Success');
  });

  it('reads an Issuer that carries attributes', async function () {
    const parsed = await parseLogoutResponse(
      wrap(
        `<saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://idp</saml:Issuer>${success}`
      )
    );
    assert.strictEqual(parsed.issuer, 'https://idp');
  });

  it('rejects a document whose root is not LogoutResponse', async function () {
    await assert.rejects(parseLogoutResponse('<LogoutRequest ID="_1"/>'), {
      message: 'Invalid SAML LogoutResponse: missing LogoutResponse element.',
    });
  });

  it('rejects a LogoutResponse without a StatusCode', async function () {
    await assert.rejects(parseLogoutResponse(wrap('<saml:Issuer>https://idp</saml:Issuer>')), {
      message: 'Invalid SAML LogoutResponse: missing StatusCode.',
    });
  });
});

describe('parseLogoutRequest edge cases', function () {
  const wrap = (inner: string) =>
    '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
    'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ' +
    `ID="_logout-1" Destination="https://idp/slo" IssueInstant="2026-01-01T00:00:00Z">${inner}</samlp:LogoutRequest>`;
  const issuerAndNameId = '<saml:Issuer>https://sp</saml:Issuer><saml:NameID>jo@example.com</saml:NameID>';
  const signatureWith = (certificate: string) =>
    `<ds:Signature><ds:SignedInfo/><ds:KeyInfo><ds:X509Data>${certificate}</ds:X509Data></ds:KeyInfo></ds:Signature>`;

  it('rejects a document whose root is not LogoutRequest', async function () {
    await assert.rejects(parseLogoutRequest('<LogoutResponse ID="_1"/>'), {
      message: 'Invalid SAML LogoutRequest: missing LogoutRequest element.',
    });
  });

  it('returns the certificate embedded in the Signature', async function () {
    const parsed = await parseLogoutRequest(
      wrap(issuerAndNameId + signatureWith('<ds:X509Certificate>MIIC</ds:X509Certificate>'))
    );
    assert.strictEqual(parsed.publicKey, 'MIIC');
  });

  it('returns the text of a certificate element that carries attributes', async function () {
    const parsed = await parseLogoutRequest(
      wrap(issuerAndNameId + signatureWith('<ds:X509Certificate Id="c1">MIIC</ds:X509Certificate>'))
    );
    assert.strictEqual(parsed.publicKey, 'MIIC');
  });

  it('leaves publicKey undefined for a Signature without a certificate', async function () {
    const parsed = await parseLogoutRequest(
      wrap(`${issuerAndNameId}<ds:Signature><ds:SignedInfo/></ds:Signature>`)
    );
    assert.strictEqual(parsed.publicKey, undefined);
  });

  it('reads the optional fields and defaults the missing ones', async function () {
    const parsed = await parseLogoutRequest(wrap(''));
    assert.deepStrictEqual(parsed, {
      id: '_logout-1',
      issuer: '',
      nameId: '',
      sessionIndex: undefined,
      destination: 'https://idp/slo',
      issueInstant: '2026-01-01T00:00:00Z',
      publicKey: undefined,
      idToken: undefined,
    });
  });

  it('ignores an Extensions Attribute that is not id_token', async function () {
    const parsed = await parseLogoutRequest(
      wrap(
        issuerAndNameId +
          '<samlp:Extensions><saml:Attribute Name="other"><saml:AttributeValue>x</saml:AttributeValue></saml:Attribute></samlp:Extensions>'
      )
    );
    assert.strictEqual(parsed.idToken, undefined);
  });
});

describe('logout round trips', function () {
  it('createLogoutRequest output parses back to the same values', async function () {
    const { id, xml } = createLogoutRequest({
      nameId: 'jo@example.com',
      providerName: 'https://sp',
      sloUrl: 'https://idp/slo',
    });
    const parsed = await parseLogoutRequest(xml);
    assert.strictEqual(parsed.id, id);
    assert.strictEqual(parsed.issuer, 'https://sp');
    assert.strictEqual(parsed.nameId, 'jo@example.com');
    assert.strictEqual(parsed.destination, 'https://idp/slo');
  });

  it('createLogoutResponse output parses back to the same values', async function () {
    const { id, xml } = createLogoutResponse({
      requestId: '_logout-1',
      issuer: 'https://idp',
      destination: 'https://sp/slo',
      status: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
    });
    assert.deepStrictEqual(await parseLogoutResponse(xml), {
      id,
      issuer: 'https://idp',
      status: 'urn:oasis:names:tc:SAML:2.0:status:Requester',
      destination: 'https://sp/slo',
      inResponseTo: '_logout-1',
    });
  });
});

describe('parseLogoutRequest on empty or bare input', function () {
  for (const input of ['', '   ', '<LogoutRequest/>']) {
    it(`rejects ${JSON.stringify(input)} with a clear error`, async function () {
      await assert.rejects(parseLogoutRequest(input), {
        message: 'Invalid SAML LogoutRequest: missing LogoutRequest element.',
      });
    });
  }

  it('reads a LogoutRequest whose element has no attributes', async function () {
    const parsed = await parseLogoutRequest(
      '<LogoutRequest><Issuer>https://sp</Issuer><NameID>jo@example.com</NameID></LogoutRequest>'
    );
    assert.strictEqual(parsed.id, undefined);
    assert.strictEqual(parsed.issuer, 'https://sp');
    assert.strictEqual(parsed.nameId, 'jo@example.com');
  });
});
