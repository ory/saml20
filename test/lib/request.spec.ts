import assert from 'assert';
import fs from 'fs';
import { decodeBase64, parseSAMLRequest, request } from '../../lib/request';
import { doctypeNotAllowedError } from '../../lib/utils';

const request1 = fs.readFileSync('./test/assets/request1.xml').toString();
const request2 = fs.readFileSync('./test/assets/request2.xml').toString();
const request3 = fs.readFileSync('./test/assets/request3.xml').toString();

const ssoUrl =
  'https://dev-20901260.okta.com/app/dev-20901260_jacksondemo5225_1/exk3wth7ss1TKnAN15d7/sso/saml';
const entityID = 'https://saml.boxyhq.com';
const callbackUrl = 'http://localhost:5225/api/oauth/saml';

const signingKey =
  '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+OW02UYdrA8aHlgcVmGT551Ft3Z83uRNCMNHHKGzVOARhm0xY4RhLya/o+sMz6I+rwvhk00ZNv9qQHXqXiP0tOn8gdjtL9Iw2OH7Jpe6VRvhmWq/0ts0YrDL33VjjoKwJgblFgV0s0XIb58qQa2Leif2KucFHtRkEMWaAaBzrUC7PpNVoV75zBzLkQ0H7ERm3haobE8hdFUR+pI+Nn6WiFbtrqedtV4vospd3m3LwmLIYCPdoMNl9/o578wjG03qLHOx9ewvR2GZa91T7z6th0Yb2q4g3oGWtO4+PiOiTVzNtcIyunGvbkCSFE5uTWohclkZFNupHeB9DwLHvrwytAgMBAAECggEBAJDF9/59MkkaCICsiBvBbihcCrdJEqJAMw4PRbkDZUEpbvwyS3rhZbJYf48bOnFJL/8TViS2Py1xNJC2PtURp05C1PoJwbtfFU821Bf4N4pZBzgvEPd4IMQEWo4WYk5rvENH/Y+OkzFG/keKs7oSYJ7p+pMYKKfAhpeQWWik1E2p2coaN0gFIyY1Jei22VTh/BjzNAxc3bI1F2tHUovo3EHJ4Ft2exYG9231JloHKPsxsPR/7BigDFFqaGYQyp3lxNvPSdH0UN+chfLZsCI5cG//qMeAAPHu9zdwOorSuHxB6kP69tPdFRTs6DaHVmSwsC+XpzoE4nXBWyM+6lnEuYECgYEA7676sYOiXJ6Y/epaDxZHdLTkPJK5YqJG1xmCFYGslkcbeYQyhpzQzAAzgxefPXhKcaFpEv2gvBbtGE7rxvjBSX4EVaeIcP+8bex6K3ZH0ND5EUFeg8EbZf4rkbqPexEocxn+2HZ/HhHNYvgLMeicKe4bcAIt0z/yTi3B0ufSJ/0CgYEAyyyCrJzCN7x4aOhlFmD3qwKyHRu0AszJY5xONO0A3ZjtKzOGqPcHwNZqq8yCgFTDvqkvicsqo9i/9+czC1MnyQ7hpG43+2JoemPq87uzlvkt0eck1ncyjeTK5ckpvRaiOFhtOWoIqpBGzL4iBPI5TxA3e9lYlHxJ3+KRQ1uW3nECgYA7YPIigCX9JB1q6mAdVLunIhlZGFBtKx65s0wS3+lN4Zfg5utNhhQENhiM5ZFBvUdUF1Tcq5DiiBt85jBrPr1D48BXKAYZWIHqCafKlKb+CIdryvILWg/bmLhahgl9x6ZpvYrxPYoIfQiQ+Dptxt7JVH/fo+qOZ000KQnXoi7iUQKBgE+Ayl2bNdCzmnaKwcvBBAlSE7qaNZWG5yNobZ3+RAFyrxPhpMcHa2xFOxag/0wSX0qDT8veyX+1+GCcgvfigUYG4bsDOjrPZkzGPpFDmOHx/cEObvbRS+IEbnT+g6uvaKkdyRfXay67KElD+XHwCwbqNJvtD+GCxTGrqeYut9mxAoGAabRuoqxlO/eZnxBYRb3aHTcn4bTaKvJm5ez2vyctgc01wScpigly4EWaVTy7LEJAQV+RbnlI3EARHnPc7Mr+brtXnLwinGRh5WZiU4oF+Wm6WFzTS0h47WjK4TmbKdr04P/3hkhT71sxc3VEfj9Hf4XiaAmJaUQ/LyPXHzapbuY=\n-----END PRIVATE KEY-----';
const publicKey =
  '-----BEGIN CERTIFICATE-----\nMIIC6jCCAdKgAwIBAgIBATANBgkqhkiG9w0BAQsFADAZMRcwFQYDVQQDEw5Cb3h5SFEgSmFja3NvbjAcFw0yMjA0MDcxOTEyMTBaFwsxMjMxMTgzMDAwWjAZMRcwFQYDVQQDEw5Cb3h5SFEgSmFja3NvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL45bTZRh2sDxoeWBxWYZPnnUW3dnze5E0Iw0ccobNU4BGGbTFjhGEvJr+j6wzPoj6vC+GTTRk2/2pAdepeI/S06fyB2O0v0jDY4fsml7pVG+GZar/S2zRisMvfdWOOgrAmBuUWBXSzRchvnypBrYt6J/Yq5wUe1GQQxZoBoHOtQLs+k1WhXvnMHMuRDQfsRGbeFqhsTyF0VRH6kj42fpaIVu2up521Xi+iyl3ebcvCYshgI92gw2X3+jnvzCMbTeosc7H17C9HYZlr3VPvPq2HRhvariDegZa07j4+I6JNXM21wjK6ca9uQJIUTm5NaiFyWRkU26kd4H0PAse+vDK0CAwEAAaM/MD0wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFI0tLXGuzcZi2eXNI3epHYJwreXQMA0GCSqGSIb3DQEBCwUAA4IBAQAEre2GfP/haRoQo0JYFKqXNsogR1++kFIebn9FTnb64+bDd5DRhV2pOAtAFIWUbm5+YeQIkBbAQmfPFX5OG6WgBSqgJCMpU7ekVwU/tExhxXFaTCRL39pMwLnsJ9R6NIy/WUKrTDW9VtyINE5OIL7lDZbejKbidIuOtdyJtlJrLtnVuhiLmNaZJo+kDKvHYKVmwdEXRMQ5OyR0f53MV4Kq/28dSeUQPe+qKovrcVk3F0J8h+aj/+1bU6VsBfrNSRq1dO/jQM6oIOUI68q3GNBeOCEcDGXpytX5C0HxVmNTz5/ybqB14hEhp343GIZ0/gbdAGmt90uJHoS9Xp4dI77j\n-----END CERTIFICATE-----';

describe('request.ts', function () {
  // See https://github.com/ory/polis/issues/4071.
  it('parseSAMLRequest rejects a request that declares a DTD', async function () {
    const dtd =
      '<?xml version="1.0"?><!DOCTYPE AuthnRequest [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>' +
      '<AuthnRequest>&x;</AuthnRequest>';
    await assert.rejects(parseSAMLRequest(dtd, false), doctypeNotAllowedError);
  });

  it('request ok', function () {
    assert(
      request({
        ssoUrl,
        entityID: entityID,
        callbackUrl: callbackUrl,
        signingKey: signingKey,
        publicKey: publicKey,
      })
    );
  });

  it('parseSAMLRequest sample 1 ok', async function () {
    const decodedRequest1 = await decodeBase64(request1, true);
    const res1 = await parseSAMLRequest(decodedRequest1, false);
    assert.strictEqual(res1.id, 'id-6888523066678369812_-1');
    assert.strictEqual(res1.acsUrl, 'https://test1.snowflakecomputing.com/fed/login');
    assert.strictEqual(res1.audience, 'https://test1.snowflakecomputing.com');
    assert.strictEqual(res1.publicKey, null);
  });

  it('parseSAMLRequest sample 2 ok', async function () {
    const decodedRequest2 = await decodeBase64(request2, true);
    const res2 = await parseSAMLRequest(decodedRequest2, false);
    assert.strictEqual(res2.id, '_aa4df01f-3911-4de7-ae9a-a793a7f6c12c');
    assert.strictEqual(res2.acsUrl, undefined);
    assert.strictEqual(res2.audience, 'https://fivetran.com');
    assert.strictEqual(res2.publicKey, null);
  });

  it('parseSAMLRequest sample 3 ok', async function () {
    const decodedRequest3 = await decodeBase64(request3, true);
    const res3 = await parseSAMLRequest(decodedRequest3, false);
    assert.strictEqual(res3.id, 'ONELOGIN_c6bc2360-ea7d-45ca-b206-4220a4f5b978');
    assert.strictEqual(res3.acsUrl, 'https://iam.twilio.com/v1/Accounts/abcdef/saml2');
    assert.strictEqual(res3.audience, 'https://iam.twilio.com/v1/Accounts/abcdef/saml2/metadata');
    assert.strictEqual(res3.publicKey, null);
    assert.strictEqual(res3.providerName, 'Twilio');
  });
});
describe('request.ts', function () {
  it('should generate a valid SAML request with default parameters', function () {
    const result = request({
      ssoUrl,
      entityID,
      callbackUrl,
      signingKey,
      publicKey,
    });

    assert(result.id.startsWith('_'));
    assert(result.request.includes('<samlp:AuthnRequest'));
    assert(result.request.includes(`Destination="${ssoUrl}"`));
    assert(result.request.includes(`AssertionConsumerServiceURL="${callbackUrl}"`));
    assert(result.request.includes(`ProviderName="BoxyHQ"`));
    assert(result.request.includes(`Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"`));
  });

  it('should generate a valid SAML request with isPassive set to true', function () {
    const result = request({
      ssoUrl,
      entityID,
      callbackUrl,
      isPassive: true,
      signingKey,
      publicKey,
    });

    assert(result.request.includes('IsPassive="true"'));
  });

  it('should generate a valid SAML request with forceAuthn set to true', function () {
    const result = request({
      ssoUrl,
      entityID,
      callbackUrl,
      forceAuthn: true,
      signingKey,
      publicKey,
    });

    assert(result.request.includes('ForceAuthn="true"'));
  });

  it('should generate a valid SAML request with custom identifierFormat', function () {
    const customIdentifierFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
    const result = request({
      ssoUrl,
      entityID,
      callbackUrl,
      identifierFormat: customIdentifierFormat,
      signingKey,
      publicKey,
    });

    assert(result.request.includes(`Format="${customIdentifierFormat}"`));
  });

  it('should generate a valid SAML request with custom providerName', function () {
    const customProviderName = 'CustomProvider';
    const result = request({
      ssoUrl,
      entityID,
      callbackUrl,
      providerName: customProviderName,
      signingKey,
      publicKey,
    });

    assert(result.request.includes(`ProviderName="${customProviderName}"`));
  });

  it('should generate a signed SAML request', function () {
    const result = request({
      ssoUrl,
      entityID,
      callbackUrl,
      signingKey,
      publicKey,
    });

    assert(result.request.includes('<Signature'));
  });
});
