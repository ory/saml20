import assert from 'assert';
import { parseMetadata, createIdPMetadataXML, createSPMetadataXML } from '../../lib/metadata';
import fs from 'fs';

const samlMetadata = fs.readFileSync('./test/assets/mock-saml-metadata.xml').toString();
const samlMetadata1 = fs.readFileSync('./test/assets/mock-saml-metadata1.xml').toString();
const samlMetadata2 = fs.readFileSync('./test/assets/mock-saml-metadata2.xml').toString();
const samlMetadata3 = fs.readFileSync('./test/assets/mock-saml-metadata3.xml').toString();
const samlMetadata4 = fs.readFileSync('./test/assets/mock-saml-metadata4.xml').toString();
const samlMetadata5 = fs.readFileSync('./test/assets/mock-saml-metadata5.xml').toString();
const samlMetadata6 = fs.readFileSync('./test/assets/mock-saml-metadata6.xml').toString();
const samlMetadata7 = fs.readFileSync('./test/assets/mock-saml-metadata7.xml').toString();

describe('metadata.ts', function () {
  it('saml MetaData ok without BEGIN & END notations', async function () {
    const value = await parseMetadata(samlMetadata, {});
    assert.strictEqual(value.entityID, 'https://saml.example.com/entityid');
    assert.strictEqual(value.thumbprint, '8996bcc1afff3ff8e41f8025ff034b516050a434');

    assert.strictEqual(value.loginType, 'idp');
    assert.strictEqual(value.sso.postUrl, 'http://localhost:4000/api/saml/sso');
    assert.strictEqual(value.sso.redirectUrl, 'http://localhost:4000/api/saml/sso');
    assert.strictEqual(value.validTo, 'Aug 12 10:27:20 3021 GMT');
  });

  it('saml MetaData ok with cert having BEGIN & END notations', async function () {
    const value = await parseMetadata(samlMetadata1, {});
    assert.strictEqual(value.entityID, 'https://saml.example.com/entityid');
    assert.strictEqual(value.thumbprint, 'f9e424fe5fb3422db37859fe29b7f92f11af60a7');
    assert.strictEqual(value.loginType, 'idp');
    assert.strictEqual(value.sso.postUrl, 'http://localhost:4000/api/saml/sso');
    assert.strictEqual(value.sso.redirectUrl, 'http://localhost:4000/api/saml/sso');
    assert.strictEqual(value.validTo, 'Aug 12 10:27:20 3021 GMT');
  });

  it('saml MetaData ok with cert having just END notations', async function () {
    const value = await parseMetadata(samlMetadata2, {});
    assert.strictEqual(value.entityID, 'https://saml.example.com/entityid');
    assert.strictEqual(value.thumbprint, '8996bcc1afff3ff8e41f8025ff034b516050a434');
    assert.strictEqual(value.loginType, 'idp');
    assert.strictEqual(value.sso.postUrl, 'http://localhost:4000/api/saml/sso');
    assert.strictEqual(value.sso.redirectUrl, 'http://localhost:4000/api/saml/sso');
    assert.strictEqual(value.validTo, 'Aug 12 10:27:20 3021 GMT');
  });

  it('saml MetaData ok with cert having just BEGIN notations', async function () {
    const value = await parseMetadata(samlMetadata3, {});
    assert.strictEqual(value.entityID, 'https://saml.example.com/entityid');
    assert.strictEqual(value.thumbprint, 'f9e424fe5fb3422db37859fe29b7f92f11af60a7');
    assert.strictEqual(value.loginType, 'idp');
    assert.strictEqual(value.sso.postUrl, 'http://localhost:4000/api/saml/sso');
    assert.strictEqual(value.sso.redirectUrl, 'http://localhost:4000/api/saml/sso');
    assert.strictEqual(value.validTo, 'Aug 12 10:27:20 3021 GMT');
  });

  it('saml MetaData ok with multiple signing certs', async function () {
    const value = await parseMetadata(samlMetadata4, {});
    assert.strictEqual(value.entityID, 'https://saml.example.com/entityid');
    assert.strictEqual(
      '8996bcc1afff3ff8e41f8025ff034b516050a434,f9e424fe5fb3422db37859fe29b7f92f11af60a7',
      value.thumbprint
    );
    assert.strictEqual(
      value.publicKey,
      `MIICmDCCAYACCQC6LM978TM/gjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJJ
\t\t\t\t\t\tbjAgFw0yMjA0MTExMDI3MjBaGA8zMDIxMDgxMjEwMjcyMFowDTELMAkGA1UEBhMC
\t\t\t\t\t\tSW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgPMN71V4y5VzLw6Ev
\t\t\t\t\t\taQA+oMLzmIpoV/p4Y3AM00FUYbVhVtngvRPCmsKOvIxkTM9kZ6VjVfPmzQet+dDS
\t\t\t\t\t\t+rOmJDH5Y+42du6dJnA0SM/wNWL7nAqfWN6e7q7/Jxa/dYMOhkgV6/7+0jBxHGnn
\t\t\t\t\t\tx/2CEVeDF5+nPsdDh2HlPy0MCXLjXGvRpHB/IHQsUHJFKuOQzTiz1OMQHLnV+FQX
\t\t\t\t\t\tT2kDsGmbM/wZo6xGeH5qcRqZJGgLvtLj8XNe6yVmb1naog7Fr7gjThMichkNDVg2
\t\t\t\t\t\t0/lkxYqIL8zgS2NYXwQ6UOKplUv189kHSbXgQCco0h1oNR2LRTaHoYsRnzLMH2Pv
\t\t\t\t\t\tjVoTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMXKnzYEyLFwePXXWE76lq5S+2O2
\t\t\t\t\t\tJIMtygzB3YxOJwvIFWmwDPxqpr4aOpw6T2pQLa3rM1YjW2roNw7B3HHXWoc9F4Av
\t\t\t\t\t\tGAe8T1u0Cu+Tyo8ZFf9VrPg5kZ7x2G+nojFfs8zeuEKdNrUZz4bkgkC7sTWHFsOA
\t\t\t\t\t\toZjUqLyT2tfLnXfYGiXd0qGg9X1bs1x+anAhViltjZ97Eeq8wPtRqhm1hiQyawKT
\t\t\t\t\t\t5qs4oKw0AaKsW4pBQux4h+ZmfvqD+1chBd5Ve/bq9FsEnWNkGyawzmsMSTB9UwDA
\t\t\t\t\t\t+bqiHmfaTXWlQnualNaY3g5v7EDVB4COz6rXXQY/y5Y90BFoho5MqIjGW0I=,-----BEGIN CERTIFICATE-----
\t\t\t\t\t\tMIICmDCCAYACCQC6LM978TM/gjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJJ
\t\t\t\t\t\tbjAgFw0yMjA0MTExMDI3MjBaGA8zMDIxMDgxMjEwMjcyMFowDTELMAkGA1UEBhMC
\t\t\t\t\t\tSW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgPMN71V4y5VzLw6Ev
\t\t\t\t\t\taQA+oMLzmIpoV/p4Y3AM00FUYbVhVtngvRPCmsKOvIxkTM9kZ6VjVfPmzQet+dDS
\t\t\t\t\t\t+rOmJDH5Y+42du6dJnA0SM/wNWL7nAqfWN6e7q7/Jxa/dYMOhkgV6/7+0jBxHGnn
\t\t\t\t\t\tx/2CEVeDF5+nPsdDh2HlPy0MCXLjXGvRpHB/IHQsUHJFKuOQzTiz1OMQHLnV+FQX
\t\t\t\t\t\tT2kDsGmbM/wZo6xGeH5qcRqZJGgLvtLj8XNe6yVmb1naog7Fr7gjThMichkNDVg2
\t\t\t\t\t\t0/lkxYqIL8zgS2NYXwQ6UOKplUv189kHSbXgQCco0h1oNR2LRTaHoYsRnzLMH2Pv
\t\t\t\t\t\tjVoTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMXKnzYEyLFwePXXWE76lq5S+2O2
\t\t\t\t\t\tJIMtygzB3YxOJwvIFWmwDPxqpr4aOpw6T2pQLa3rM1YjW2roNw7B3HHXWoc9F4Av
\t\t\t\t\t\tGAe8T1u0Cu+Tyo8ZFf9VrPg5kZ7x2G+nojFfs8zeuEKdNrUZz4bkgkC7sTWHFsOA
\t\t\t\t\t\toZjUqLyT2tfLnXfYGiXd0qGg9X1bs1x+anAhViltjZ97Eeq8wPtRqhm1hiQyawKT
\t\t\t\t\t\t5qs4oKw0AaKsW4pBQux4h+ZmfvqD+1chBd5Ve/bq9FsEnWNkGyawzmsMSTB9UwDA
\t\t\t\t\t\t+bqiHmfaTXWlQnualNaY3g5v7EDVB4COz6rXXQY/y5Y90BFoho5MqIjGW0I=`
    );
    assert.strictEqual(value.loginType, 'idp');
    assert.strictEqual(value.sso.postUrl, 'http://localhost:4000/api/saml/sso');
    assert.strictEqual(value.sso.redirectUrl, 'http://localhost:4000/api/saml/sso');
    assert.strictEqual(value.validTo, 'Aug 12 10:27:20 3021 GMT,Aug 12 10:27:20 3021 GMT');
  });

  it('saml Metadata validateNameIDFormat ok', async function () {
    assert(
      await parseMetadata(samlMetadata, {
        validateNameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      })
    );
  });

  it('saml MetaData not ok', async function () {
    try {
      await parseMetadata('samlMetadata', {
        validateNameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      });
    } catch (error) {
      assert(error);
    }
  });

  it(`metadata with missing KeyDescriptor attribute 'use=signing' should use the cert available`, async function () {
    const value = await parseMetadata(samlMetadata5, {});
    assert.strictEqual(value.thumbprint, 'd797f3829882233d3f01e49643f6a1195f242c94');
    assert.strictEqual(
      value.publicKey,
      `MIIC4jCCAcoCCQC33wnybT5QZDANBgkqhkiG9w0BAQsFADAyMQswCQYDVQQGEwJV
                        SzEPMA0GA1UECgwGQm94eUhRMRIwEAYDVQQDDAlNb2NrIFNBTUwwIBcNMjIwMjI4
                        MjE0NjM4WhgPMzAyMTA3MDEyMTQ2MzhaMDIxCzAJBgNVBAYTAlVLMQ8wDQYDVQQK
                        DAZCb3h5SFExEjAQBgNVBAMMCU1vY2sgU0FNTDCCASIwDQYJKoZIhvcNAQEBBQAD
                        ggEPADCCAQoCggEBALGfYettMsct1T6tVUwTudNJH5Pnb9GGnkXi9Zw/e6x45DD0
                        RuRONbFlJ2T4RjAE/uG+AjXxXQ8o2SZfb9+GgmCHuTJFNgHoZ1nFVXCmb/Hg8Hpd
                        4vOAGXndixaReOiq3EH5XvpMjMkJ3+8+9VYMzMZOjkgQtAqO36eAFFfNKX7dTj3V
                        pwLkvz6/KFCq8OAwY+AUi4eZm5J57D31GzjHwfjH9WTeX0MyndmnNB1qV75qQR3b
                        2/W5sGHRv+9AarggJkF+ptUkXoLtVA51wcfYm6hILptpde5FQC8RWY1YrswBWAEZ
                        NfyrR4JeSweElNHg4NVOs4TwGjOPwWGqzTfgTlECAwEAATANBgkqhkiG9w0BAQsF
                        AAOCAQEAAYRlYflSXAWoZpFfwNiCQVE5d9zZ0DPzNdWhAybXcTyMf0z5mDf6FWBW
                        5Gyoi9u3EMEDnzLcJNkwJAAc39Apa4I2/tml+Jy29dk8bTyX6m93ngmCgdLh5Za4
                        khuU3AM3L63g7VexCuO7kwkjh/+LqdcIXsVGO6XDfu2QOs1Xpe9zIzLpwm/RNYeX
                        UjbSj5ce/jekpAw7qyVVL4xOyh8AtUW1ek3wIw1MJvEgEPt0d16oshWJpoS1OT8L
                        r/22SvYEo3EmSGdTVGgk3x3s+A0qWAqTcyjr7Q4s/GKYRFfomGwz0TZ4Iw1ZN99M
                        m0eo2USlSRTVl7QHRTuiuSThHpLKQQ==`
    );
  });

  it(`metadata with missing KeyDescriptor attribute 'use=signing' should use all the certs available (multi cert metadata)`, async function () {
    const value = await parseMetadata(samlMetadata7, {});

    assert.strictEqual(
      value.thumbprint,
      '8996bcc1afff3ff8e41f8025ff034b516050a434,f9e424fe5fb3422db37859fe29b7f92f11af60a7'
    );
    assert.strictEqual(
      value.publicKey,
      `MIICmDCCAYACCQC6LM978TM/gjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJJ
                        bjAgFw0yMjA0MTExMDI3MjBaGA8zMDIxMDgxMjEwMjcyMFowDTELMAkGA1UEBhMC
                        SW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgPMN71V4y5VzLw6Ev
                        aQA+oMLzmIpoV/p4Y3AM00FUYbVhVtngvRPCmsKOvIxkTM9kZ6VjVfPmzQet+dDS
                        +rOmJDH5Y+42du6dJnA0SM/wNWL7nAqfWN6e7q7/Jxa/dYMOhkgV6/7+0jBxHGnn
                        x/2CEVeDF5+nPsdDh2HlPy0MCXLjXGvRpHB/IHQsUHJFKuOQzTiz1OMQHLnV+FQX
                        T2kDsGmbM/wZo6xGeH5qcRqZJGgLvtLj8XNe6yVmb1naog7Fr7gjThMichkNDVg2
                        0/lkxYqIL8zgS2NYXwQ6UOKplUv189kHSbXgQCco0h1oNR2LRTaHoYsRnzLMH2Pv
                        jVoTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMXKnzYEyLFwePXXWE76lq5S+2O2
                        JIMtygzB3YxOJwvIFWmwDPxqpr4aOpw6T2pQLa3rM1YjW2roNw7B3HHXWoc9F4Av
                        GAe8T1u0Cu+Tyo8ZFf9VrPg5kZ7x2G+nojFfs8zeuEKdNrUZz4bkgkC7sTWHFsOA
                        oZjUqLyT2tfLnXfYGiXd0qGg9X1bs1x+anAhViltjZ97Eeq8wPtRqhm1hiQyawKT
                        5qs4oKw0AaKsW4pBQux4h+ZmfvqD+1chBd5Ve/bq9FsEnWNkGyawzmsMSTB9UwDA
                        +bqiHmfaTXWlQnualNaY3g5v7EDVB4COz6rXXQY/y5Y90BFoho5MqIjGW0I=,-----BEGIN CERTIFICATE-----
                        MIICmDCCAYACCQC6LM978TM/gjANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJJ
                        bjAgFw0yMjA0MTExMDI3MjBaGA8zMDIxMDgxMjEwMjcyMFowDTELMAkGA1UEBhMC
                        SW4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDgPMN71V4y5VzLw6Ev
                        aQA+oMLzmIpoV/p4Y3AM00FUYbVhVtngvRPCmsKOvIxkTM9kZ6VjVfPmzQet+dDS
                        +rOmJDH5Y+42du6dJnA0SM/wNWL7nAqfWN6e7q7/Jxa/dYMOhkgV6/7+0jBxHGnn
                        x/2CEVeDF5+nPsdDh2HlPy0MCXLjXGvRpHB/IHQsUHJFKuOQzTiz1OMQHLnV+FQX
                        T2kDsGmbM/wZo6xGeH5qcRqZJGgLvtLj8XNe6yVmb1naog7Fr7gjThMichkNDVg2
                        0/lkxYqIL8zgS2NYXwQ6UOKplUv189kHSbXgQCco0h1oNR2LRTaHoYsRnzLMH2Pv
                        jVoTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMXKnzYEyLFwePXXWE76lq5S+2O2
                        JIMtygzB3YxOJwvIFWmwDPxqpr4aOpw6T2pQLa3rM1YjW2roNw7B3HHXWoc9F4Av
                        GAe8T1u0Cu+Tyo8ZFf9VrPg5kZ7x2G+nojFfs8zeuEKdNrUZz4bkgkC7sTWHFsOA
                        oZjUqLyT2tfLnXfYGiXd0qGg9X1bs1x+anAhViltjZ97Eeq8wPtRqhm1hiQyawKT
                        5qs4oKw0AaKsW4pBQux4h+ZmfvqD+1chBd5Ve/bq9FsEnWNkGyawzmsMSTB9UwDA
                        +bqiHmfaTXWlQnualNaY3g5v7EDVB4COz6rXXQY/y5Y90BFoho5MqIjGW0I=`
    );
  });

  it(`metadata with missing KeyDescriptor should throw an error`, async () => {
    try {
      await parseMetadata(samlMetadata6, {});
    } catch (error) {
      const result = (error as Error).message;
      assert.strictEqual(result, 'Could not find X509Certificate in the IdP metadata.');
    }
  });

  it(`createIdPMetadataXML ok`, async () => {
    const res = createIdPMetadataXML({
      ssoUrl: 'http://localhost:4000/api/saml/sso',
      entityId: 'https://saml.example.com/entityid',
      x509cert: 'x509cert',
      wantAuthnRequestsSigned: false,
    });

    assert.strictEqual(!!res, true);
  });

  it(`createSPMetadataXML ok`, async () => {
    const res = createSPMetadataXML({
      acsUrl: 'http://localhost:4000/api/saml/sso',
      entityId: 'https://saml.example.com/entityid',
      publicKeyString: 'x509cert',
      encryption: false,
    });

    assert.strictEqual(!!res, true);
  });
  it(`createSPMetadataXML ok with encryption`, async () => {
    const res = createSPMetadataXML({
      acsUrl: 'http://localhost:4000/api/saml/sso',
      entityId: 'https://saml.example.com/entityid',
      publicKeyString: 'x509cert',
      encryption: true,
    });

    assert.strictEqual(!!res, true);
    assert(res.includes('md:EncryptionMethod'));
  });

  it('saml MetaData validateNameIDFormat not ok', async function () {
    try {
      await parseMetadata(samlMetadata, {
        validateNameIDFormat: 'invalid:format',
      });
    } catch (error) {
      assert.strictEqual(
        (error as Error).message,
        "Invalid nameIDFormat. Please set 'Name ID Format' to undefined"
      );
    }
  });

  it('saml MetaData with SLO services', async function () {
    const sloMetadata = `
      <EntityDescriptor entityID="https://saml.example.com/entityid" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
              <X509Data>
                <X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</X509Certificate>
              </X509Data>
            </KeyInfo>
          </KeyDescriptor>
          <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://localhost:4000/api/saml/slo/redirect"/>
          <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:4000/api/saml/slo/post"/>
        </IDPSSODescriptor>
      </EntityDescriptor>
    `;
    const value = await parseMetadata(sloMetadata, {});
    assert.strictEqual(value.slo.redirectUrl, 'http://localhost:4000/api/saml/slo/redirect');
    assert.strictEqual(value.slo.postUrl, 'http://localhost:4000/api/saml/slo/post');
  });

  it('saml MetaData with SP descriptor', async function () {
    const spMetadata = `
      <EntityDescriptor entityID="https://saml.example.com/entityid" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
        <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <KeyDescriptor use="signing">
            <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
              <X509Data>
                <X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</X509Certificate>
              </X509Data>
            </KeyInfo>
          </KeyDescriptor>
        </SPSSODescriptor>
      </EntityDescriptor>
    `;
    const value = await parseMetadata(spMetadata, {});
    assert.strictEqual(value.loginType, 'sp');
  });
});
