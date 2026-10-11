// Builders for SAML fixtures that need a fresh validity window or a shape the
// static assets in test/assets do not have. Everything is signed (and, where
// asked, encrypted) with the testIdp key pair.
import fs from 'fs';
import { promisify } from 'util';
import * as xmlenc from 'xml-encryption';
import { sign } from '../../lib/sign';

export const testIdpCert = fs.readFileSync('./test/assets/certificates/testIdpCert.crt').toString();
export const testIdpKey = fs.readFileSync('./test/assets/certificates/testIdpKey.pem').toString();

export const ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
export const PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';
export const RESPONSE_XPATH = `/*[local-name(.)="Response" and namespace-uri(.)="${PROTOCOL_NS}"]`;
export const ASSERTION_XPATH = `/*[local-name(.)="Assertion" and namespace-uri(.)="${ASSERTION_NS}"]`;

export const SP = 'https://sp.example.com/metadata';
export const ACS = 'https://sp.example.com/acs';
export const IDP = 'https://idp.example.com';
export const REQUEST_ID = '_request-1';

type AssertionOptions = {
  id?: string;
  // Each inner array is one <AudienceRestriction>.
  audienceRestrictions?: string[][];
  attributes?: string;
};

export const buildAssertion = ({
  id = '_assertion-1',
  audienceRestrictions = [[SP]],
  attributes = '',
}: AssertionOptions = {}) => {
  const notBefore = new Date(Date.now() - 60 * 1000).toISOString();
  const notOnOrAfter = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  const restrictions = audienceRestrictions
    .map(
      (audiences) =>
        `<saml:AudienceRestriction>${audiences.map((a) => `<saml:Audience>${a}</saml:Audience>`).join('')}</saml:AudienceRestriction>`
    )
    .join('');
  return (
    `<saml:Assertion xmlns:saml="${ASSERTION_NS}" ID="${id}" Version="2.0" IssueInstant="${notBefore}">` +
    `<saml:Issuer>${IDP}</saml:Issuer>` +
    '<saml:Subject>' +
    '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">jo@example.com</saml:NameID>' +
    '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">' +
    `<saml:SubjectConfirmationData InResponseTo="${REQUEST_ID}" NotOnOrAfter="${notOnOrAfter}" Recipient="${ACS}"/>` +
    '</saml:SubjectConfirmation></saml:Subject>' +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">${restrictions}</saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${notBefore}" SessionIndex="_session-1"/>` +
    attributes +
    '</saml:Assertion>'
  );
};

export const buildResponse = (inner: string, status = 'urn:oasis:names:tc:SAML:2.0:status:Success') =>
  `<samlp:Response xmlns:samlp="${PROTOCOL_NS}" xmlns:saml="${ASSERTION_NS}" ID="_response-1" Version="2.0" ` +
  `IssueInstant="${new Date().toISOString()}" Destination="${ACS}" InResponseTo="${REQUEST_ID}">` +
  `<saml:Issuer>${IDP}</saml:Issuer>` +
  `<samlp:Status><samlp:StatusCode Value="${status}"/></samlp:Status>` +
  inner +
  '</samlp:Response>';

export const encryptAssertion = async (assertion: string) => {
  const encrypted = await promisify(xmlenc.encrypt)(assertion, {
    rsa_pub: testIdpCert,
    pem: testIdpCert,
    encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
  });
  return `<saml:EncryptedAssertion>${encrypted}</saml:EncryptedAssertion>`;
};

export const signXml = (xml: string, xPath: string) => sign(xml, testIdpKey, testIdpCert, xPath);
