import { promisify } from 'util';
import xml2js from 'xml2js';
import { inflateRaw } from 'zlib';
import xmlbuilder from 'xmlbuilder';
import { SAMLReq } from './typings';
import crypto from 'crypto';
import { sign } from './sign';

const inflateRawAsync = promisify(inflateRaw);

const idPrefix = '_';
const authnXPath =
  '/*[local-name(.)="AuthnRequest" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';

const request = ({
  ssoUrl,
  entityID,
  callbackUrl,
  isPassive = false,
  forceAuthn = false,
  identifierFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  providerName = 'BoxyHQ',
  signingKey,
  publicKey,
}: SAMLReq): { id: string; request: string } => {
  const id = idPrefix + crypto.randomBytes(10).toString('hex');
  const date = new Date().toISOString();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const samlReq: Record<string, any> = {
    'samlp:AuthnRequest': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': date,
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@Destination': ssoUrl,
      'saml:Issuer': {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': entityID,
      },
    },
  };

  if (isPassive) samlReq['samlp:AuthnRequest']['@IsPassive'] = true;

  if (forceAuthn) {
    samlReq['samlp:AuthnRequest']['@ForceAuthn'] = true;
  }

  samlReq['samlp:AuthnRequest']['@AssertionConsumerServiceURL'] = callbackUrl;

  samlReq['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
    '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    '@Format': identifierFormat,
    '@AllowCreate': 'true',
  };

  if (providerName != null) {
    samlReq['samlp:AuthnRequest']['@ProviderName'] = providerName;
  }

  let xml = xmlbuilder.create(samlReq).end({});
  if (signingKey) {
    xml = sign(xml, {privateKey: signingKey, publicKey, sigLocation: authnXPath});
  }

  return {
    id,
    request: xml,
  };
};

// Parse XML
const parseXML = (xml: string): Promise<Record<string, any>> => {
  return new Promise((resolve, reject) => {
    xml2js.parseString(
      xml,
      {
        tagNameProcessors: [xml2js.processors.stripPrefix],
        strict: true,
      },
      (err: Error | null, result: any) => {
        if (err) {
          reject(err);
        }

        resolve(result);
      }
    );
  });
};

// Decode the base64 string
const decodeBase64 = async (string: string, isDeflated: boolean) => {
  return isDeflated
    ? (await inflateRawAsync(Buffer.from(string, 'base64'))).toString()
    : Buffer.from(string, 'base64').toString();
};

// Parse SAMLRequest attributes
const parseSAMLRequest = async (rawRequest: string, isPost = true) => {
  const result = await parseXML(rawRequest);

  const attributes = result['AuthnRequest']['$'];
  const issuer = result['AuthnRequest']['Issuer'];

  const publicKey = result['AuthnRequest']['Signature']
    ? result['AuthnRequest']['Signature'][0]['KeyInfo'][0]['X509Data'][0]['X509Certificate'][0]
    : null;

  if (!issuer) {
    throw new Error("Missing 'Issuer' in SAML Request.");
  }

  if (!publicKey && isPost) {
    throw new Error('Missing signature');
  }

  return {
    id: attributes.ID,
    acsUrl: attributes.AssertionConsumerServiceURL,
    providerName: attributes.ProviderName,
    audience: issuer[0]['_'] ?? issuer[0], // also known as entityID
    publicKey,
  };
};

export { request, parseSAMLRequest, decodeBase64 };
