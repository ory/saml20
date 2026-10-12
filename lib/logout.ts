import xmlbuilder from 'xmlbuilder';
import { generateId } from './utils';
import { xmlToObject } from './xml';
import { ASSERTION_NS, PROTOCOL_NS } from './constants';

type ParsedLogoutResponse = {
  id: string;
  issuer: string;
  status: string;
  destination: string;
  inResponseTo: string;
};

type LogoutRequestParams = {
  nameId: string;
  providerName: string;
  sloUrl: string;
};

// Text content of the first element in a child list. xmlToObject yields a
// plain string for an element without attributes and `{ _: text, $: attrs }`
// for one with attributes (a namespace declaration counts as an attribute).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const textOf = (elements: any): string | undefined => {
  const first = elements?.[0];
  return typeof first === 'string' ? first : first?._;
};

const parseLogoutResponse = async (rawResponse: string): Promise<ParsedLogoutResponse> => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const parsedData: any = xmlToObject(rawResponse, { attrkey: '$' });
  const LogoutResponse = parsedData?.LogoutResponse;

  if (!LogoutResponse) {
    throw new Error('Invalid SAML LogoutResponse: missing LogoutResponse element.');
  }

  const status = LogoutResponse.Status?.[0]?.StatusCode?.[0]?.$?.Value;
  if (!status) {
    throw new Error('Invalid SAML LogoutResponse: missing StatusCode.');
  }

  return {
    issuer: textOf(LogoutResponse.Issuer) as string,
    id: LogoutResponse.$?.ID,
    status,
    destination: LogoutResponse.$?.Destination,
    inResponseTo: LogoutResponse.$?.InResponseTo,
  };
};

const createLogoutRequest = ({
  nameId,
  providerName,
  sloUrl,
}: LogoutRequestParams): { id: string; xml: string } => {
  const id = generateId();

  const xml = {
    'samlp:LogoutRequest': {
      '@xmlns:samlp': PROTOCOL_NS,
      '@xmlns:saml': ASSERTION_NS,
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': new Date().toISOString(),
      '@Destination': sloUrl,
      'saml:Issuer': {
        '#text': providerName,
      },
      'saml:NameID': {
        '@Format': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        '#text': nameId,
      },
    },
  };

  return {
    id,
    xml: xmlbuilder.create(xml).end({}),
  };
};

type ParsedLogoutRequest = {
  id: string;
  issuer: string;
  nameId: string;
  sessionIndex?: string;
  destination?: string;
  /**
   * The request's IssueInstant, as the sender wrote it. A relying party needs it
   * to reject a request that is too old to act on, which a signature alone
   * cannot tell it.
   */
  issueInstant?: string;
  publicKey?: string;
  idToken?: string;
};

type LogoutResponseParams = {
  requestId: string;
  issuer: string;
  destination: string;
  status?: string;
};

const parseLogoutRequest = async (rawRequest: string): Promise<ParsedLogoutRequest> => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const parsedData: any = xmlToObject(rawRequest, { attrkey: '$' });
  // xmlToObject yields null for an empty document and '' for an element with no
  // attributes and no children; neither is a usable LogoutRequest.
  const LogoutRequest = parsedData?.LogoutRequest;

  if (!LogoutRequest) {
    throw new Error('Invalid SAML LogoutRequest: missing LogoutRequest element.');
  }

  const id = LogoutRequest.$?.ID;
  const destination = LogoutRequest.$?.Destination;
  const issueInstant = LogoutRequest.$?.IssueInstant;

  const issuer = textOf(LogoutRequest.Issuer) ?? '';
  const nameId = textOf(LogoutRequest.NameID) ?? '';
  const sessionIndex = textOf(LogoutRequest.SessionIndex);

  // Extract public key from Signature > KeyInfo > X509Data > X509Certificate if present
  let publicKey: string | undefined;
  const signature = LogoutRequest.Signature;
  if (signature) {
    try {
      const keyInfo = signature[0]?.KeyInfo?.[0];
      const x509Data = keyInfo?.X509Data?.[0];
      const x509Cert = x509Data?.X509Certificate?.[0];
      if (x509Cert) {
        publicKey = typeof x509Cert === 'string' ? x509Cert : x509Cert._;
      }
    } catch {
      // Signature parsing is best-effort
    }
  }

  // Extract id_token from Extensions > IdToken if present
  // The SP can embed the OIDC id_token inside the LogoutRequest so it is
  // covered by the XML signature.
  let idToken: string | undefined;
  const extensions = LogoutRequest.Extensions;
  if (extensions) {
    try {
      const idTokenElement = extensions[0]?.Attribute?.[0];
      if (idTokenElement && idTokenElement.$ && idTokenElement.$.Name === 'id_token') {
        const attrVal = idTokenElement.AttributeValue[0];
        idToken = typeof attrVal === 'string' ? attrVal : attrVal._;
      }
    } catch {
      // Extensions parsing is best-effort
    }
  }

  return {
    id,
    issuer,
    nameId,
    sessionIndex,
    destination,
    issueInstant,
    publicKey,
    idToken,
  };
};

const createLogoutResponse = ({
  requestId,
  issuer,
  destination,
  status = 'urn:oasis:names:tc:SAML:2.0:status:Success',
}: LogoutResponseParams): { id: string; xml: string } => {
  const id = generateId();

  const xml = {
    'samlp:LogoutResponse': {
      '@xmlns:samlp': PROTOCOL_NS,
      '@xmlns:saml': ASSERTION_NS,
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': new Date().toISOString(),
      '@Destination': destination,
      '@InResponseTo': requestId,
      'saml:Issuer': {
        '#text': issuer,
      },
      'samlp:Status': {
        'samlp:StatusCode': {
          '@Value': status,
        },
      },
    },
  };

  return {
    id,
    xml: xmlbuilder.create(xml).end({}),
  };
};

export { parseLogoutResponse, createLogoutRequest, parseLogoutRequest, createLogoutResponse };

export type { ParsedLogoutResponse, LogoutRequestParams, ParsedLogoutRequest, LogoutResponseParams };
