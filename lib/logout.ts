import crypto from 'crypto';
import xml2js from 'xml2js';
import xmlbuilder from 'xmlbuilder';

const parseLogoutResponse = async (
  rawResponse: string
): Promise<{
  id: string;
  issuer: string;
  status: string;
  destination: string;
  inResponseTo: string;
}> => {
  return new Promise((resolve, reject) => {
    xml2js.parseString(
      rawResponse,
      { tagNameProcessors: [xml2js.processors.stripPrefix] },
      (err: Error | null, parsedData: { LogoutResponse: any }) => {
        if (err) {
          reject(err);
          return;
        }
        const { LogoutResponse } = parsedData;

        resolve({
          issuer: LogoutResponse.Issuer[0]._,
          id: LogoutResponse.$.ID,
          status: LogoutResponse.Status[0].StatusCode[0].$.Value,
          destination: LogoutResponse.$.Destination,
          inResponseTo: LogoutResponse.$.InResponseTo,
        });
      }
    );
  });
};

const createLogoutRequest = ({
  nameId,
  providerName,
  sloUrl,
}: {
  nameId: string;
  providerName: string;
  sloUrl: string;
}): { id: string; xml: string } => {
  const id = '_' + crypto.randomBytes(10).toString('hex');

  const xml: Record<string, any> = {
    'samlp:LogoutRequest': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
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
  publicKey?: string;
  idToken?: string;
};

type LogoutResponseParams = {
  requestId: string;
  issuer: string;
  destination: string;
  status?: string;
};

/**
 * Parse a SAML 2.0 LogoutRequest XML and extract key fields.
 */
const parseLogoutRequest = async (rawRequest: string): Promise<ParsedLogoutRequest> => {
  return new Promise((resolve, reject) => {
    xml2js.parseString(
      rawRequest,
      { tagNameProcessors: [xml2js.processors.stripPrefix] },
      (err, parsedData) => {
        if (err) {
          reject(err);
          return;
        }

        const { LogoutRequest } = parsedData;

        if (!LogoutRequest) {
          reject(new Error('Invalid SAML LogoutRequest: missing LogoutRequest element.'));
          return;
        }

        const id = LogoutRequest.$.ID;
        const destination = LogoutRequest.$.Destination;

        const issuerElement = LogoutRequest.Issuer;
        const issuer = issuerElement
          ? typeof issuerElement[0] === 'string'
            ? issuerElement[0]
            : issuerElement[0]._
          : '';

        const nameIdElement = LogoutRequest.NameID;
        const nameId = nameIdElement
          ? typeof nameIdElement[0] === 'string'
            ? nameIdElement[0]
            : nameIdElement[0]._
          : '';

        const sessionIndexElement = LogoutRequest.SessionIndex;
        const sessionIndex = sessionIndexElement
          ? typeof sessionIndexElement[0] === 'string'
            ? sessionIndexElement[0]
            : sessionIndexElement[0]._
          : undefined;

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
            const idTokenElement = extensions[0]?.IdToken?.[0];
            if (idTokenElement) {
              idToken = typeof idTokenElement === 'string' ? idTokenElement : idTokenElement._;
            }
          } catch {
            // Extensions parsing is best-effort
          }
        }

        resolve({
          id,
          issuer,
          nameId,
          sessionIndex,
          destination,
          publicKey,
          idToken,
        });
      }
    );
  });
};

/**
 * Create a SAML 2.0 LogoutResponse XML string.
 */
const createLogoutResponse = ({
  requestId,
  issuer,
  destination,
  status = 'urn:oasis:names:tc:SAML:2.0:status:Success',
}: LogoutResponseParams): { id: string; xml: string } => {
  const id = '_' + crypto.randomBytes(10).toString('hex');

  const xml = {
    'samlp:LogoutResponse': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
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

export type { ParsedLogoutRequest, LogoutResponseParams };
