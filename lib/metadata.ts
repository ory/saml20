import { getAttribute, thumbprint, containsDoctype, doctypeNotAllowedError } from './utils';
import { ensurePemArmor, stripCertHeaderAndFooter } from './cert';

import crypto from 'crypto';
import xml2js from 'xml2js';
import xmlbuilder from 'xmlbuilder';
import { METADATA_NS, PROTOCOL_NS, XMLDSIG_NS } from './constants';

type ParseMetadataOptions = {
  // Reject the metadata unless every SSO descriptor lists this NameIDFormat.
  validateNameIDFormat?: string;
};

type MetadataEndpoints = { postUrl?: string; redirectUrl?: string };

type ParsedMetadata = {
  // HTTP-POST and HTTP-Redirect SingleSignOnService (or, for SP metadata,
  // AssertionConsumerService) locations.
  sso: MetadataEndpoints;
  slo: MetadataEndpoints;
  entityID?: string;
  // Signing certificates, comma-separated, with their SHA-1 thumbprints and
  // expiry dates in the same order.
  publicKey?: string;
  thumbprint?: string;
  validTo?: string;
  // 'idp' for an IDPSSODescriptor, 'sp' for an SPSSODescriptor.
  loginType: 'idp' | 'sp';
};

const parseMetadata = async (
  idpMeta: string,
  validateOpts: ParseMetadataOptions = {}
): Promise<ParsedMetadata> => {
  // Some Providers do not escape the & character in the metadata, for now these have been encountered in errorURL
  idpMeta = idpMeta.replace(/errorURL=".*?"/g, '');
  if (containsDoctype(idpMeta)) {
    throw doctypeNotAllowedError;
  }
  const res = await xml2js.parseStringPromise(idpMeta, {
    tagNameProcessors: [xml2js.processors.stripPrefix],
    strict: true,
  });
  const entityID = getAttribute<string | undefined>(res, 'EntityDescriptor.$.entityID');
  let X509Certificates: string[] = [];
  const X509CertificatesWithoutSigningAttr: string[] = [];
  let ssoPostUrl: string | undefined;
  let ssoRedirectUrl: string | undefined;
  let loginType: ParsedMetadata['loginType'] = 'idp';
  let sloRedirectUrl: string | undefined;
  let sloPostUrl: string | undefined;

  let ssoDes: any = getAttribute(res, 'EntityDescriptor.IDPSSODescriptor', null);
  if (!ssoDes) {
    ssoDes = getAttribute(res, 'EntityDescriptor.SPSSODescriptor', []);
    if (ssoDes.length > 0) {
      loginType = 'sp';
    }
  }

  for (const ssoDesRec of ssoDes) {
    const keyDes = ssoDesRec['KeyDescriptor'] || [];
    for (const keyDesRec of keyDes) {
      const ki = keyDesRec['KeyInfo']?.[0];
      const cd = ki?.['X509Data']?.[0];
      const x509cert = cd?.['X509Certificate']?.[0];
      if (keyDesRec['$'] && keyDesRec['$'].use === 'signing') {
        if (x509cert) {
          X509Certificates.push(x509cert);
        }
      } else {
        if (x509cert) {
          X509CertificatesWithoutSigningAttr.push(x509cert);
        }
      }
    }

    const ssoSvc = ssoDesRec['SingleSignOnService'] || ssoDesRec['AssertionConsumerService'] || [];
    for (const ssoSvcRec of ssoSvc) {
      if (getAttribute(ssoSvcRec, '$.Binding', '').endsWith('HTTP-POST')) {
        ssoPostUrl = getAttribute<string>(ssoSvcRec, '$.Location');
      } else if (getAttribute(ssoSvcRec, '$.Binding', '').endsWith('HTTP-Redirect')) {
        ssoRedirectUrl = getAttribute<string>(ssoSvcRec, '$.Location');
      }
    }

    const sloSvc = ssoDesRec['SingleLogoutService'] || [];
    for (const sloSvcRec of sloSvc) {
      if (getAttribute(sloSvcRec, '$.Binding', '').endsWith('HTTP-Redirect')) {
        sloRedirectUrl = getAttribute<string>(sloSvcRec, '$.Location');
      } else if (getAttribute(sloSvcRec, '$.Binding', '').endsWith('HTTP-POST')) {
        sloPostUrl = getAttribute<string>(sloSvcRec, '$.Location');
      }
    }

    if (validateOpts?.validateNameIDFormat) {
      let validNameIDFormat = false;
      const nameIDFormats = ssoDesRec['NameIDFormat'] || [];
      for (const nameIDFormat of nameIDFormats) {
        if (validateOpts?.validateNameIDFormat === nameIDFormat) {
          validNameIDFormat = true;
        }
      }

      if (!validNameIDFormat) {
        throw new Error(
          `Invalid nameIDFormat. Please set 'Name ID Format' to ${validateOpts.validateNameIDFormat}`
        );
      }
    }
  }

  if (X509Certificates.length === 0) {
    if (X509CertificatesWithoutSigningAttr.length !== 0) {
      X509Certificates = X509CertificatesWithoutSigningAttr;
    } else {
      throw new Error(`Could not find X509Certificate in the IdP metadata.`);
    }
  }

  // Built field by field so that only the fields that were found are set.
  const ret = {
    sso: {},
    slo: {},
  } as ParsedMetadata;

  if (entityID) {
    ret.entityID = entityID;
  }

  const tPrints: string[] = [];
  const validTos: string[] = [];
  for (const X509Certificate of X509Certificates) {
    tPrints.push(thumbprint(X509Certificate));
    validTos.push(new crypto.X509Certificate(ensurePemArmor(X509Certificate)).validTo);
  }

  if (X509Certificates.length > 0) {
    ret.publicKey = X509Certificates.map((_) => _.trim()).join(',');
  }

  if (tPrints.length > 0) {
    ret.thumbprint = tPrints.join(',');
  }
  if (validTos.length > 0) {
    ret.validTo = validTos.join(',');
  }

  if (ssoPostUrl) {
    ret.sso.postUrl = ssoPostUrl;
  }

  if (ssoRedirectUrl) {
    ret.sso.redirectUrl = ssoRedirectUrl;
  }

  if (sloRedirectUrl) {
    ret.slo.redirectUrl = sloRedirectUrl;
  }

  if (sloPostUrl) {
    ret.slo.postUrl = sloPostUrl;
  }

  ret.loginType = loginType;

  return ret;
};

const createIdPMetadataXML = ({
  ssoUrl,
  sloUrl,
  entityId,
  x509cert,
  wantAuthnRequestsSigned,
}: {
  ssoUrl: string;
  sloUrl?: string;
  entityId: string;
  x509cert: string;
  wantAuthnRequestsSigned: boolean;
}): string => {
  x509cert = stripCertHeaderAndFooter(x509cert);

  const today = new Date();
  const nodes = {
    'md:EntityDescriptor': {
      '@xmlns:md': METADATA_NS,
      '@entityID': entityId,
      '@validUntil': new Date(today.setFullYear(today.getFullYear() + 10)).toISOString(),
      'md:IDPSSODescriptor': {
        '@WantAuthnRequestsSigned': wantAuthnRequestsSigned,
        '@protocolSupportEnumeration': PROTOCOL_NS,
        'md:KeyDescriptor': {
          '@use': 'signing',
          'ds:KeyInfo': {
            '@xmlns:ds': XMLDSIG_NS,
            'ds:X509Data': {
              'ds:X509Certificate': {
                '#text': x509cert,
              },
            },
          },
        },
        'md:NameIDFormat': {
          '#text': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        },
        'md:SingleSignOnService': [
          {
            '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            '@Location': ssoUrl,
          },
          {
            '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            '@Location': ssoUrl,
          },
        ],
        ...(sloUrl
          ? {
              'md:SingleLogoutService': [
                {
                  '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                  '@Location': sloUrl,
                },
                {
                  '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                  '@Location': sloUrl,
                },
              ],
            }
          : {}),
      },
    },
  };

  return xmlbuilder.create(nodes, { encoding: 'UTF-8', standalone: false }).end({ pretty: true });
};

const createSPMetadataXML = ({
  entityId,
  publicKeyString,
  acsUrl,
  encryption,
  authnRequestsSigned = false,
}: {
  entityId: string;
  publicKeyString: string;
  acsUrl: string;
  encryption: boolean;
  authnRequestsSigned?: boolean;
}): string => {
  // Like createIdPMetadataXML, accept a PEM string: X509Certificate must carry
  // only the base64 body, not the BEGIN/END lines.
  const x509cert = stripCertHeaderAndFooter(publicKeyString);
  const today = new Date();

  const keyDescriptor: any[] = [
    {
      '@use': 'signing',
      'ds:KeyInfo': {
        '@xmlns:ds': XMLDSIG_NS,
        'ds:X509Data': {
          'ds:X509Certificate': {
            '#text': x509cert,
          },
        },
      },
    },
  ];

  if (encryption) {
    keyDescriptor.push({
      '@use': 'encryption',
      'ds:KeyInfo': {
        '@xmlns:ds': XMLDSIG_NS,
        'ds:X509Data': {
          'ds:X509Certificate': {
            '#text': x509cert,
          },
        },
      },
      'md:EncryptionMethod': {
        '@Algorithm': 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
      },
    });
  }

  const nodes = {
    'md:EntityDescriptor': {
      '@xmlns:md': METADATA_NS,
      '@entityID': entityId,
      '@validUntil': new Date(today.setFullYear(today.getFullYear() + 10)).toISOString(),
      'md:SPSSODescriptor': {
        ...(authnRequestsSigned ? { '@AuthnRequestsSigned': true } : {}),
        '@protocolSupportEnumeration': PROTOCOL_NS,
        'md:KeyDescriptor': keyDescriptor,
        'md:NameIDFormat': {
          '#text': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        },
        'md:AssertionConsumerService': {
          '@index': 1,
          '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
          '@Location': acsUrl,
        },
      },
    },
  };

  return xmlbuilder.create(nodes, { encoding: 'UTF-8', standalone: false }).end({ pretty: true });
};

export { parseMetadata, createIdPMetadataXML, createSPMetadataXML };
export type { ParseMetadataOptions, ParsedMetadata, MetadataEndpoints };
