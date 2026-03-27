import { getAttribute } from './utils';
import { thumbprint } from './utils';
import { stripCertHeaderAndFooter } from './cert';

import crypto from 'crypto';
import xml2js from 'xml2js';
import xmlbuilder from 'xmlbuilder';

const BEGIN = '-----BEGIN CERTIFICATE-----';
const END = '-----END CERTIFICATE-----';

const parseMetadata = async (idpMeta: string, validateOpts): Promise<Record<string, any>> => {
  return new Promise((resolve, reject) => {
    // Some Providers do not escape the & character in the metadata, for now these have been encountered in errorURL
    idpMeta = idpMeta.replace(/errorURL=".*?"/g, '');
    xml2js.parseString(
      idpMeta,
      {
        tagNameProcessors: [xml2js.processors.stripPrefix],
        strict: true,
      },
      (err, res) => {
        if (err) {
          reject(err);
          return;
        }

        const entityID = getAttribute(res, 'EntityDescriptor.$.entityID');
        let X509Certificates: string[] = [];
        const X509CertificatesWithoutSigningAttr: string[] = [];
        let ssoPostUrl: null | undefined = null;
        let ssoRedirectUrl: null | undefined = null;
        let loginType = 'idp';
        let sloRedirectUrl: null | undefined = null;
        let sloPostUrl: null | undefined = null;

        let ssoDes: any = getAttribute(res, 'EntityDescriptor.IDPSSODescriptor', null);
        if (!ssoDes) {
          ssoDes = getAttribute(res, 'EntityDescriptor.SPSSODescriptor', []);
          if (ssoDes.length > 0) {
            loginType = 'sp';
          }
        }

        for (const ssoDesRec of ssoDes) {
          const keyDes = ssoDesRec['KeyDescriptor'];
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
              ssoPostUrl = getAttribute(ssoSvcRec, '$.Location');
            } else if (getAttribute(ssoSvcRec, '$.Binding', '').endsWith('HTTP-Redirect')) {
              ssoRedirectUrl = getAttribute(ssoSvcRec, '$.Location');
            }
          }

          const sloSvc = ssoDesRec['SingleLogoutService'] || [];
          for (const sloSvcRec of sloSvc) {
            if (getAttribute(sloSvcRec, '$.Binding', '').endsWith('HTTP-Redirect')) {
              sloRedirectUrl = getAttribute(sloSvcRec, '$.Location');
            } else if (getAttribute(sloSvcRec, '$.Binding', '').endsWith('HTTP-POST')) {
              sloPostUrl = getAttribute(sloSvcRec, '$.Location');
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
              reject(
                new Error(
                  `Invalid nameIDFormat. Please set 'Name ID Format' to ${validateOpts?.nameIDFormat}`
                )
              );
              return;
            }
          }
        }

        if (X509Certificates.length === 0) {
          if (X509CertificatesWithoutSigningAttr.length !== 0) {
            X509Certificates = X509CertificatesWithoutSigningAttr;
          } else {
            reject(new Error(`Could not find X509Certificate in the IdP metadata.`));
          }
        }

        const ret: Record<string, any> = {
          sso: {},
          slo: {},
        };

        if (entityID) {
          ret.entityID = entityID;
        }

        const tPrints: string[] = [];
        const validTos: string[] = [];
        for (const X509Certificate of X509Certificates) {
          tPrints.push(thumbprint(X509Certificate));
          /**
           * new crypto.X509Certificate fails with the X509Certificate cert without
           * -----BEGIN CERTIFICATE-----
           * and
           * -----END CERTIFICATE-----
           */
          if (X509Certificate.indexOf(BEGIN) != -1 && X509Certificate.indexOf(END) != -1) {
            const { validTo } = new crypto.X509Certificate(X509Certificate.trim());
            validTos.push(validTo);
          } else if (X509Certificate.indexOf(BEGIN) == -1 && X509Certificate.indexOf(END) != -1) {
            /**
             * Prefixing -----BEGIN CERTIFICATE-----
             */
            const { validTo } = new crypto.X509Certificate(`${BEGIN}\n${X509Certificate.trim()}`);
            validTos.push(validTo);
          } else if (X509Certificate.indexOf(BEGIN) != -1 && X509Certificate.indexOf(END) == -1) {
            /**
             * Suffixing -----END CERTIFICATE-----
             */
            const { validTo } = new crypto.X509Certificate(`${X509Certificate.trim()}\n${END}`);
            validTos.push(validTo);
          } else {
            /**
             * Prefixing -----BEGIN CERTIFICATE----- and suffixing -----END CERTIFICATE-----
             */
            const { validTo } = new crypto.X509Certificate(`${BEGIN}\n${X509Certificate.trim()}\n${END}`);
            validTos.push(validTo);
          }
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

        resolve(ret);
      }
    );
  });
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
      '@xmlns:md': 'urn:oasis:names:tc:SAML:2.0:metadata',
      '@entityID': entityId,
      '@validUntil': new Date(today.setFullYear(today.getFullYear() + 10)).toISOString(),
      'md:IDPSSODescriptor': {
        '@WantAuthnRequestsSigned': wantAuthnRequestsSigned,
        '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'md:KeyDescriptor': {
          '@use': 'signing',
          'ds:KeyInfo': {
            '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
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
  const today = new Date();

  const keyDescriptor: any[] = [
    {
      '@use': 'signing',
      'ds:KeyInfo': {
        '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
        'ds:X509Data': {
          'ds:X509Certificate': {
            '#text': publicKeyString,
          },
        },
      },
    },
  ];

  if (encryption) {
    keyDescriptor.push({
      '@use': 'encryption',
      'ds:KeyInfo': {
        '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
        'ds:X509Data': {
          'ds:X509Certificate': {
            '#text': publicKeyString,
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
      '@xmlns:md': 'urn:oasis:names:tc:SAML:2.0:metadata',
      '@entityID': entityId,
      '@validUntil': new Date(today.setFullYear(today.getFullYear() + 10)).toISOString(),
      'md:SPSSODescriptor': {
        ...(authnRequestsSigned ? { '@AuthnRequestsSigned': true } : {}),
        '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:2.0:protocol',
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
