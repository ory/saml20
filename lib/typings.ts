export interface SAMLReq {
  ssoUrl?: string;
  entityID: string;
  callbackUrl: string;
  isPassive?: boolean;
  forceAuthn?: boolean;
  identifierFormat?: string;
  providerName?: string;
  signingKey: string;
  publicKey: string;
}

export interface SAMLProfile {
  audience: string;
  claims: Record<string, any>;
  issuer: string;
  sessionIndex: string;
}

/**
 * Configuration options for the encryption process.
 */
export interface EncryptOptions {
  /**
   * The Service Provider's (SP) Public Key or Certificate content.
   * This can be the raw Base64 string found in SAML Metadata <ds:X509Certificate>.
   * It does not need to be in PEM format (headers will be added automatically if missing).
   */
  publicKey: string;

  /**
   * (Optional) The algorithm used to encrypt the assertion data.
   * @default EncryptionAlgorithms.AES256_CBC
   */
  encryptionAlgorithm?: string;

  /**
   * (Optional) The algorithm used to encrypt the key.
   * @default EncryptionAlgorithms.RSA_OAEP_MGF1P
   */
  keyEncryptionAlgorithm?: string;

  /**
   * Allow additional options to be passed directly to the xml-encryption library.
   */
  [key: string]: any;
}

export interface IdpMetadataOptions {
  entityID: string;
  ssoUrl: string;
  sloUrl?: string;
  /**
   * Certificate used for signing the assertions/responses (Public Key).
   * Can be raw string or PEM.
   */
  signingCert: string;
  /**
   * (Optional) Certificate used for encryption (Public Key).
   * If provided, an additional KeyDescriptor with use="encryption" will be added.
   * If not provided, usually the signingCert is used for both or encryption is not advertised.
   */
  encryptionCert?: string;
  nameIDFormat?: string[];
  /**
   * (Optional) Expiration date of the metadata.
   * Will be converted to ISO 8601 format (YYYY-MM-DDThh:mm:ss.sssZ).
   */
  validUntil?: Date;
  encryption?: boolean;
}

export interface SpMetadataOptions {
  entityID: string;
  /**
   * Certificate used for signing the assertions/responses (Public Key).
   * Can be raw string or PEM.
   */
  publicKey: string;
  acsUrl: string;
  encryption?: boolean;
}

export interface SAMLResponseOptions {
  audience: string;
  issuer: string;
  acsUrl: string;
  claims: Record<string, any>;
  requestId?: string;
  signingKey: string;
  publicKey: string;
  flattenArray?: boolean;
  ttlInMinutes?: number;
  encryptionKey?: string;
  encryptionAlgorithm?: string;
  signResponse?: boolean;
}

/**
 * Interface defining the options required to sign a SAML element.
 */
export interface SignOptions {
  /**
   * The private key used for signing (PEM format).
   */
  privateKey: string;

  /**
   * The public key/certificate (PEM format).
   * Required for constructing the <ds:KeyInfo> block via PubKeyInfo.
   */
  publicKey: string;

  /**
   * The XPath expression indicating the location of the element to be signed.
   * Example: "//*[@ID='_123456...']"
   */
  sigLocation: string;
}
