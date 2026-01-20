import * as xmlenc from 'xml-encryption';

/**
 * Enumeration of standard XML Encryption algorithms used in SAML 2.0.
 */
export const EncryptionAlgorithms = {
  /**
   * Block encryption algorithm (AES-128 in CBC mode).
   */
  AES128_CBC: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc',

  /**
   * Block encryption algorithm (AES-256 in CBC mode).
   * @description Standard algorithm often used in legacy SAML implementations.
   */
  AES256_CBC: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',

  /**
   * Authenticated encryption algorithm (AES-256 in GCM mode).
   * @description Recommended for modern implementations (requires Node.js 10+).
   * Provides both confidentiality and data integrity.
   */
  AES256_GCM: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',

  /**
   * Key transport algorithm (RSA-OAEP with MGF1).
   * @description The standard algorithm for encrypting the symmetric key using the SP's public key.
   */
  RSA_OAEP_MGF1P: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
};

/**
 * Configuration options for the encryption process.
 */
export interface IEncryptOptions {
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

/**
 * Helper function to ensure the key is in valid PEM format.
 * SAML Metadata usually provides keys as raw Base64 strings without headers.
 * This function adds the standard BEGIN/END CERTIFICATE headers if they are missing.
 *
 * @param key - The raw key string or already formatted PEM.
 * @returns A properly formatted PEM string.
 */
const formatAsPem = (key: string): string => {
  const raw = key.trim();
  if (raw.startsWith('-----BEGIN')) {
    return raw;
  }

  const cleanKey = raw.replace(/\s+/g, '');

  const chunked = cleanKey.match(/.{1,64}/g)?.join('\n');

  return `-----BEGIN CERTIFICATE-----\n${chunked}\n-----END CERTIFICATE-----`;
};

/**
 * Encrypts a raw SAML Assertion XML string according to SAML 2.0 standards.
 * * @param {string} rawAssertion - The signed or raw XML Assertion string to be encrypted.
 * @param {IEncryptOptions} options - Configuration object containing the public key (raw string) and algorithms.
 * @returns {Promise<string>} A promise that resolves to the fully encrypted XML string wrapped in <saml:EncryptedAssertion>.
 */
export const encryptAssertion = (rawAssertion: string, options: IEncryptOptions): Promise<string> => {
  return new Promise((resolve, reject) => {
    try {
      // Ensure the public key is in valid PEM format before passing to the library
      const validPemKey = formatAsPem(options.publicKey);

      const encAlgo = options.encryptionAlgorithm || EncryptionAlgorithms.AES256_CBC;
      const keyAlgo = options.keyEncryptionAlgorithm || EncryptionAlgorithms.RSA_OAEP_MGF1P;

      const encryptOptions: any = {
        rsa_pub: validPemKey,
        pem: validPemKey,
        encryptionAlgorithm: encAlgo,
        keyEncryptionAlgorithm: keyAlgo,
        disig: true, // Adds <ds:KeyInfo> structure
        warn: false,
        ...options,
      };

      xmlenc.encrypt(rawAssertion, encryptOptions, (err, result) => {
        if (err) {
          return reject(new Error(`SAML Encryption failed: ${err.message}`));
        }

        /**
         * The xml-encryption library returns the <xenc:EncryptedData> element.
         * According to the SAML XSD, this must be wrapped inside a <saml:EncryptedAssertion> element.
         * * Structure:
         * <saml:EncryptedAssertion>
         * <xenc:EncryptedData>
         * <xenc:EncryptionMethod />
         * <ds:KeyInfo>
         * <xenc:EncryptedKey> ... </xenc:EncryptedKey>
         * </ds:KeyInfo>
         * <xenc:CipherData> ... </xenc:CipherData>
         * </xenc:EncryptedData>
         * </saml:EncryptedAssertion>
         */
        const wrappedAssertion = `
<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
${result}
</saml:EncryptedAssertion>`;

        resolve(wrappedAssertion.trim());
      });
    } catch (error: any) {
      reject(new Error(`Pre-encryption setup failed: ${error.message}`));
    }
  });
};
