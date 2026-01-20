import { DOMParser, MIME_TYPE } from '@xmldom/xmldom';
import crypto from 'crypto';

const multiRootedXMLError = new Error('multirooted xml not allowed.');

const countRootNodes = (xmlDoc: Document) => {
  const rootNodes = Array.from(xmlDoc.childNodes as NodeListOf<Element>).filter(
    (n) => n.tagName != null && n.childNodes != null
  );
  return rootNodes.length;
};

const parseFromString = (xmlString: string) => {
  const errors: string[] = [];
  let multiRootErrFound = false;
  const onError = (level, msg) => {
    if (isMultiRootedXMLError({ message: msg })) {
      if (!multiRootErrFound) {
        multiRootErrFound = true;
        errors.push(msg);
      }
    } else if (level !== 'warn') {
      if (msg.indexOf('entity not matching Reference production:') < 0) {
        errors.push(msg);
      }
    }
  };
  try {
    const xml = new DOMParser({ onError }).parseFromString(xmlString, MIME_TYPE.XML_APPLICATION);
    if (multiRootErrFound) {
      throw multiRootedXMLError;
    } else if (errors.length > 0) {
      throw new Error('Invalid XML.');
    }

    // @ts-expect-error missing Node properties are not needed
    const rootNodeCount = countRootNodes(xml);
    if (rootNodeCount > 1) {
      throw multiRootedXMLError;
    }

    if (rootNodeCount === 0) {
      throw new Error('Invalid assertion.');
    }

    return xml;
  } catch (err) {
    if (isMultiRootedXMLError(err)) {
      throw multiRootedXMLError;
    } else {
      throw err;
    }
  }
};

const thumbprint = (cert: string) => {
  const shasum = crypto.createHash('sha1');
  const bin = Buffer.from(cert, 'base64').toString('binary');
  shasum.update(bin);
  return shasum.digest('hex');
};

const getAttribute = <TDefault = unknown>(value: any, path: string, defaultValue?: TDefault): TDefault => {
  const segments = path.split(/[\.\[\]]/g); // eslint-disable-line no-useless-escape
  let current: any = value;
  for (const key of segments) {
    if (current === null) return defaultValue as TDefault;
    if (current === undefined) return defaultValue as TDefault;
    const dequoted = key.replace(/['"]/g, '');
    if (dequoted.trim() === '') continue;
    current = current[dequoted];
  }
  if (current === undefined) return defaultValue as TDefault;
  return current;
};

const isMultiRootedXMLError = (err: any) => {
  if ((err as any)?.message?.indexOf('Only one element can be added and only after doctype') >= 0) {
    return true;
  }
  return false;
};

/**
 * Generates a cryptographically strong unique identifier.
 * This is used to create unique IDs for SAML Assertions and Responses.
 *
 * @returns {string} A random hex string (e.g., "_a1b2c3d4...").
 */
const generateUniqueID = (prefix?: string): string => {
  return (prefix ?  prefix + '_' : '_') + crypto.randomBytes(10).toString('hex');
};

export {
  parseFromString,
  thumbprint,
  getAttribute,
  isMultiRootedXMLError,
  multiRootedXMLError,
  generateUniqueID
};
