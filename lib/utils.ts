import { DOMParser, MIME_TYPE } from '@xmldom/xmldom';
import crypto from 'crypto';

// An error that keeps the underlying failure in `inner` while presenting a
// fixed, caller-safe message.
class WrapError extends Error {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  inner?: any;
}

const multiRootedXMLError = new Error('multirooted xml not allowed.');
const doctypeNotAllowedError = new Error('doctype not allowed.');

// Detects a document type definition (DTD) in a raw XML string. A DOCTYPE has
// no legitimate place in SAML XML and accepting one is an XXE-class risk, so
// parseFromString rejects any document this matches before parsing it. See
// https://github.com/ory/polis/issues/4071.
//
// The keywords are matched anywhere, including inside comments and CDATA:
// skipping those would mean reproducing a parser's error-recovery tokenizer,
// and every attempt at that has been bypassable. A false positive can only be
// a comment or CDATA that mentions a DTD keyword, and rejecting it fails safe.
const dtdDeclaration = /<!DOCTYPE|<!ENTITY|<!ELEMENT/i;

const containsDoctype = (xml: string): boolean => dtdDeclaration.test(xml);

const countRootNodes = (xmlDoc: Document) => {
  const rootNodes = Array.from(xmlDoc.childNodes as NodeListOf<Element>).filter(
    (n) => n.tagName != null && n.childNodes != null
  );
  return rootNodes.length;
};

// `xmlns` declares namespace prefixes the document may use without declaring.
const parseFromString = (xmlString: string, xmlns?: Record<string, string>) => {
  // Reject a DTD before the parser processes it. Checking only the parsed
  // `doctype` node (below) lets a malformed DTD make @xmldom/xmldom throw first,
  // leaking raw parser text (e.g. "doctype not terminated with > at position N")
  // instead of the fixed error. See https://github.com/ory/polis/issues/4071.
  if (containsDoctype(xmlString)) {
    throw doctypeNotAllowedError;
  }

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
    const xml = new DOMParser({ onError, xmlns }).parseFromString(xmlString, MIME_TYPE.XML_APPLICATION);

    // SAML XML never legitimately declares a document type definition (DTD).
    // Accepting one exposes the parser to XXE-class attacks: a DTD can declare
    // entities and its handling makes parser behaviour observable as an oracle.
    // Reject any document that declares a DOCTYPE. See
    // https://github.com/ory/polis/issues/4071.
    if (xml.doctype) {
      throw doctypeNotAllowedError;
    }

    if (multiRootErrFound) {
      throw multiRootedXMLError;
    } else if (errors.length > 0) {
      throw new Error('Invalid XML.');
    }

    // Defence in depth: with the current @xmldom/xmldom, a second root element
    // or a missing root is already rejected while parsing (and a DOCTYPE by
    // containsDoctype), so neither these root-count checks nor the parsed
    // `doctype` check above fire today. They stay so that a parser change
    // cannot quietly let such a document through: multiple roots are a
    // signature-wrapping vector.
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

// A SAML message or assertion ID: '_' (an xs:ID must not start with a digit)
// followed by 80 random bits as hex.
const generateId = () => '_' + crypto.randomBytes(10).toString('hex');

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

export {
  WrapError,
  generateId,
  parseFromString,
  thumbprint,
  getAttribute,
  multiRootedXMLError,
  doctypeNotAllowedError,
  containsDoctype,
};
