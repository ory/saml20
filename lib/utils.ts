import { DOMParser, MIME_TYPE } from '@xmldom/xmldom';
import crypto from 'crypto';

const multiRootedXMLError = new Error('multirooted xml not allowed.');
const doctypeNotAllowedError = new Error('doctype not allowed.');

// Detects a document type definition (DTD) declaration in a raw XML string.
// `parseFromString` rejects a DTD via the parsed `doctype` node, but xml2js/sax
// does not expose one, so its callers screen the raw string with this instead.
// A DOCTYPE has no legitimate place in SAML XML and accepting one is an
// XXE-class risk. See https://github.com/ory/polis/issues/4071.
//
// Comments, CDATA sections and processing instructions are removed first so
// that a `<!DOCTYPE` appearing as text inside them (e.g. in an AttributeValue or
// a `<?pi ...?>`) is not mistaken for a real declaration. A genuine DOCTYPE only
// appears in the prolog and never inside those regions, so stripping them never
// hides a real one. The trailing `\s` matches the whitespace the XML grammar
// requires after `<!DOCTYPE` (`'<!DOCTYPE' S Name`).
const containsDoctype = (xml: string): boolean => {
  const withoutInertRegions = xml
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, '')
    .replace(/<\?[\s\S]*?\?>/g, '');
  return /<!DOCTYPE\s/i.test(withoutInertRegions);
};

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

export {
  parseFromString,
  thumbprint,
  getAttribute,
  isMultiRootedXMLError,
  multiRootedXMLError,
  doctypeNotAllowedError,
  containsDoctype,
};
