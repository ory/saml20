const stripCertHeaderAndFooter = (cert: string): string => {
  cert = cert.replace(/-+BEGIN CERTIFICATE-+\r?\n?/, '');
  cert = cert.replace(/-+END CERTIFICATE-+\r?\n?/, '');
  cert = cert.replace(/\r\n/g, '\n');
  return cert.trimEnd();
};

const BEGIN = '-----BEGIN CERTIFICATE-----';
const END = '-----END CERTIFICATE-----';

// Wrap a bare base64 certificate in PEM armor, split into 64-character lines.
// A string that already mentions BEGIN or END CERTIFICATE is returned as is.
const certToPEM = (cert: string): string => {
  if (cert.indexOf('BEGIN CERTIFICATE') === -1 && cert.indexOf('END CERTIFICATE') === -1) {
    cert = cert.match(/.{1,64}/g)!.join('\n');
    cert = '-----BEGIN CERTIFICATE-----\n' + cert;
    cert = cert + '\n-----END CERTIFICATE-----\n';
    return cert;
  } else {
    return cert;
  }
};

// Add whichever of the BEGIN/END lines is missing, without reflowing the body.
// crypto.X509Certificate needs both; metadata certificates arrive with
// neither, one or both.
const ensurePemArmor = (cert: string): string => {
  let pem = cert.trim();
  if (!pem.includes(BEGIN)) {
    pem = `${BEGIN}\n${pem}`;
  }
  if (!pem.includes(END)) {
    pem = `${pem}\n${END}`;
  }
  return pem;
};

function PubKeyInfo(pubKey: string) {
  const pubKeyTrimmed = stripCertHeaderAndFooter(pubKey);

  return function ({ prefix }) {
    prefix = prefix || '';
    prefix = prefix ? prefix + ':' : prefix;
    return `<${prefix}X509Data><${prefix}X509Certificate>${pubKeyTrimmed}</${prefix}X509Certificate></${prefix}X509Data>`;
  };
}

export { stripCertHeaderAndFooter, PubKeyInfo, certToPEM, ensurePemArmor };
