import assert from 'assert';
import fs from 'fs';
import path from 'path';
import * as root from '../../lib/index';

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf8'));

// The package root is the whole public API: adding to this list is a feature,
// removing from it is a breaking change.
const api = [
  'DEFAULT_MAX_SIGNATURE_REFERENCES',
  'MAX_ENCODED_REQUEST_LENGTH',
  'MAX_INFLATED_REQUEST_BYTES',
  'WrapError',
  'certToPEM',
  'containsDoctype',
  'createIdPMetadataXML',
  'createLogoutRequest',
  'createLogoutResponse',
  'createPostForm',
  'createSAMLResponse',
  'createSPMetadataXML',
  'decodeBase64',
  'parseIssuer',
  'parseLogoutRequest',
  'parseLogoutResponse',
  'parseMetadata',
  'parseSAMLRequest',
  'request',
  'samlRequestDecodeError',
  'samlRequestTooLargeError',
  'sign',
  'stripCertHeaderAndFooter',
  'validate',
  'validateSignature',
];

describe('public API', function () {
  it('the package root has exactly these named exports', function () {
    assert.deepStrictEqual(
      Object.keys(root)
        .filter((key) => key !== 'default')
        .sort(),
      api
    );
  });

  it('the default export has exactly the same keys', function () {
    assert.deepStrictEqual(Object.keys(root.default).sort(), api);
  });

  it('package.json exports only the package root', function () {
    assert.deepStrictEqual(pkg.exports, {
      '.': { types: './dist/index.d.ts', default: './dist/index.js' },
      './package.json': './package.json',
    });
    assert.strictEqual(pkg.exports['.'].types, `./${pkg.types}`);
    assert.strictEqual(pkg.exports['.'].default, `./${pkg.main}`);
  });

  it('a module inside the package cannot be imported', function () {
    // Resolved through the package's own name, so Node applies the exports map.
    assert.throws(() => require.resolve(`${pkg.name}/dist/typings`), {
      code: 'ERR_PACKAGE_PATH_NOT_EXPORTED',
    });
    assert.throws(() => require.resolve(`${pkg.name}/dist/validateSignature`), {
      code: 'ERR_PACKAGE_PATH_NOT_EXPORTED',
    });
  });
});
