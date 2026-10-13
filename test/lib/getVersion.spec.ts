import assert from 'assert';
import * as version from '../../lib/getVersion';

describe('getVersion.ts', function () {
  it('getVersion not ok', function () {
    assert.strictEqual(version.getVersion(undefined), null);
  });

  it('getVersion not 2.0', function () {
    assert.strictEqual(version.getVersion({ '@': { Version: '1.1' } }), null);
  });
});

describe('getVersion without attributes', function () {
  it('returns null for an assertion that has no attributes', function () {
    assert.strictEqual(version.getVersion({ Issuer: 'https://idp' }), null);
  });
});
