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
