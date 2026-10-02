// KeyStore port: the shared contract against the memory and file adapters, plus file specifics
// (persistence, atomic writes, corruption handling).
import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { FileKeyStore, InMemoryKeyStore, isAuthError } from '../../src/index.js';
import { hmacMaterial, keyStoreContract } from '../support/keyStoreContract.js';

let dir: string;
let files = 0;
before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'aegis-keys-'));
});
after(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe('KeyStore contract — memory', () => {
  keyStoreContract(async () => ({ store: new InMemoryKeyStore(), dispose: async () => undefined }));
});

describe('KeyStore contract — file', () => {
  keyStoreContract(async () => ({
    store: new FileKeyStore(join(dir, `contract-${++files}.json`)),
    dispose: async () => undefined,
  }));
});

describe('FileKeyStore specifics', () => {
  it('keys survive a "restart" (a new instance over the same file)', async () => {
    const path = join(dir, 'restart.json');
    const a = new FileKeyStore(path);
    const m = hmacMaterial();
    await a.createKey(m, { createdAt: 1 });
    await a.activate(m.kid, 2);
    const b = new FileKeyStore(path);
    assert.equal((await b.getActiveKey())?.kid, m.kid);
  });

  it('writes atomically and leaves no temporary files behind', async () => {
    const sub = join(dir, 'atomic');
    await rm(sub, { recursive: true, force: true });
    await (await import('node:fs/promises')).mkdir(sub);
    const s = new FileKeyStore(join(sub, 'keys.json'));
    for (let i = 0; i < 5; i++) await s.createKey(hmacMaterial(), { createdAt: i });
    assert.deepEqual(await readdir(sub), ['keys.json']);
  });

  it('a failed atomically block leaves the file untouched', async () => {
    const path = join(dir, 'untouched.json');
    const s = new FileKeyStore(path);
    await s.createKey(hmacMaterial(), { createdAt: 1 });
    const before = await readFile(path, 'utf8');
    await assert.rejects(
      s.atomically(async () => {
        await s.createKey(hmacMaterial(), { createdAt: 2 });
        throw new Error('nope');
      }),
    );
    assert.equal(await readFile(path, 'utf8'), before);
  });

  it('a corrupt keyring file is an error, never silently an empty keyring', async () => {
    const path = join(dir, 'corrupt.json');
    await writeFile(path, '{ this is not json');
    const s = new FileKeyStore(path);
    await assert.rejects(
      s.listKeys(),
      (e: unknown) => isAuthError(e) && e.code === 'STORAGE_UNAVAILABLE',
    );
    await assert.rejects(
      s.createKey(hmacMaterial(), { createdAt: 1 }),
      (e: unknown) => isAuthError(e) && e.code === 'STORAGE_UNAVAILABLE',
    );
    assert.equal(await readFile(path, 'utf8'), '{ this is not json', 'not overwritten');
  });
});
