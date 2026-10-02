// The KeyStore port contract (src/ports/index.ts), run identically against every adapter: memory and
// file (test/unit/keystore.test.ts) and PostgreSQL (test/postgres/keys.pg-test.ts). A behavioural
// difference between adapters is a bug in one of them.
import assert from 'node:assert/strict';
import { generateKeyPairSync, createPublicKey, randomBytes } from 'node:crypto';
import { it } from 'node:test';
import { isAuthError, seal, type KeyStore, type KeyStoreMaterial } from '../../src/index.js';

export const CONTRACT_MASTER_KEY = Buffer.from(
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  'hex',
);
const T0 = Date.UTC(2030, 0, 1);

let n = 0;
const kid = (p = 'k'): string => `${p}-${++n}-${randomBytes(3).toString('hex')}`;

/** HMAC material with a properly sealed (AEK1) private envelope. */
export function hmacMaterial(id: string = kid()): KeyStoreMaterial {
  return {
    kid: id,
    type: 'HMAC',
    publicMaterial: null,
    privateMaterial: seal(id, randomBytes(32), CONTRACT_MASTER_KEY),
  };
}

/** RSA material: public JWK members only, sealed PKCS#8 private key. */
export function rsaMaterial(id: string = kid()): KeyStoreMaterial {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = createPublicKey(privateKey).export({ format: 'jwk' });
  return {
    kid: id,
    type: 'RSA',
    publicMaterial: { kty: 'RSA', n: jwk.n as string, e: jwk.e as string },
    privateMaterial: seal(
      id,
      privateKey.export({ type: 'pkcs8', format: 'der' }),
      CONTRACT_MASTER_KEY,
    ),
  };
}

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    assert.ok(isAuthError(e), `expected an AuthError, got ${String(e)}`);
    return e.code;
  }
  return 'OK';
}

export interface StoreHandle {
  readonly store: KeyStore;
  dispose(): Promise<void>;
}

/**
 * Registers the contract cases. `make` must return a FRESH, empty store each time: the cases rely
 * on "the" active key of a store.
 */
export function keyStoreContract(make: () => Promise<StoreHandle>): void {
  const withStore = (fn: (s: KeyStore) => Promise<void>) => async () => {
    const h = await make();
    try {
      await fn(h.store);
    } finally {
      await h.dispose();
    }
  };

  it(
    'createKey creates a PENDING key with no activation or retirement time',
    withStore(async (s) => {
      const m = rsaMaterial();
      const k = await s.createKey(m, { createdAt: T0, metadata: { note: 'x' } });
      assert.equal(k.status, 'pending');
      assert.equal(k.activatedAt, null);
      assert.equal(k.retiredAt, null);
      assert.deepEqual({ ...k.publicMaterial }, { ...m.publicMaterial });
      assert.deepEqual(Buffer.from(k.privateMaterial), Buffer.from(m.privateMaterial));
      assert.deepEqual({ ...k.metadata }, { note: 'x' });
      assert.equal(await s.getActiveKey(), null);
      assert.equal((await s.getKeyById(m.kid))?.status, 'pending');
    }),
  );

  it(
    'a kid is never reused, not even after remove',
    withStore(async (s) => {
      const m = hmacMaterial();
      await s.createKey(m, { createdAt: T0 });
      assert.equal(
        await codeOf(() => s.createKey(hmacMaterial(m.kid), { createdAt: T0 })),
        'CONFLICT',
      );
      await s.remove(m.kid);
      assert.equal(await s.getKeyById(m.kid), null);
      assert.equal(
        await codeOf(() => s.createKey(hmacMaterial(m.kid), { createdAt: T0 })),
        'CONFLICT',
      );
    }),
  );

  it(
    'rejects private members in public material and public material for HMAC',
    withStore(async (s) => {
      const rsa = rsaMaterial();
      const leaky = {
        ...rsa,
        publicMaterial: { ...rsa.publicMaterial, d: 'secret' },
      } as unknown as KeyStoreMaterial;
      assert.equal(await codeOf(() => s.createKey(leaky, { createdAt: T0 })), 'VALIDATION_FAILED');
      const hmacWithPublic = { ...hmacMaterial(), publicMaterial: rsa.publicMaterial };
      assert.equal(
        await codeOf(() => s.createKey(hmacWithPublic, { createdAt: T0 })),
        'VALIDATION_FAILED',
      );
      assert.equal(
        await codeOf(() => s.createKey({ ...hmacMaterial(), kid: 'bad kid!' }, { createdAt: T0 })),
        'VALIDATION_FAILED',
      );
    }),
  );

  it(
    'activate makes one key active and retires the previous one at the same instant',
    withStore(async (s) => {
      const a = hmacMaterial();
      const b = hmacMaterial();
      await s.createKey(a, { createdAt: T0 });
      await s.createKey(b, { createdAt: T0 + 1 });
      assert.deepEqual(await s.activate(a.kid, T0 + 10), { activated: a.kid, retired: null });
      assert.deepEqual(await s.activate(b.kid, T0 + 20), { activated: b.kid, retired: a.kid });
      const ka = await s.getKeyById(a.kid);
      assert.equal(ka?.status, 'retired');
      assert.equal(ka?.retiredAt, T0 + 20);
      assert.equal(ka?.activatedAt, T0 + 10);
      assert.equal((await s.getActiveKey())?.kid, b.kid);
      assert.equal((await s.getKeyById(b.kid))?.activatedAt, T0 + 20);
    }),
  );

  it(
    'activate is idempotent on the active key and refuses a retired or unknown one',
    withStore(async (s) => {
      const a = hmacMaterial();
      const b = hmacMaterial();
      await s.createKey(a, { createdAt: T0 });
      await s.createKey(b, { createdAt: T0 });
      await s.activate(a.kid, T0 + 1);
      assert.deepEqual(await s.activate(a.kid, T0 + 2), { activated: a.kid, retired: null });
      assert.equal((await s.getKeyById(a.kid))?.activatedAt, T0 + 1, 'unchanged');
      await s.activate(b.kid, T0 + 3);
      assert.equal(
        await codeOf(() => s.activate(a.kid, T0 + 4)),
        'PRECONDITION_FAILED',
        'retired stays retired',
      );
      assert.equal(await codeOf(() => s.activate('no-such-kid', T0)), 'NOT_FOUND');
    }),
  );

  it(
    'markPending only confirms a pending key; nothing can return to pending',
    withStore(async (s) => {
      const a = hmacMaterial();
      await s.createKey(a, { createdAt: T0 });
      await s.markPending(a.kid);
      await s.activate(a.kid, T0 + 1);
      assert.equal(await codeOf(() => s.markPending(a.kid)), 'PRECONDITION_FAILED');
      assert.equal(await codeOf(() => s.markPending('no-such-kid')), 'NOT_FOUND');
    }),
  );

  it(
    'retire sets retiredAt once; repeating is a no-op',
    withStore(async (s) => {
      const a = hmacMaterial();
      await s.createKey(a, { createdAt: T0 });
      await s.activate(a.kid, T0 + 10);
      assert.equal(
        await codeOf(() => s.retire(a.kid, T0 + 5)),
        'VALIDATION_FAILED',
        'not before activation',
      );
      assert.equal(await s.retire(a.kid, T0 + 30), true);
      assert.equal(await s.retire(a.kid, T0 + 40), false);
      const k = await s.getKeyById(a.kid);
      assert.equal(k?.status, 'retired');
      assert.equal(k?.retiredAt, T0 + 30);
      assert.equal(await s.getActiveKey(), null, 'retiring the active key leaves no signer');
      assert.equal(await codeOf(() => s.retire('no-such-kid', T0)), 'NOT_FOUND');
    }),
  );

  it(
    'remove refuses the active key; prune deletes only keys retired before the cutoff',
    withStore(async (s) => {
      const a = hmacMaterial();
      const b = hmacMaterial();
      const c = hmacMaterial();
      for (const m of [a, b, c]) await s.createKey(m, { createdAt: T0 });
      await s.activate(a.kid, T0 + 1);
      await s.activate(b.kid, T0 + 100); // retires a at T0+100
      await s.activate(c.kid, T0 + 200); // retires b at T0+200
      assert.equal(await codeOf(() => s.remove(c.kid)), 'PRECONDITION_FAILED');
      await s.remove('no-such-kid'); // idempotent
      assert.equal(await s.prune(T0 + 150), 1);
      assert.equal(await s.getKeyById(a.kid), null);
      assert.ok(await s.getKeyById(b.kid));
      assert.deepEqual(
        (await s.listKeys()).map((k) => k.kid),
        [b.kid, c.kid],
      );
    }),
  );

  it(
    'atomically is all-or-nothing',
    withStore(async (s) => {
      const a = hmacMaterial();
      await assert.rejects(
        s.atomically(async () => {
          await s.createKey(a, { createdAt: T0 });
          await s.activate(a.kid, T0 + 1);
          throw new Error('fail inside');
        }),
        /fail inside/,
      );
      assert.equal(await s.getKeyById(a.kid), null);
      assert.equal(await s.getActiveKey(), null);
      // Nothing was registered either: the rolled-back kid can be created.
      await s.createKey(a, { createdAt: T0 });
    }),
  );

  it(
    'concurrent rotations end with exactly one active key and nothing lost',
    withStore(async (s) => {
      const kids = Array.from({ length: 12 }, () => kid('rot'));
      await Promise.all(
        kids.map((id, i) =>
          s.atomically(async () => {
            await s.createKey(hmacMaterial(id), { createdAt: T0 + i });
            await s.activate(id, T0 + 100);
          }),
        ),
      );
      const all = await s.listKeys();
      assert.equal(all.length, 12);
      assert.equal(all.filter((k) => k.status === 'active').length, 1);
      assert.equal(all.filter((k) => k.status === 'retired').length, 11);
      assert.ok(all.every((k) => k.status === 'active' || k.retiredAt !== null));
    }),
  );

  it(
    'activate refuses an instant before creation or before the current key’s activation',
    withStore(async (s) => {
      const a = hmacMaterial();
      const b = hmacMaterial();
      await s.createKey(a, { createdAt: T0 });
      await s.createKey(b, { createdAt: T0 + 10 });
      const refused = (e: unknown) =>
        isAuthError(e) &&
        e.code === 'VALIDATION_FAILED' &&
        e.details?.['rule'] === 'key.activated_at';
      await assert.rejects(s.activate(b.kid, T0 + 5), refused);
      await s.activate(a.kid, T0 + 50);
      await assert.rejects(s.activate(b.kid, T0 + 49), refused);
      assert.equal((await s.getActiveKey())?.kid, a.kid, 'nothing changed');
      assert.equal((await s.getKeyById(b.kid))?.status, 'pending');
      await s.activate(b.kid, T0 + 50);
      assert.equal((await s.getKeyById(a.kid))?.retiredAt, T0 + 50);
    }),
  );

  it(
    'concurrent "create a key if the store is empty" creates exactly one',
    withStore(async (s) => {
      await Promise.all(
        Array.from({ length: 8 }, () =>
          s.atomically(async () => {
            if ((await s.listKeys()).length > 0) return;
            const m = hmacMaterial();
            await s.createKey(m, { createdAt: T0 });
            await s.activate(m.kid, T0);
          }),
        ),
      );
      const all = await s.listKeys();
      assert.equal(all.length, 1);
      assert.equal(all[0]?.status, 'active');
    }),
  );
}
