'use strict';

const common = require('../common');

if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const crypto = require('crypto');
const { subtle } = globalThis.crypto;

// Known answers from Project Wycheproof's aes_gcm_test.json.
const vectors = [
  { // tcId 277
    key: '59a284f50aedd8d3e2a91637d3815579',
    iv: '80',
    aad: '',
    plaintext: '',
    ciphertext: '',
    tag: 'af498f701d2470695f6e7c8327a2398b',
  },
  { // tcId 278
    key: 'fec58aa8cf06bfe05de829f27ec77693',
    iv: '9d',
    aad: '',
    plaintext: 'f2d99a9f893378e0757d27c2e3a3101b',
    ciphertext: '0a24612a9d1cbe967dbfe804bf8440e5',
    tag: '96e6fd2cdc707e3ee0a1c90d34c9c36c',
  },
  { // tcId 279
    key: '88a972cce9eaf5a7813ce8149d0c1d0e',
    iv: '0f2f',
    aad: '',
    plaintext: '',
    ciphertext: '',
    tag: '4ccf1efb4da05b4ae4452aea42f5424b',
  },
  { // tcId 68
    key: 'aa023d0478dcb2b2312498293d9a9129',
    iv: '0432bc49ac344120',
    aad: 'aac39231129872a2',
    plaintext: '2035af313d1346ab00154fea78322105',
    ciphertext: '64c36bb3b732034e3a7d04efc5197785',
    tag: 'b7d0dd70b00d65b97cfd080ff4b819d1',
  },
  { // tcId 308
    key: '115884f693b155563e9bfb3b07cacb2f7f7caa9bfe51f89e23feb5a9468bfdd0',
    iv: '04102199ef21e1df',
    aad: '',
    plaintext: '82e3e604d2be8fcab74f638d1e70f24c',
    ciphertext: '7e0dd6c72aec49f89cc6a80060c0b170',
    tag: 'af68a37cfefecc4ab99ba50a5353edca',
  },
];

const hex = (s) => Buffer.from(s, 'hex');

async function testKnownAnswer(vector) {
  const algorithm = {
    name: 'AES-GCM',
    iv: hex(vector.iv),
    additionalData: hex(vector.aad),
    tagLength: 128,
  };
  const key = await subtle.importKey(
    'raw', hex(vector.key), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

  const encrypted = Buffer.from(
    await subtle.encrypt(algorithm, key, hex(vector.plaintext)));
  assert.strictEqual(encrypted.toString('hex'), vector.ciphertext + vector.tag);

  const decrypted = Buffer.from(await subtle.decrypt(algorithm, key, encrypted));
  assert.strictEqual(decrypted.toString('hex'), vector.plaintext);

  const otherIv = hex(vector.iv);
  otherIv[0] ^= 0x01;
  await assert.rejects(
    subtle.decrypt({ ...algorithm, iv: otherIv }, key, encrypted),
    { name: 'OperationError' });
}

async function testAgreesWithNodeCrypto(ivLength) {
  const keyBytes = Buffer.alloc(16, 0xa5);
  const iv = Buffer.alloc(ivLength, ivLength);
  const aad = Buffer.alloc(8, 0x5a);
  const plaintext = Buffer.alloc(24, 0x3c);

  const cipher = crypto.createCipheriv('aes-128-gcm', keyBytes, iv,
                                       { authTagLength: 16 });
  cipher.setAAD(aad);
  const expected = Buffer.concat(
    [cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  const key = await subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
  const actual = Buffer.from(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
    key, plaintext));

  assert.deepStrictEqual(actual, expected,
                         `AES-GCM disagrees for a ${ivLength}-byte IV`);
}

async function testEmptyIvIsRejected() {
  const key = await subtle.importKey(
    'raw', new Uint8Array(16), { name: 'AES-GCM' }, false, ['encrypt']);
  await assert.rejects(
    subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(0), tagLength: 128 },
      key, new Uint8Array(0)),
    { name: 'OperationError' });

  assert.throws(
    () => crypto.createCipheriv('aes-128-gcm', Buffer.alloc(16),
                                Buffer.alloc(0)),
    { code: 'ERR_CRYPTO_INVALID_IV' });
}

(async function() {
  for (const vector of vectors)
    await testKnownAnswer(vector);
  for (let ivLength = 1; ivLength <= 16; ivLength++)
    await testAgreesWithNodeCrypto(ivLength);
  await testEmptyIvIsRejected();
})().then(common.mustCall());
