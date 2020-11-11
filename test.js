const assert = require('assert')
const has = require('has')
const sodium = require('sodium-native')

// Configure a protocol implementation with primitives
// from sodium-native.
const protocol = require('./')({
  clientStretch: function ({ password, salt }) {
    const returned = Buffer.alloc(32)
    sodium.crypto_pwhash(
      returned, password, salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_DEFAULT
    )
    return returned
  },

  serverStretchSaltLength: sodium.crypto_pwhash_SALTBYTES,

  serverStretch: function ({ password, salt }) {
    const returned = Buffer.alloc(32)
    sodium.crypto_pwhash(
      returned, password, salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_DEFAULT
    )
    return returned
  },

  authenticationToken: {
    subkey: 1,
    context: Buffer.from('authTokn')
  },

  verificationHash: {
    subkey: 2,
    context: Buffer.from('verifHsh')
  },

  serverWrappingKey: {
    subkey: 3,
    context: Buffer.from('serverKy')
  },

  clientWrappingKey: {
    subkey: 4,
    context: Buffer.from('clientKy')
  },

  requestAuthenticationKey: {
    subkey: 5,
    context: Buffer.from('reqAthKy')
  },

  responseAuthenticationKey: {
    subkey: 6,
    context: Buffer.from('resAthKy')
  },

  responseEncryptionKey: {
    subkey: 7,
    context: Buffer.from('resEncKy')
  },

  keyRequestToken: {
    subkey: 8,
    context: Buffer.from('kyReqTkn')
  },

  tokenID: {
    subkey: 9,
    context: Buffer.from('token-ID')
  },

  deriveKey: function ({ key, subkey, context, length }) {
    const returned = Buffer.alloc(length || 32)
    assert(returned.length >= sodium.crypto_kdf_BYTES_MIN)
    assert(returned.length <= sodium.crypto_kdf_BYTES_MAX)
    assert(context.length === sodium.crypto_kdf_CONTEXTBYTES)
    assert(key.length === sodium.crypto_kdf_KEYBYTES)
    sodium.crypto_kdf_derive_from_key(
      returned, subkey, context, key
    )
    return returned
  },

  authenticate: function ({ key, input }) {
    const returned = Buffer.alloc(sodium.crypto_auth_BYTES)
    sodium.crypto_auth(returned, input, key)
    return returned
  },

  random: random,

  generateUserID: function () { return random(32) },

  generateToken: function () { return random(32) }
})

function random (size) {
  const returned = Buffer.alloc(size)
  sodium.randombytes_buf(returned)
  return returned
}

// Test login computations.

const clientLogin = protocol.client.login({
  password: 'apple sauce',
  email: 'user@example.com'
})

assert(has(clientLogin, 'clientStretchedPassword'))
assert(clientLogin.clientStretchedPassword.length === 32)
assert(has(clientLogin, 'authenticationToken'))
assert(clientLogin.authenticationToken.length === 32)

// Test server register computations.

const serverRegister = protocol.server.register({
  clientStretchedPassword: clientLogin.clientStretchedPassword,
  authenticationToken: clientLogin.authenticationToken
})

assert(has(serverRegister, 'authenticationSalt'))
assert(serverRegister.authenticationSalt.length === 16)
assert(has(serverRegister, 'serverStretchedPassword'))
assert(serverRegister.serverStretchedPassword.length === 32)
assert(has(serverRegister, 'serverWrappedEncryptionKey'))
assert(serverRegister.serverWrappedEncryptionKey.length === 32)
assert(has(serverRegister, 'userID'))
assert(serverRegister.userID.length === 32)
assert(has(serverRegister, 'verificationHash'))
assert(serverRegister.verificationHash.length === 32)

// Test server login verification.

const serverLogin = protocol.server.login({
  authenticationToken: clientLogin.authenticationToken,
  authenticationSalt: serverRegister.authenticationSalt,
  verificationHash: serverRegister.verificationHash
})

assert(serverLogin === true)

const badServerLogin = protocol.server.login({
  authenticationToken: clientLogin.authenticationToken,
  authenticationSalt: serverRegister.authenticationSalt,
  verificationHash: Buffer.alloc(32)
})

assert(badServerLogin === false)

// Test access token request server computations.

const keyAccessToken = random(32)

const serverRequest = protocol.server.request({
  serverStretchedPassword: serverRegister.serverStretchedPassword,
  serverWrappedEncryptionKey: serverRegister.serverWrappedEncryptionKey,
  keyAccessToken
})

assert(has(serverRequest, 'tokenID'))
assert(serverRequest.tokenID.length === 32)
assert(has(serverRequest, 'ciphertext'))
assert(serverRequest.ciphertext.length === 32)
assert(has(serverRequest, 'mac'))
assert(serverRequest.mac.length === 32)
assert(has(serverRequest, 'requestAuthenticationKey'))
assert(serverRequest.requestAuthenticationKey.length === 32)

// Test access token request client computations.

const clientRequest = protocol.client.request({
  ciphertext: serverRequest.ciphertext,
  mac: serverRequest.mac,
  clientStretchedPassword: clientLogin.clientStretchedPassword,
  keyAccessToken
})

assert(has(clientRequest, 'encryptionKey'))
assert(clientRequest.encryptionKey.length === 32)

const badClientRequest = protocol.client.request({
  ciphertext: serverRequest.ciphertext,
  mac: Buffer.alloc(32),
  clientStretchedPassword: clientLogin.clientStretchedPassword,
  keyAccessToken
})

assert(badClientRequest === false)
