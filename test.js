var assert = require('assert')
var sodium = require('sodium-native')

var protocol = require('./')({
  clientStretch: function (options) {
    var password = options.password
    var salt = options.salt
    var returned = Buffer.alloc(32)
    sodium.crypto_pwhash(
      returned, password, salt,
      sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
      sodium.crypto_pwhash_ALG_DEFAULT
    )
    return returned
  },

  serverStretchSaltLength: 32,

  serverStretch: function (options) {
    var password = options.password
    var salt = options.salt
    var returned = Buffer.alloc(32)
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

  serverKey: {
    subkey: 3,
    context: Buffer.from('serverKy')
  },

  clientKey: {
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

  deriveKey: function (options) {
    var key = options.key
    var subkey = options.subkey
    var context = options.context
    var returned = Buffer.alloc(options.length || 32)
    assert(returned.length >= sodium.crypto_kdf_BYTES_MIN)
    assert(returned.length <= sodium.crypto_kdf_BYTES_MAX)
    assert(context.length === sodium.crypto_kdf_CONTEXTBYTES)
    assert(key.length === sodium.crypto_kdf_KEYBYTES)
    sodium.crypto_kdf_derive_from_key(
      returned, subkey, context, key
    )
    return returned
  },

  authenticate: function (options) {
    var key = options.key
    var input = options.input
    var returned = Buffer.alloc(sodium.crypto_auth_BYTES)
    sodium.crypto_auth(returned, input, key)
    return returned
  },

  random: random,

  generateUserID: function () { return random(32) },

  generateToken: function () { return random(32) }
})

function random (size) {
  var returned = Buffer.alloc(size)
  sodium.randombytes_buf(returned)
  return returned
}

var clientLogin = protocol.client.login({
  password: 'apple sauce',
  email: 'user@example.com'
})

assert(clientLogin.hasOwnProperty('clientStretchedPassword'))
assert(clientLogin.hasOwnProperty('authenticationToken'))

var serverRegister = protocol.server.register({
  clientStretchedPassword: clientLogin.clientStretchedPassword,
  authenticationToken: clientLogin.authenticationToken
})

assert(serverRegister.hasOwnProperty('authenticationSalt'))
assert(serverRegister.hasOwnProperty('serverStretchedPassword'))
assert(serverRegister.hasOwnProperty('serverWrappedKey'))
assert(serverRegister.hasOwnProperty('userID'))
assert(serverRegister.hasOwnProperty('verificationHash'))

var keyAccessToken = random(32)

var serverRequest = protocol.server.request({
  serverStretchedPassword: serverRegister.serverStretchedPassword,
  serverWrappedKey: serverRegister.serverWrappedKey,
  keyAccessToken
})

assert(serverRequest.hasOwnProperty('tokenID'))
assert(serverRequest.hasOwnProperty('ciphertext'))
assert(serverRequest.hasOwnProperty('mac'))
assert(serverRequest.hasOwnProperty('requestAuthenticationKey'))

var clientRequest = protocol.client.request({
  ciphertext: serverRequest.ciphertext,
  mac: serverRequest.mac,
  clientStretchedPassword: clientLogin.clientStretchedPassword,
  keyAccessToken
})

assert(clientRequest.hasOwnProperty('encryptionKey'))
