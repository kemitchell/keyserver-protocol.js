var assert = require('assert')

var VERIFICATION_HASH = 'verificationHash'

module.exports = function (primitives) {
  assert(typeof primitives === 'object')

  var clientStretch = primitives.clientStretch
  assert(typeof clientStretch === 'function')

  var serverStretch = primitives.serverStretch
  assert(typeof serverStretch === 'function')

  var serverStretchSaltLength = primitives.serverStretchSaltLength
  assert(typeof serverStretchSaltLength === 'number')
  assert(serverStretchSaltLength > 0)

  var hkdf = primitives.hkdf
  assert(typeof hkdf === 'function')

  var hmac = primitives.hmac
  assert(typeof hmac === 'function')

  var random = primitives.random
  assert(typeof random === 'function')

  var keyLength = primitives.unwrappedKeyLength
  assert(typeof keyLength === 'number')
  assert(keyLength > 0)

  var generateUserID = primitives.generateUserID
  assert(typeof generateUserID === 'function')

  var generateToken = primitives.generateToken
  assert(typeof generateToken === 'function')

  return {
    client: {
      login: clientLogin,
      request: clientRequest
    },
    server: {
      register: serverRegister,
      login: serverLogin,
      request: serverRequest
    }
  }

  function clientLogin (input) {
    assert(typeof input === 'object')

    var password = input.password
    assert(typeof password === 'string')
    assert(password.length > 0)

    var email = input.email
    assert(typeof email === 'string')
    assert(email.length > 0)
    assert(email.indexOf('@') > 1)

    var clientStretchedPassword = clientStretch({
      password, salt: email
    })
    var authenticationToken = hkdf({
      input: clientStretchedPassword,
      info: 'authenticationToken'
    })

    return {
      clientStretchedPassword,
      authenticationToken
    }
  }

  function serverRegister (input) {
    assert(typeof input === 'object')

    var email = input.email
    assert(typeof email === 'string')
    assert(email.length > 0)
    assert(email.indexOf('@') > 1)

    var clientStretchedPassword = input.clientStretchedPassword
    assert(clientStretchedPassword instanceof ArrayBuffer)
    assert(clientStretchedPassword.byteLength > 0)

    var authenticationToken = input.authenticationToken
    assert(authenticationToken instanceof ArrayBuffer)
    assert(authenticationToken.byteLength > 0)

    var authenticationSalt = random(serverStretchSaltLength)
    var serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })
    var verificationHash = hkdf({
      input: serverStretchedPassword,
      salt: new ArrayBuffer(0),
      info: VERIFICATION_HASH
    })
    var serverWrappedKey = random(keyLength)
    var userID = generateUserID()

    return {
      authenticationSalt,
      email,
      userID,
      serverWrappedKey,
      verificationHash,
      sessionToken: generateToken(),
      keyAccessToken: generateToken()
    }
  }

  function serverLogin (input) {
    assert(typeof input === 'object')

    var authenticationToken = input.authenticationToken
    assert(authenticationToken instanceof ArrayBuffer)
    assert(authenticationToken.byteLength > 0)

    var authenticationSalt = input.authenticationSalt
    assert(authenticationSalt instanceof ArrayBuffer)
    assert(authenticationSalt.byteLength > 0)

    var serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })

    var storedVerificationHash = input.verificationHash

    var computedVerificationHash = hkdf({
      input: serverStretchedPassword,
      salt: new ArrayBuffer(0),
      info: VERIFICATION_HASH
    })

    if (!equal(storedVerificationHash, computedVerificationHash)) {
      return false
    }

    return {
      sessionToken: generateToken(),
      keyAccessToken: generateToken()
    }
  }

  function serverRequest (input) {
    assert(typeof input === 'object')

    var serverStretchedPassword = input.serverStretchedPassword
    assert(serverStretchedPassword instanceof ArrayBuffer)
    assert(serverStretchedPassword.byteLength > 0)

    var serverWrappedKey = input.serverWrappedKey
    assert(serverWrappedKey instanceof ArrayBuffer)
    assert(serverWrappedKey.byteLength > 0)

    var keyAccessToken = input.keyAccessToken
    assert(keyAccessToken instanceof ArrayBuffer)
    assert(keyAccessToken.byteLength > 0)

    var serverKey = hkdf({
      input: serverStretchedPassword,
      info: 'serverKey'
    })
    var clientWrappedKey = xor(serverKey, serverWrappedKey)

    var fromKeyAccessToken = deriveFromKeyAccessToken(keyAccessToken)
    var tokenID = fromKeyAccessToken.tokenID
    var requestAuthenticationKey = fromKeyAccessToken.requestAuthenticationKey
    var keyRequestToken = fromKeyAccessToken.keyRequestToken

    var fromKeyRequestToken = deriveFromKeyRequestToken(keyRequestToken)
    var responseAuthenticationKey = fromKeyRequestToken.responseAuthenticationKey
    var responseEncryptionKey = fromKeyRequestToken.responseEncryptionKey

    var ciphertext = xor(clientWrappedKey, responseEncryptionKey)
    var mac = hmac({
      key: responseAuthenticationKey,
      ciphertext
    })

    return {
      tokenID,
      ciphertext,
      mac,
      requestAuthenticationKey
    }
  }

  function clientRequest (input) {
    assert(typeof input === 'object')

    var ciphertext = input.ciphertext
    assert(ciphertext instanceof ArrayBuffer)

    var providedMAC = input.mac
    assert(ciphertext instanceof ArrayBuffer)

    var clientStretchedPassword = input.clientStretchedPassword
    assert(ciphertext instanceof ArrayBuffer)

    var keyAccessToken = input.keyAccessToken
    assert(keyAccessToken instanceof ArrayBuffer)

    var fromKeyAccessToken = deriveFromKeyAccessToken(keyAccessToken)
    // var tokenID = fromKeyAccessToken.tokenID
    // var requestAuthenticationKey = fromKeyAccessToken.requestAuthenticationKey
    var keyRequestToken = fromKeyAccessToken.keyRequestToken

    var fromKeyRequestToken = deriveFromKeyRequestToken(keyRequestToken)
    var responseAuthenticationKey = fromKeyRequestToken.responseAuthenticationKey
    var responseEncryptionKey = fromKeyRequestToken.responseEncryptionKey

    var computedMAC = hmac({
      key: responseAuthenticationKey,
      ciphertext
    })

    if (!equal(providedMAC, computedMAC)) return false

    var clientWrappedKey = xor(ciphertext, responseEncryptionKey)

    var clientKey = hkdf({
      input: clientStretchedPassword,
      salt: new ArrayBuffer(0),
      info: 'clientKey',
      length: 32
    })

    var key = xor(clientWrappedKey, clientKey)

    return key
  }

  function deriveFromKeyAccessToken (keyAccessToken) {
    var buffer = hkdf({
      input: keyAccessToken,
      salt: new ArrayBuffer(0),
      info: 'fromKeyAccessToken',
      length: 3 * 32
    })
    return {
      tokenID: buffer.slice(0, 32),
      requestAuthenticationKey: buffer.slice(32, 64),
      keyRequestToken: buffer.slice(64, 96)
    }
  }

  function deriveFromKeyRequestToken (keyRequestToken) {
    var buffer = hkdf({
      input: keyRequestToken,
      salt: new ArrayBuffer(0),
      info: 'fromKeyRequestToken',
      length: 2 * 32
    })
    return {
      requestAuthenticationKey: buffer.slice(0, 32),
      responseEncryptionKey: buffer.slice(32, 65)
    }
  }
}

function equal (a, b) {
  if (a.byteLength !== b.byteLength) return false
  var aView = DataView(a)
  var bView = DataView(b)
  for (var offset = 0; offset < aView.byteLength; offset++) {
    if (aView.getUint8(offset) !== bView.getUint8(offset)) {
      return false
    }
  }
  return true
}

function xor (a, b) {
  var aView = DataView(a)
  var bView = DataView(b)
  var returned = new ArrayBuffer(a.byteLength)
  var returnedView = DataView(returned)
  for (var offset = 0; offset < aView.byteLength; offset++) {
    returnedView.setUint8(
      offset,
      aView.getUint8(offset) ^ bView.getUint8(offset)
    )
  }
  return returned
}
