var assert = require('assert')

module.exports = function (primitives) {
  assert(typeof primitives === 'object')

  // Cryptographic Primitives

  var clientStretch = primitives.clientStretch
  assert(typeof clientStretch === 'function')

  var serverStretch = primitives.serverStretch
  assert(typeof serverStretch === 'function')

  var serverStretchSaltLength = primitives.serverStretchSaltLength
  assert(Number.isInteger(serverStretchSaltLength))
  assert(serverStretchSaltLength > 0)

  var deriveKey = primitives.deriveKey
  assert(typeof deriveKey === 'function')

  var authenticate = primitives.authenticate
  assert(typeof authenticate === 'function')

  var random = primitives.random
  assert(typeof random === 'function')

  var generateUserID = primitives.generateUserID
  assert(typeof generateUserID === 'function')

  // Key Derivation Parameters

  var verificationHashParameters = primitives.verificationHash
  assert(typeof verificationHashParameters === 'object')

  var authenticationTokenParameters = primitives.authenticationToken
  assert(typeof authenticationTokenParameters === 'object')

  var clientKeyParameters = primitives.clientKey
  assert(typeof clientKeyParameters === 'object')

  var serverKeyParameters = primitives.serverKey
  assert(typeof serverKeyParameters === 'object')

  var fromKeyAccessTokenParameters = primitives.fromKeyAccessToken
  assert(typeof fromKeyAccessTokenParameters === 'object')

  var fromKeyRequestTokenParameters = primitives.fromKeyRequestToken
  assert(typeof fromKeyRequestTokenParameters === 'object')

  var tokenIDParameters = primitives.tokenID
  assert(typeof tokenIDParameters === 'object')

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
    var passwordBuffer = Buffer.from(password, 'utf8')

    var email = input.email
    assert(typeof email === 'string')
    assert(email.length > 0)
    assert(email.indexOf('@') > 1)
    var emailBuffer = Buffer.from(email, 'utf8')

    var clientStretchedPassword = clientStretch({
      password: passwordBuffer,
      salt: emailBuffer
    })
    var parameters = { key: clientStretchedPassword }
    Object.assign(parameters, authenticationTokenParameters)
    var authenticationToken = deriveKey(parameters)

    return {
      authenticationToken,
      clientStretchedPassword
    }
  }

  function serverRegister (input) {
    assert(typeof input === 'object')

    var clientStretchedPassword = input.clientStretchedPassword
    assert(Buffer.isBuffer(clientStretchedPassword))
    assert(clientStretchedPassword.byteLength > 0)

    var authenticationToken = input.authenticationToken
    assert(Buffer.isBuffer(authenticationToken))
    assert(authenticationToken.byteLength > 0)

    var authenticationSalt = random(serverStretchSaltLength)
    var serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })
    var parameters = { key: serverStretchedPassword }
    Object.assign(parameters, verificationHashParameters)
    var verificationHash = deriveKey(parameters)
    var serverWrappedKey = random(32)
    var userID = generateUserID()

    return {
      authenticationSalt,
      userID,
      serverWrappedKey,
      verificationHash,
      serverStretchedPassword
    }
  }

  function serverLogin (input) {
    assert(typeof input === 'object')

    var authenticationToken = input.authenticationToken
    assert(Buffer.isBuffer(authenticationToken))
    assert(authenticationToken.byteLength > 0)

    var authenticationSalt = input.authenticationSalt
    assert(Buffer.isBuffer(authenticationSalt))
    assert(authenticationSalt.byteLength > 0)

    var serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })

    var storedVerificationHash = input.verificationHash

    var parameters = { key: serverStretchedPassword }
    Object.assign(parameters, verificationHashParameters)
    var computedVerificationHash = deriveKey(parameters)

    if (!storedVerificationHash.equals(computedVerificationHash)) {
      return false
    }

    return true
  }

  function serverRequest (input) {
    assert(typeof input === 'object')

    var serverStretchedPassword = input.serverStretchedPassword
    assert(Buffer.isBuffer(serverStretchedPassword))
    assert(serverStretchedPassword.byteLength > 0)

    var serverWrappedKey = input.serverWrappedKey
    assert(Buffer.isBuffer(serverWrappedKey))
    assert(serverWrappedKey.byteLength > 0)

    var keyAccessToken = input.keyAccessToken
    assert(Buffer.isBuffer(keyAccessToken))
    assert(keyAccessToken.byteLength > 0)

    var parameters = { key: serverStretchedPassword }
    Object.assign(parameters, serverKeyParameters)
    var serverKey = deriveKey(parameters)
    var clientWrappedKey = xor(serverKey, serverWrappedKey)

    var fromKeyAccessToken = deriveFromKeyAccessToken(keyAccessToken)
    var tokenID = fromKeyAccessToken.tokenID
    var requestAuthenticationKey = fromKeyAccessToken.requestAuthenticationKey
    var keyRequestToken = fromKeyAccessToken.keyRequestToken

    var fromKeyRequestToken = deriveFromKeyRequestToken(keyRequestToken)
    var responseAuthenticationKey = fromKeyRequestToken.responseAuthenticationKey
    var responseEncryptionKey = fromKeyRequestToken.responseEncryptionKey

    var ciphertext = xor(clientWrappedKey, responseEncryptionKey)
    var mac = authenticate({
      key: responseAuthenticationKey,
      input: ciphertext
    })

    return {
      ciphertext,
      mac,
      requestAuthenticationKey,
      tokenID
    }
  }

  function clientRequest (input) {
    assert(typeof input === 'object')

    var ciphertext = input.ciphertext
    assert(Buffer.isBuffer(ciphertext))

    var providedMAC = input.mac
    assert(Buffer.isBuffer(providedMAC))

    var clientStretchedPassword = input.clientStretchedPassword
    assert(Buffer.isBuffer(clientStretchedPassword))

    var keyAccessToken = input.keyAccessToken
    assert(Buffer.isBuffer(keyAccessToken))

    // TODO: Only call function to derive what we need.
    var fromKeyAccessToken = deriveFromKeyAccessToken(keyAccessToken)
    // var tokenID = fromKeyAccessToken.tokenID
    // var requestAuthenticationKey = fromKeyAccessToken.requestAuthenticationKey
    var keyRequestToken = fromKeyAccessToken.keyRequestToken

    var fromKeyRequestToken = deriveFromKeyRequestToken(keyRequestToken)
    var responseAuthenticationKey = fromKeyRequestToken.responseAuthenticationKey
    var responseEncryptionKey = fromKeyRequestToken.responseEncryptionKey

    var computedMAC = authenticate({
      key: responseAuthenticationKey,
      input: ciphertext
    })

    if (!providedMAC.equals(computedMAC)) return false

    var clientWrappedKey = xor(ciphertext, responseEncryptionKey)

    var parameters = { key: clientStretchedPassword }
    Object.assign(parameters, clientKeyParameters)
    var clientKey = deriveKey(parameters)

    var encryptionKey = xor(clientWrappedKey, clientKey)

    return { encryptionKey }
  }

  function deriveFromKeyAccessToken (keyAccessToken) {
    // TODO: Verify this is best for > crypto_kdf_BYTES_MAX.
    var tokenParameters = { key: keyAccessToken }
    Object.assign(tokenParameters, tokenIDParameters)
    var tokenID = deriveKey(tokenParameters)

    var otherParameters = {
      key: keyAccessToken,
      length: 2 * 32
    }
    Object.assign(otherParameters, fromKeyAccessTokenParameters)
    var buffer = deriveKey(otherParameters)

    return {
      keyRequestToken: buffer.slice(32, 64),
      requestAuthenticationKey: buffer.slice(0, 32),
      tokenID
    }
  }

  function deriveFromKeyRequestToken (keyRequestToken) {
    var parameters = {
      key: keyRequestToken,
      length: 2 * 32
    }
    Object.assign(parameters, fromKeyRequestTokenParameters)
    var buffer = deriveKey(parameters)

    return {
      responseAuthenticationKey: buffer.slice(0, 32),
      responseEncryptionKey: buffer.slice(32, 65)
    }
  }
}

function xor (a, b) {
  var returned = Buffer.alloc(a.length)
  for (var offset = 0; offset < a.length; offset++) {
    returned[offset] = a[offset] ^ b[offset]
  }
  return returned
}
