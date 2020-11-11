const assert = require('assert')

module.exports = function (configuration) {
  assert(typeof configuration === 'object')

  // Cryptographic Primitives

  const clientStretch = configuration.clientStretch
  assert(typeof clientStretch === 'function')

  const serverStretch = configuration.serverStretch
  assert(typeof serverStretch === 'function')

  const serverStretchSaltLength = configuration.serverStretchSaltLength
  assert(Number.isInteger(serverStretchSaltLength))
  assert(serverStretchSaltLength > 0)

  const deriveKey = configuration.deriveKey
  assert(typeof deriveKey === 'function')

  const authenticate = configuration.authenticate
  assert(typeof authenticate === 'function')

  const random = configuration.random
  assert(typeof random === 'function')

  const generateUserID = configuration.generateUserID
  assert(typeof generateUserID === 'function')

  // Key Derivation Parameters

  const verificationHashParameters = configuration.verificationHash
  assert(typeof verificationHashParameters === 'object')

  const authenticationTokenParameters = configuration.authenticationToken
  assert(typeof authenticationTokenParameters === 'object')

  const clientKeyParameters = configuration.clientKey
  assert(typeof clientKeyParameters === 'object')

  const serverKeyParameters = configuration.serverKey
  assert(typeof serverKeyParameters === 'object')

  const responseAuthenticationKeyParameters = configuration.responseAuthenticationKey
  assert(typeof responseAuthenticationKeyParameters === 'object')

  const responseEncryptionKeyParameters = configuration.responseEncryptionKey
  assert(typeof responseEncryptionKeyParameters === 'object')

  const requestAuthenticationKeyParameters = configuration.requestAuthenticationKey
  assert(typeof requestAuthenticationKeyParameters === 'object')

  const keyRequestTokenParameters = configuration.keyRequestToken
  assert(typeof keyRequestTokenParameters === 'object')

  const tokenIDParameters = configuration.tokenID
  assert(typeof tokenIDParameters === 'object')

  // API

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

    const password = input.password
    assert(typeof password === 'string')
    assert(password.length > 0)
    const passwordBuffer = Buffer.from(password, 'utf8')

    const email = input.email
    assert(typeof email === 'string')
    assert(email.length > 0)
    assert(email.indexOf('@') > 1)
    const emailBuffer = Buffer.from(email, 'utf8')

    const clientStretchedPassword = clientStretch({
      password: passwordBuffer,
      salt: emailBuffer
    })
    const authenticationToken = deriveKeyHelper(
      clientStretchedPassword, authenticationTokenParameters
    )

    return {
      authenticationToken,
      clientStretchedPassword
    }
  }

  function serverRegister (input) {
    assert(typeof input === 'object')

    const clientStretchedPassword = input.clientStretchedPassword
    assert(Buffer.isBuffer(clientStretchedPassword))
    assert(clientStretchedPassword.byteLength > 0)

    const authenticationToken = input.authenticationToken
    assert(Buffer.isBuffer(authenticationToken))
    assert(authenticationToken.byteLength > 0)

    const authenticationSalt = random(serverStretchSaltLength)
    const serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })
    const verificationHash = deriveKeyHelper(
      serverStretchedPassword, verificationHashParameters
    )
    const serverWrappedKey = random(32)
    const userID = generateUserID()

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

    const authenticationToken = input.authenticationToken
    assert(Buffer.isBuffer(authenticationToken))
    assert(authenticationToken.byteLength > 0)

    const authenticationSalt = input.authenticationSalt
    assert(Buffer.isBuffer(authenticationSalt))
    assert(authenticationSalt.byteLength > 0)

    const storedVerificationHash = input.verificationHash
    assert(Buffer.isBuffer(storedVerificationHash))
    assert(storedVerificationHash.byteLength > 0)

    const serverStretchedPassword = serverStretch({
      password: authenticationToken,
      salt: authenticationSalt
    })

    const computedVerificationHash = deriveKeyHelper(
      serverStretchedPassword, verificationHashParameters
    )

    return storedVerificationHash.equals(computedVerificationHash)
  }

  function serverRequest (input) {
    assert(typeof input === 'object')

    const serverStretchedPassword = input.serverStretchedPassword
    assert(Buffer.isBuffer(serverStretchedPassword))
    assert(serverStretchedPassword.byteLength > 0)

    const serverWrappedKey = input.serverWrappedKey
    assert(Buffer.isBuffer(serverWrappedKey))
    assert(serverWrappedKey.byteLength > 0)

    const keyAccessToken = input.keyAccessToken
    assert(Buffer.isBuffer(keyAccessToken))
    assert(keyAccessToken.byteLength > 0)

    const parameters = { key: serverStretchedPassword }
    Object.assign(parameters, serverKeyParameters)
    const serverKey = deriveKeyHelper(
      serverStretchedPassword, serverKeyParameters
    )
    const clientWrappedKey = xor(serverKey, serverWrappedKey)

    const tokenID = deriveKeyHelper(
      keyAccessToken, tokenIDParameters
    )
    const requestAuthenticationKey = deriveKeyHelper(
      keyAccessToken, requestAuthenticationKeyParameters
    )
    const keyRequestToken = deriveKeyHelper(
      keyAccessToken, keyRequestTokenParameters
    )

    const responseEncryptionKey = deriveKeyHelper(
      keyRequestToken, responseEncryptionKeyParameters
    )
    const responseAuthenticationKey = deriveKeyHelper(
      keyRequestToken, responseAuthenticationKeyParameters
    )

    const ciphertext = xor(clientWrappedKey, responseEncryptionKey)
    const mac = authenticate({
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

    const ciphertext = input.ciphertext
    assert(Buffer.isBuffer(ciphertext))

    const providedMAC = input.mac
    assert(Buffer.isBuffer(providedMAC))

    const clientStretchedPassword = input.clientStretchedPassword
    assert(Buffer.isBuffer(clientStretchedPassword))

    const keyAccessToken = input.keyAccessToken
    assert(Buffer.isBuffer(keyAccessToken))

    const keyRequestToken = deriveKeyHelper(
      keyAccessToken, keyRequestTokenParameters
    )

    const responseAuthenticationKey = deriveKeyHelper(
      keyRequestToken, responseAuthenticationKeyParameters
    )
    const responseEncryptionKey = deriveKeyHelper(
      keyRequestToken, responseEncryptionKeyParameters
    )

    const computedMAC = authenticate({
      key: responseAuthenticationKey,
      input: ciphertext
    })

    if (!providedMAC.equals(computedMAC)) return false

    const clientWrappedKey = xor(ciphertext, responseEncryptionKey)

    const clientKey = deriveKeyHelper(
      clientStretchedPassword, clientKeyParameters
    )

    const encryptionKey = xor(clientWrappedKey, clientKey)

    return { encryptionKey }
  }

  function deriveKeyHelper (key, parameters) {
    assert(Buffer.isBuffer(key))
    assert(typeof parameters === 'object')
    return deriveKey(Object.assign({ key }, parameters))
  }
}

function xor (a, b) {
  assert(a.length === b.length)
  const returned = Buffer.alloc(a.length)
  for (let offset = 0; offset < a.length; offset++) {
    returned[offset] = a[offset] ^ b[offset]
  }
  return returned
}
