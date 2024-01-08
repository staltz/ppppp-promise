// @ts-ignore
const AtomicFileRW = require('atomic-file-rw')
const Path = require('node:path')
const crypto = require('node:crypto')
const bs58 = require('bs58')
const b4a = require('b4a')

/**
 * @typedef {ReturnType<import('ppppp-db').init>} PPPPPDB
 * @typedef {ReturnType<import('ppppp-set').init>} PPPPPSet
 * @typedef {import('ppppp-db/msg-v4').AccountAdd} AccountAdd
 * @typedef {Buffer | Uint8Array} B4A
 * @typedef {{global: {path: string}}} ExpectedConfig
 * @typedef {{global: {path?: string}}} Config
 * @typedef {{type: 'follow', account: string}} FollowPromise
 * @typedef {{type: 'account-add', account: string}} AccountAddPromise
 * @typedef {FollowPromise | AccountAddPromise} PPromise
 */

/**
 * @template T
 * @typedef {(...args: [NodeJS.ErrnoException] | [null, T]) => void} CB<T>
 */

/**
 * @param {Config} config
 * @returns {asserts config is ExpectedConfig}
 */
function assertValidConfig(config) {
  if (typeof config.global?.path !== 'string') {
    throw new Error('promise plugin requires config.global.path')
  }
}

/**
 * @param {{ db: PPPPPDB; set: PPPPPSet }} peer
 * @param {Config} config
 */
function initPromise(peer, config) {
  assertValidConfig(config)
  const devicePromisesFile = Path.join(config.global.path, 'promises.json')

  const promises = /** @type {Map<string, PPromise>} */ (new Map())
  let loaded = false

  // Initial load
  AtomicFileRW.readFile(
    devicePromisesFile,
    /** @type {CB<B4A | string>} */ function onLoad(err, buf) {
      if (err) {
        if (err.code === 'ENOENT') {
          save((err, _) => {
            if (err) return console.log('Problem creating promises file:', err)
            else loaded = true
          })
          return
        }
        console.log('Problem loading promises file:', err)
        return
      }
      const json = typeof buf === 'string' ? buf : b4a.toString(buf, 'utf-8')
      const arr = JSON.parse(json)
      for (const [token, promise] of arr) {
        promises.set(token, promise)
      }
      loaded = true
    }
  )

  /**
   * @param {PPromise} promise
   * @return {Error | null}
   */
  function validatePromise(promise) {
    if (typeof promise !== 'object' || typeof promise.type !== 'string') {
      return Error('Invalid promise created: ' + JSON.stringify(promise))
    }
    switch (promise.type) {
      case 'follow':
      case 'account-add':
        if (typeof promise.account !== 'string') {
          // prettier-ignore
          return Error('Invalid promise missing "account" field: ' + JSON.stringify(promise))
        } else {
          break
        }
      default:
        return Error('Invalid promise type: ' + JSON.stringify(promise))
    }
    return null
  }

  /**
   * @param {CB<any>} cb
   */
  function save(cb) {
    const json = JSON.stringify([...promises])
    AtomicFileRW.writeFile(devicePromisesFile, json, cb)
  }

  /**
   * @param {PPromise} promise
   * @param {CB<string>} cb
   */
  function create(promise, cb) {
    if (!loaded) {
      setTimeout(() => create(promise, cb), 100)
      return
    }
    let err
    if ((err = validatePromise(promise))) return cb(err)

    const token = bs58.encode(crypto.randomBytes(32))
    promises.set(token, promise)
    save((err, _) => {
      // prettier-ignore
      if (err) return cb(new Error('Failed to save promise file when creating new promise', { cause: err }))
      cb(null, token)
    })
  }

  /**
   * @param {string} token
   * @param {string} accountID
   * @param {CB<boolean>} cb
   */
  function follow(token, accountID, cb) {
    if (!loaded) {
      setTimeout(() => follow(token, accountID, cb), 100)
      return
    }
    try {
    } catch (err) {
      cb(/**@type {Error}*/ (err))
      return
    }
    if (!promises.has(token)) {
      cb(new Error('Invalid token'))
      return
    }
    const promise = /** @type {PPromise} */ (promises.get(token))
    if (promise.type !== 'follow') {
      cb(new Error('Invalid token'))
      return
    }
    const myAccountID = promise.account
    const theirAccountID = accountID

    peer.set.load(myAccountID, (err) => {
      // prettier-ignore
      if (err) return cb(new Error(`Failed to load ppppp-set with account "${myAccountID}" when executing follow promise`, { cause: err }))
      if (peer.set.has('follow', theirAccountID)) {
        promises.delete(token)
        cb(null, false)
        return
      } else {
        peer.set.add('follow', theirAccountID, (err, _) => {
          // prettier-ignore
          if (err) return cb(new Error(`Failed to follow account "${theirAccountID}" in ppppp-set from account "${myAccountID}" when executing follow promise`, { cause: err }))
          promises.delete(token)
          save((err, _) => {
            // prettier-ignore
            if (err) return cb(new Error('Failed to save promise file when executing follow promise', { cause: err }))
            cb(null, true)
          })
        })
      }
    })
  }

  /**
   * @param {string} token
   * @param {AccountAdd} addition
   * @param {CB<boolean>} cb
   */
  function accountAdd(token, addition, cb) {
    if (!loaded) {
      setTimeout(() => accountAdd(token, addition, cb), 100)
      return
    }

    try {
    } catch (err) {
      cb(/**@type {Error}*/ (err))
      return
    }

    if (!addition?.consent) {
      // prettier-ignore
      cb(new Error('Invalid key to be added, missing "consent": ' + JSON.stringify(addition)))
      return
    }

    if (
      !addition?.key?.purpose ||
      !addition?.key?.algorithm ||
      !addition?.key?.bytes
    ) {
      // prettier-ignore
      cb(new Error('Invalid key to be added, missing purpose/algorithm/bytes: ' + JSON.stringify(addition)))
      return
    }

    const { algorithm, purpose } = addition.key
    switch (purpose) {
      case 'sig':
      case 'shs-and-sig':
        if (algorithm !== 'ed25519') {
          // prettier-ignore
          cb(new Error(`Invalid key to be added, expected algorithm "ed25519" for "${purpose}": ${JSON.stringify(addition)}`))
          return
        } else {
          break
        }
      case 'external-encryption':
        if (algorithm !== 'x25519-xsalsa20-poly1305') {
          // prettier-ignore
          cb(new Error(`Invalid key to be added, expected algorithm "x25519-xsalsa20-poly1305" for "${purpose}": ${JSON.stringify(addition)}`))
          return
        } else {
          break
        }
      default:
        // prettier-ignore
        cb(new Error(`Invalid key to be added, expected purpose "sig", "shs-and-sig", or "external-encryption": ${JSON.stringify(addition)}`))
        return
    }

    if (!promises.has(token)) {
      cb(new Error('Invalid token'))
      return
    }

    const promise = /** @type {AccountAddPromise} */ (promises.get(token))
    const { type, account } = promise
    if (type !== 'account-add') {
      cb(new Error('Invalid token'))
      return
    }

    const keypair = {
      curve: /**@type {const}*/ ('ed25519'),
      public: addition.key.bytes,
    }
    if (peer.db.account.has({ account, keypair })) {
      cb(null, false)
      return
    }

    peer.db.account.add(
      { account, keypair, consent: addition.consent },
      (err, rec) => {
        if (err) return cb(err)
        promises.delete(token)
        save(() => {
          cb(null, true)
        })
      }
    )
  }

  /**
   * @param {string} token
   * @param {CB<any>} cb
   */
  function revoke(token, cb) {
    if (!loaded) {
      setTimeout(() => revoke(token, cb), 100)
      return
    }

    promises.delete(token)
    save(cb)
  }

  return { create, revoke, follow, accountAdd }
}

exports.name = 'promise'
exports.needs = ['db', 'set']
exports.manifest = {
  // management
  create: 'async',
  revoke: 'async',
  // promises
  follow: 'async',
  accountAdd: 'async',
}
exports.init = initPromise
exports.permissions = {
  anonymous: {
    allow: ['follow', 'accountAdd'],
  },
}
