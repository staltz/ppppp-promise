// @ts-ignore
const AtomicFileRW = require('atomic-file-rw')
const Path = require('node:path')
const crypto = require('node:crypto')
const bs58 = require('bs58')
const b4a = require('b4a')

/**
 * @typedef {import('ppppp-db/msg-v3').AccountAdd} AccountAdd
 */

/**
 * @template T
 * @typedef {(...args: [NodeJS.ErrnoException] | [null, T]) => void} CB<T>
 */

/**
 * @typedef {Buffer | Uint8Array} B4A
 */

/**
 * @typedef {{type: 'follow'}} FollowPromise
 * @typedef {{type: 'account-add', account: string}} AccountAddPromise
 * @typedef {FollowPromise | AccountAddPromise} PPromise
 */

const FILENAME = 'promises.json'

module.exports = {
  name: 'promise',
  manifest: {
    // management
    create: 'async',
    revoke: 'async',
    // promises
    follow: 'async',
    accountAdd: 'async',
  },
  permissions: {
    anonymous: {
      allow: ['follow', 'accountAdd'],
    },
  },

  /**
   * @param {any} local
   * @param {any} config
   */
  init(local, config) {
    const devicePromisesFile = Path.join(config.path, FILENAME)

    const promises = /** @type {Map<string, PPromise>} */ (new Map())
    let loaded = false

    // Initial load
    AtomicFileRW.readFile(
      devicePromisesFile,
      /** @type {CB<B4A | string>} */ function onLoad(err, buf) {
        if (err) {
          if (err.code === 'ENOENT') {
            save((err, _) => {
              // prettier-ignore
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
      if (
        typeof promise !== 'object' ||
        typeof promise.type !== 'string' ||
        (promise.type !== 'follow' && promise.type !== 'account-add')
      ) {
        return Error('Invalid promise created: ' + JSON.stringify(promise))
      }
      if (
        promise.type === 'account-add' &&
        typeof promise.account !== 'string'
      ) {
        // prettier-ignore
        return Error('Invalid account-add promise missing "account" field: ' + JSON.stringify(promise))
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
        if (err) return cb(err)
        cb(null, token)
      })
    }

    /**
     * @param {string} token
     * @param {string} id
     * @param {CB<boolean>} cb
     */
    function follow(token, id, cb) {
      if (!loaded) {
        setTimeout(() => follow(token, id, cb), 100)
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
      console.log('ppppp-promise mock follow') // FIXME: implement follow
      promises.delete(token)
      save(() => {
        cb(null, true)
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
      if (
        !addition?.key?.purpose ||
        !addition?.key?.algorithm ||
        !addition?.key?.bytes ||
        !addition?.consent ||
        addition?.key?.purpose !== 'sig' ||
        addition?.key?.algorithm !== 'ed25519'
      ) {
        cb(new Error('Invalid key to be added: ' + JSON.stringify(addition)))
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

      const keypair = { curve: 'ed25519', public: addition.key.bytes }
      if (local.db.account.has({ account, keypair })) {
        cb(null, false)
        return
      }

      local.db.account.add(
        { account, keypair, consent: addition.consent },
        /**
         * @param {Error | null} err
         * @param {any} rec
         */
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
  },
}
