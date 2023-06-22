// @ts-ignore
const AtomicFileRW = require('atomic-file-rw')
const Path = require('node:path')
const crypto = require('node:crypto')
const bs58 = require('bs58')
const b4a = require('b4a')

/**
 * @template T
 * @typedef {(...args: [NodeJS.ErrnoException] | [null, T]) => void} CB<T>
 */

/**
 * @typedef {Buffer | Uint8Array} B4A
 */

/**
 * @typedef {{type: 'follow'}} FollowPromise
 * @typedef {FollowPromise} PPromise
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
  },
  permissions: {
    anonymous: {
      allow: ['follow'],
    },
  },

  /**
   * @param {any} sstack
   * @param {any} config
   */
  init(sstack, config) {
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
        promise.type !== 'follow'
      ) {
        return Error('Invalid promise created: ' + JSON.stringify(promise))
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

    return { create, revoke, follow }
  },
}
