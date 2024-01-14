const test = require('node:test')
const assert = require('node:assert')
const Path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const p = require('node:util').promisify
const rimraf = require('rimraf')
const Keypair = require('ppppp-keypair')
const caps = require('ppppp-caps')

async function setup() {
  setup.counter ??= 0
  setup.counter += 1
  const path = Path.join(os.tmpdir(), 'ppppp-promise-' + setup.counter)
  rimraf.sync(path)
  const keypair = Keypair.generate('ed25519', 'alice')

  const peer = require('secret-stack/bare')()
    .use(require('secret-stack/plugins/net'))
    .use(require('secret-handshake-ext/secret-stack'))
    .use(require('ppppp-db'))
    .use(require('ppppp-set'))
    .use(require('../lib'))
    .call(null, {
      shse: { caps },
      global: {
        path,
        keypair,
      },
    })

  await peer.db.loaded()

  return { peer, path, keypair }
}

test('create()', async (t) => {
  const { peer, path } = await setup()

  const account = await p(peer.db.account.findOrCreate)({
    subdomain: 'account',
  })

  const promise = { type: 'follow', account }
  const token = await p(peer.promise.create)(promise)
  assert.strictEqual(typeof token, 'string')
  assert.ok(token.length > 42)

  const file = Path.join(path, 'promises.json')
  assert.ok(fs.existsSync(file), 'file exists')
  const contents = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contents, JSON.stringify([[token, promise]]))

  await p(peer.close)()
})

test('follow()', async (t) => {
  const { peer, path } = await setup()

  assert.rejects(() => p(peer.promise.follow)('randomnottoken', 'FRIEND_ID'))

  const account = await p(peer.db.account.findOrCreate)({
    subdomain: 'account',
  })
  await p(peer.set.load)(account)

  const promise = { type: 'follow', account }
  const token = await p(peer.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  assert.equal(peer.set.has('follows', 'FRIEND_ID'), false, 'not following')

  const result1 = await p(peer.promise.follow)(token, 'FRIEND_ID')
  assert.strictEqual(result1, true)

  assert.equal(peer.set.has('follows', 'FRIEND_ID'), true, 'following')

  const contentsAfter = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsAfter, '[]')

  assert.rejects(() => p(peer.promise.follow)(token, 'FRIEND_ID'))

  await p(peer.close)()
})

test('accountAdd()', async (t) => {
  const { peer, path, keypair } = await setup()

  assert.rejects(() => p(peer.promise.accountAdd)('randomnottoken', {}))

  const account = await p(peer.db.account.findOrCreate)({
    subdomain: 'account',
  })

  const promise = { type: 'account-add', account }
  const token = await p(peer.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  const dbBefore = [...peer.db.msgs()].map(({ data }) => data)
  assert.equal(dbBefore.length, 1)
  assert.equal(dbBefore[0].action, 'add')
  assert.equal(dbBefore[0].key.algorithm, 'ed25519')
  assert.equal(dbBefore[0].key.bytes, keypair.public)
  assert.equal(dbBefore[0].key.purpose, 'shs-and-sig')
  assert(dbBefore[0].nonce)

  const keypair2 = Keypair.generate('ed25519', 'bob')
  const consent = peer.db.account.consent({ account, keypair: keypair2 })
  const result1 = await p(peer.promise.accountAdd)(token, {
    key: {
      purpose: 'sig',
      algorithm: 'ed25519',
      bytes: keypair2.public,
    },
    consent,
  })
  assert.strictEqual(result1, true)

  const dbAfter = [...peer.db.msgs()].map(({ data }) => data)
  assert.equal(dbAfter.length, 2)
  assert.equal(dbAfter[0].action, 'add')
  assert.equal(dbAfter[0].key.algorithm, 'ed25519')
  assert.equal(dbAfter[0].key.bytes, keypair.public)
  assert.equal(dbAfter[0].key.purpose, 'shs-and-sig')
  assert(dbAfter[0].nonce)
  assert.equal(dbAfter[1].action, 'add')
  assert.equal(dbAfter[1].key.algorithm, 'ed25519')
  assert.equal(dbAfter[1].key.bytes, keypair2.public)
  assert.equal(dbAfter[1].key.purpose, 'sig')
  assert(dbAfter[1].consent)

  const contentsAfter = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsAfter, '[]')

  assert.rejects(() => p(peer.promise.accountAdd)(token, {}))

  await p(peer.close)()
})

test('revoke()', async (t) => {
  const { peer, path } = await setup()

  const account = await p(peer.db.account.findOrCreate)({
    subdomain: 'account',
  })

  const promise = { type: 'follow', account }
  const token = await p(peer.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  await p(peer.promise.revoke)(token)

  const contentsAfter = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsAfter, '[]')

  await p(peer.close)()
})
