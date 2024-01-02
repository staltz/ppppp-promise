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

  const local = require('secret-stack/bare')()
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

  await local.db.loaded()

  return { local, path, keypair }
}

test('create()', async (t) => {
  const { local, path } = await setup()

  const account = await p(local.db.account.findOrCreate)({
    subdomain: 'account',
  })

  const promise = { type: 'follow', account }
  const token = await p(local.promise.create)(promise)
  assert.strictEqual(typeof token, 'string')
  assert.ok(token.length > 42)

  const file = Path.join(path, 'promises.json')
  assert.ok(fs.existsSync(file), 'file exists')
  const contents = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contents, JSON.stringify([[token, promise]]))

  await p(local.close)()
})

test('follow()', async (t) => {
  const { local, path } = await setup()

  assert.rejects(() => p(local.promise.follow)('randomnottoken', 'FRIEND_ID'))

  const account = await p(local.db.account.findOrCreate)({
    subdomain: 'account',
  })
  await p(local.set.load)(account)

  const promise = { type: 'follow', account }
  const token = await p(local.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  assert.equal(local.set.has('follow', 'FRIEND_ID'), false, 'not following')

  const result1 = await p(local.promise.follow)(token, 'FRIEND_ID')
  assert.strictEqual(result1, true)

  assert.equal(local.set.has('follow', 'FRIEND_ID'), true, 'following')

  const contentsAfter = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsAfter, '[]')

  assert.rejects(() => p(local.promise.follow)(token, 'FRIEND_ID'))

  await p(local.close)()
})

test('accountAdd()', async (t) => {
  const { local, path, keypair } = await setup()

  assert.rejects(() => p(local.promise.accountAdd)('randomnottoken', {}))

  const account = await p(local.db.account.findOrCreate)({
    subdomain: 'account',
  })

  const promise = { type: 'account-add', account }
  const token = await p(local.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  const dbBefore = [...local.db.msgs()].map(({ data }) => data)
  assert.equal(dbBefore.length, 1)
  assert.equal(dbBefore[0].action, 'add')
  assert.equal(dbBefore[0].key.algorithm, 'ed25519')
  assert.equal(dbBefore[0].key.bytes, keypair.public)
  assert.equal(dbBefore[0].key.purpose, 'shs-and-sig')
  assert(dbBefore[0].nonce)

  const keypair2 = Keypair.generate('ed25519', 'bob')
  const consent = local.db.account.consent({ account, keypair: keypair2 })
  const result1 = await p(local.promise.accountAdd)(token, {
    key: {
      purpose: 'sig',
      algorithm: 'ed25519',
      bytes: keypair2.public,
    },
    consent,
  })
  assert.strictEqual(result1, true)

  const dbAfter = [...local.db.msgs()].map(({ data }) => data)
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

  assert.rejects(() => p(local.promise.accountAdd)(token, {}))

  await p(local.close)()
})

test('revoke()', async (t) => {
  const { local, path } = await setup()

  const account = await p(local.db.account.findOrCreate)({
    subdomain: 'account',
  })

  const promise = { type: 'follow', account }
  const token = await p(local.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  await p(local.promise.revoke)(token)

  const contentsAfter = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsAfter, '[]')

  await p(local.close)()
})
