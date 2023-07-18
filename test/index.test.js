const test = require('node:test')
const assert = require('node:assert')
const Path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const p = require('node:util').promisify
const rimraf = require('rimraf')
const Keypair = require('ppppp-keypair')
const caps = require('ppppp-caps')

function setup() {
  setup.counter ??= 0
  setup.counter += 1
  const path = Path.join(os.tmpdir(), 'ppppp-promise-' + setup.counter)
  rimraf.sync(path)
  const keypair = Keypair.generate('ed25519', 'alice')

  const local = require('secret-stack/bare')({ caps })
    .use(require('secret-stack/plugins/net'))
    .use(require('secret-handshake-ext/secret-stack'))
    .use(require('ppppp-db'))
    .use(require('../lib'))
    .call(null, {
      path,
      keypair,
    })

  return { local, path, keypair }
}

test('create()', async (t) => {
  const { local, path } = setup()

  const promise = { type: 'follow' }
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
  const { local, path } = setup()

  assert.rejects(() => p(local.promise.follow)('randomnottoken', 'MY_ID'))

  const promise = { type: 'follow' }
  const token = await p(local.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  const result1 = await p(local.promise.follow)(token, 'MY_ID')
  assert.strictEqual(result1, true)

  const contentsAfter = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsAfter, '[]')

  assert.rejects(() => p(local.promise.follow)(token, 'MY_ID'))

  await p(local.close)()
})

test('identityAdd()', async (t) => {
  const { local, path, keypair } = setup()

  assert.rejects(() => p(local.promise.identityAdd)('randomnottoken', {}))

  const identity = await p(local.db.identity.findOrCreate)({
    domain: 'account',
  })

  const promise = { type: 'identity-add', identity }
  const token = await p(local.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  const dbBefore = [...local.db.msgs()].map(({data}) => data)
  assert.equal(dbBefore.length, 1)
  assert.equal(dbBefore[0].action, 'add')
  assert.equal(dbBefore[0].add.key.algorithm, 'ed25519')
  assert.equal(dbBefore[0].add.key.bytes, keypair.public)
  assert.equal(dbBefore[0].add.key.purpose, 'sig')
  assert(dbBefore[0].add.nonce)

  const keypair2 = Keypair.generate('ed25519', 'bob')
  const consent = local.db.identity.consent({ identity, keypair: keypair2 })
  const result1 = await p(local.promise.identityAdd)(token, {
    key: {
      purpose: 'sig',
      algorithm: 'ed25519',
      bytes: keypair2.public,
    },
    consent,
  })
  assert.strictEqual(result1, true)

  const dbAfter = [...local.db.msgs()].map(({data}) => data)
  assert.equal(dbAfter.length, 2)
  assert.equal(dbAfter[0].action, 'add')
  assert.equal(dbAfter[0].add.key.algorithm, 'ed25519')
  assert.equal(dbAfter[0].add.key.bytes, keypair.public)
  assert.equal(dbAfter[0].add.key.purpose, 'sig')
  assert(dbAfter[0].add.nonce)
  assert.equal(dbAfter[1].action, 'add')
  assert.equal(dbAfter[1].add.key.algorithm, 'ed25519')
  assert.equal(dbAfter[1].add.key.bytes, keypair2.public)
  assert.equal(dbAfter[1].add.key.purpose, 'sig')
  assert(dbAfter[1].add.consent)

  const contentsAfter = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsAfter, '[]')

  assert.rejects(() => p(local.promise.identityAdd)(token, {}))

  await p(local.close)()
})

test('revoke()', async (t) => {
  const { local, path } = setup()

  const promise = { type: 'follow' }
  const token = await p(local.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  await p(local.promise.revoke)(token)

  const contentsAfter = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsAfter, '[]')

  await p(local.close)()
})
