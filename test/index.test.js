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

  const stack = require('secret-stack/lib/api')([], {})
    .use(require('secret-stack/lib/core'))
    .use(require('secret-stack/lib/plugins/net'))
    .use(require('secret-handshake-ext/secret-stack'))
    .use(require('../lib'))
    .call(null, {
      path,
      caps,
      keypair,
    })

  return { stack, path, keypair }
}

test('create()', async (t) => {
  const { stack, path } = setup()

  const promise = { type: 'follow' }
  const token = await p(stack.promise.create)(promise)
  assert.strictEqual(typeof token, 'string')
  assert.ok(token.length > 42)

  const file = Path.join(path, 'promises.json')
  assert.ok(fs.existsSync(file), 'file exists')
  const contents = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contents, JSON.stringify([[token, promise]]))

  await p(stack.close)()
})

test('follow()', async (t) => {
  const { stack, path } = setup()

  assert.rejects(() => p(stack.promise.follow)('randomnottoken', 'MY_ID'))

  const promise = { type: 'follow' }
  const token = await p(stack.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  const result1 = await p(stack.promise.follow)(token, 'MY_ID')
  assert.strictEqual(result1, true)

  const contentsAfter = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsAfter, '[]')

  assert.rejects(() => p(stack.promise.follow)(token, 'MY_ID'));

  await p(stack.close)()
})

test('revoke()', async (t) => {
  const { stack, path } = setup()

  const promise = { type: 'follow' }
  const token = await p(stack.promise.create)(promise)

  const file = Path.join(path, 'promises.json')
  const contentsBefore = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsBefore, JSON.stringify([[token, promise]]))

  await p(stack.promise.revoke)(token)

  const contentsAfter = fs.readFileSync(file, 'utf-8')
  assert.strictEqual(contentsAfter, '[]')

  await p(stack.close)()
})
