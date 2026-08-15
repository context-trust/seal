/**
 * P107 — trava o que a migração para @noble/hashes 2.x + @noble/ed25519 3.x mudou.
 *
 * Estes testes não existiam antes porque o comportamento era ACIDENTAL: a v2 do
 * ed25519 tolerava hex string onde o tipo dizia Uint8Array, e ninguém percebia.
 * A v3 passou a exigir bytes. Agora o motor normaliza na fronteira, e é ISSO que
 * precisa ficar travado — senão a próxima pessoa "limpa" a normalização achando
 * que é redundante.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as pkg from '../dist/seal.js'

const vs = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
const vectors = Array.isArray(vs) ? vs : vs.vectors
const comAssinatura = vectors.find((v) => v.signature)
const hx = (h) => Uint8Array.from(h.match(/../g).map((b) => parseInt(b, 16)))

test('verifySignature aceita pubkey em HEX e em Uint8Array — mesmo veredito', async () => {
  const v = comAssinatura
  const porHex = await pkg.verifySignature(v.compositeHash, v.signature, v.pubkey)
  const porBytes = await pkg.verifySignature(v.compositeHash, v.signature, hx(v.pubkey))
  assert.equal(porHex, true, 'hex deveria validar')
  assert.equal(porBytes, true, 'bytes deveria validar')
  assert.equal(porHex, porBytes, 'as duas formas TÊM que dar o mesmo resultado')
})

test('🔒 e continua REPROVANDO adulterada nas duas formas — a tolerância não abre porta', async () => {
  const v = comAssinatura
  const ultimo = v.signature.slice(-1)
  const ruim = v.signature.slice(0, -1) + (ultimo === '0' ? '1' : '0')
  assert.equal(await pkg.verifySignature(v.compositeHash, ruim, v.pubkey), false)
  assert.equal(await pkg.verifySignature(v.compositeHash, ruim, hx(v.pubkey)), false)
})

test('⛔ formato errado FALHA com mensagem clara, não com TypeError críptico do @noble', async () => {
  const v = comAssinatura
  const casos = [
    ['pubkey curta demais', v.signature, 'ab'.repeat(16)],
    ['pubkey com caractere não-hex', v.signature, 'z'.repeat(64)],
    ['pubkey de 31 bytes', v.signature, new Uint8Array(31)],
  ]
  for (const [nome, sig, pub] of casos) {
    await assert.rejects(
      () => pkg.verifySignature(v.compositeHash, sig, pub),
      (e) => e instanceof TypeError && /publicKey/.test(e.message),
      `${nome}: deveria lançar TypeError citando publicKey`,
    )
  }
  await assert.rejects(
    () => pkg.verifySignature(v.compositeHash, 'ff'.repeat(10), v.pubkey),
    (e) => e instanceof TypeError && /signature/.test(e.message),
    'assinatura de tamanho errado deveria citar signature',
  )
})

test('🎓 o teste negativo reprova por CRIPTOGRAFIA, não por exceção de tipo', async () => {
  // Assinar os BYTES do hash em vez da string hex é a armadilha da SPEC §5.
  // Se isto passasse a lançar TypeError, o teste "passaria" pelo motivo errado.
  const v = comAssinatura
  const bytesDoHash = hx(v.compositeHash)
  const r = await pkg.verifySignature(
    new TextDecoder().decode(bytesDoHash) === v.compositeHash ? v.compositeHash : v.compositeHash + 'x',
    v.signature,
    v.pubkey,
  )
  assert.equal(typeof r, 'boolean', 'tem que devolver boolean, não lançar')
  assert.equal(r, false, 'hash alterado NÃO pode validar')
})

test('signHash aceita privateKey em hex e o resultado verifica', async () => {
  const kp = await pkg.generateKeyPair()
  const exp = await pkg.exportKeyPair(kp)
  const hash = pkg.hashContent('conteúdo de teste da P107')
  const assinaturaPorHex = await pkg.signHash(hash, exp.privateKey)
  const assinaturaPorBytes = await pkg.signHash(hash, kp.privateKey)
  assert.equal(assinaturaPorHex, assinaturaPorBytes, 'hex e bytes têm que assinar igual')
  assert.equal(await pkg.verifySignature(hash, assinaturaPorHex, exp.publicKey), true)
})
