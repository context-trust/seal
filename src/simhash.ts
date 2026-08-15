/* ═══════════════════════════════════════════════════════════════════
   SimHash 64-bit sobre texto — similaridade por distância de Hamming.

   Determinístico, puro, roda client+server (só BigInt + string). É
   metadado DECLARATIVO: vai em envelope.content.contentSimhash, NUNCA
   entra no compositeHash/assinatura (igual ao pHash de imagem).

   Uso: dois textos parecidos têm simhashes com poucos bits diferentes.
   Threshold sugerido p/ "quase-duplicado": Hamming ≤ 3 (de 64 bits).

   Charikar 2002 — weighted bit voting sobre hashes de tokens (uni + bi-grams).
   ═══════════════════════════════════════════════════════════════════ */

const MASK64 = 0xffffffffffffffffn

/** FNV-1a 64-bit de uma string → BigInt (determinístico, sem deps). */
function fnv1a64(str: string): bigint {
  let hash = 0xcbf29ce484222325n
  const prime = 0x100000001b3n
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i))
    hash = (hash * prime) & MASK64
  }
  return hash
}

/** Normaliza + tokeniza: unigrams + bigrams (captura ordem parcial). */
function tokenize(text: string): string[] {
  const norm = text
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')      // remove acentos (combining marks)
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')    // só letras/números/espaço
  const words = norm.split(/\s+/).filter(Boolean)
  if (words.length === 0) return []
  const tokens: string[] = [...words]
  for (let i = 0; i < words.length - 1; i++) tokens.push(words[i] + ' ' + words[i + 1])
  return tokens
}

/**
 * SimHash 64-bit → 16 hex chars. String vazia / sem tokens → 16 zeros.
 */
export function computeSimhash64(text: string): string {
  const tokens = tokenize(text)
  if (tokens.length === 0) return '0'.repeat(16)

  // peso = frequência do token
  const freq = new Map<string, number>()
  for (const t of tokens) freq.set(t, (freq.get(t) || 0) + 1)

  const v = new Array<number>(64).fill(0)
  for (const [token, w] of freq) {
    const h = fnv1a64(token)
    for (let i = 0; i < 64; i++) {
      const bitSet = ((h >> BigInt(i)) & 1n) === 1n
      v[i] += bitSet ? w : -w
    }
  }

  let out = 0n
  for (let i = 0; i < 64; i++) if (v[i] > 0) out |= (1n << BigInt(i))
  return out.toString(16).padStart(16, '0')
}

/** Distância de Hamming entre dois simhashes hex (16 chars). -1 se inválido. */
export function simhashHamming(a: string, b: string): number {
  if (!/^[0-9a-f]{16}$/i.test(a) || !/^[0-9a-f]{16}$/i.test(b)) return -1
  let x = (BigInt('0x' + a) ^ BigInt('0x' + b)) & MASK64
  let dist = 0
  while (x > 0n) {
    dist += Number(x & 1n)
    x >>= 1n
  }
  return dist
}
