
function randomBigInt(bits) {
  const bytes = Math.ceil(bits / 8);
  let n = 0n;
  for (let i = 0; i < bytes; i++) {
    const byte = Math.floor(Math.random() * 256);
    n = (n << 8n) | BigInt(byte);
  }
  // garante tamanho exato e MSB = 1
  const excess = (bytes * 8) - bits;
  if (excess > 0) n &= (1n << BigInt(bits)) - 1n;
  n |= 1n << BigInt(bits - 1);            // força bit mais alto
  n |= 1n;                                // força ímpar
  return n;
}

function modPow(base, exp, mod) {
  let res = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) res = (res * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return res;
}

function egcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}
const modInv = (x, m) => {
  const [g, a] = egcd(x, m);
  if (g !== 1n) throw new Error('inverso não existe');
  return (a % m + m) % m;
};

// primalidade (Miller-Rabin)
const smallPrimes = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];

function isProbablePrime(n, k = 8) {
  if (n < 2n || n % 2n === 0n) return n === 2n;
  for (const p of smallPrimes) if (n === p) return true;
  for (const p of smallPrimes) if (n % p === 0n) return false;

  // escreve n−1 = d·2ʳ
  let r = 0n, d = n - 1n;
  while ((d & 1n) === 0n) { d >>= 1n; r++; }

  const randBetween = (min, max) => {
    const range = max - min;
    let rnd;
    do {
      rnd = randomBigInt(range.toString(2).length);
    } while (rnd > range);
    return min + rnd;
  };

  for (let i = 0; i < k; i++) {
    const a = randBetween(2n, n - 2n);
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let continueOuter = false;
    for (let j = 1n; j < r; j++) {
      x = (x * x) % n;
      if (x === n - 1n) { continueOuter = true; break; }
    }
    if (continueOuter) continue;
    return false;
  }
  return true;
}

function generatePrime(bits) {
  while (true) {
    const p = randomBigInt(bits);
    if (isProbablePrime(p)) return p;
  }
}

// ───────── API pública ─────────
function generate_keypair(bits = 512) {          // 512 == rápido; aumente se quiser
  const e = 65537n;
  let p, q, phi;
  do {
    p = generatePrime(bits / 2);
    q = generatePrime(bits / 2);
    phi = (p - 1n) * (q - 1n);
  } while (phi % e === 0n);
  const n = p * q;
  const d = modInv(e, phi);
  return [{ e, n }, { d, n }];
}

const textToBig = txt => BigInt('0x' + Buffer.from(txt, 'utf8').toString('hex'));
const bigToText = big => {
  let hex = big.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return Buffer.from(hex, 'hex').toString('utf8');
};

// Cifra / decifra (assume msg < n)
const encrypt = (txt, pub)  => modPow(textToBig(txt),       pub.e, pub.n).toString(16);
const decrypt = (hex, priv) => bigToText(modPow(BigInt('0x' + hex), priv.d, priv.n));

// Assinatura simplificada: sign = msgᴰ mod n  (sem hash)
// (usa o próprio texto convertido para BigInt; se ultrapassar n, faz módulo n)
const sign   = (txt, priv) => modPow(textToBig(txt) % priv.n, priv.d, priv.n).toString(16);
const verify = (txt, sig, pub) =>
  (textToBig(txt) % pub.n) === modPow(BigInt('0x' + sig), pub.e, pub.n);

module.exports = { generate_keypair, encrypt, decrypt, sign, verify };
