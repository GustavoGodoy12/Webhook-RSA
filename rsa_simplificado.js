// rsa_simplificado.js
// — geração de par RSA + cifra/decifra

const crypto = require('crypto');

function generate_keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  return [publicKey, privateKey];
}

function encrypt(plaintext, pubKey) {
  return crypto.publicEncrypt(pubKey, Buffer.from(plaintext, 'utf8')).toString('base64');
}

function decrypt(ciphertext, privKey) {
  return crypto.privateDecrypt(privKey, Buffer.from(ciphertext, 'base64')).toString('utf8');
}

module.exports = { generate_keypair, encrypt, decrypt };
