// chat_http.js
// Chat HTTP assíncrono + RSA em JS puro (usa express, fetch, readline)

const express  = require('express');
const readline = require('readline');

// fetch nativo (Node ≥18) ou node-fetch
let fetchFn;
try { fetchFn = fetch; } catch { fetchFn = require('node-fetch'); }

const rsa = require('./rsa_puro');

const PORT = process.env.PORT || 5000;

(async () => {
  // entrada de teclado assíncrona 
  const rl  = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = q => new Promise(res => rl.question(q, ans => res(ans)));

  const PEER_URL = (await ask('Cole a URL (ou localhost) do outro ↦ '))
    .trim()
    .replace(/\/$/, '');

  // chaves locais 
  const [myPub, myPriv] = rsa.generate_keypair(); // padrão: 512 bits
  let peerPub = null;
  let hasSentPubOnce = false;

  // envia minha chave
  async function trySendMyPub() {
    if (peerPub) return;
    try {
      await fetchFn(`${PEER_URL}/msg`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pub: { e: myPub.e.toString(), n: myPub.n.toString() } }),
      });
      const first = !hasSentPubOnce;
      hasSentPubOnce = true;
      console.log(`⟳ [${PORT}] ${first ? '' : 'Retentando '}Handshake: enviei minha chave pública.`);
    } catch {
      const first = !hasSentPubOnce;
      hasSentPubOnce = true;
      console.log(`⚠ [${PORT}] ${first ? '' : 'Retentando '}Handshake: peer indisponível.`);
    }
  }

  // servidor HTTP 
  const app = express();
  app.use(express.json());

  app.post('/msg', async (req, res) => {
    const { pub, c, s } = req.body;

    // 1) chave pública recebida
    if (pub && !peerPub) {
      peerPub = { e: BigInt(pub.e), n: BigInt(pub.n) };
      console.log(`▶ [${PORT}] Chave pública do peer recebida!`);

      // devolve a nossa se ainda não mandou
      try {
        await fetchFn(`${PEER_URL}/msg`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pub: { e: myPub.e.toString(), n: myPub.n.toString() } }),
        });
        console.log(`⟳ [${PORT}] Respondendo: enviei minha chave pública.`);
      } catch (err) {
        console.log(`⚠ [${PORT}] Erro ao responder chave pública: ${err.message}`);
      }
    }

    // 2) mensagem cifrada
    if (c && s) {
      if (!peerPub) {
        console.log(`⚠ [${PORT}] Mensagem chegou antes do handshake; descartando.`);
      } else {
        try {
          const msg = rsa.decrypt(c, myPriv);
          const ok  = rsa.verify(msg, s, peerPub);
          console.log(`<peer> ${msg}   ${ok ? '✓' : '✗'}`);
        } catch (err) {
          console.error(`✖ [${PORT}] Erro decifrar/verificar: ${err.message}`);
        }
      }
    }
    res.json({ status: 'ok' });
  });

  // inicia servidor + tentativas de handshake 
  app.listen(PORT, async () => {
    console.log(`🔒 [${PORT}] Chat HTTP rodando em http://localhost:${PORT}`);
    await trySendMyPub();
    const id = setInterval(() => {
      if (!peerPub) trySendMyPub(); else { clearInterval(id); console.log(`✔ [${PORT}] Handshake concluído.`); }
    }, 3000);
  });

  // loop de envio (não bloqueia) 
  rl.on('line', async txt => {
    if (!txt.trim()) return;
    if (!peerPub) { console.log(`⌛ [${PORT}] Aguardando chave pública do peer...`); return; }

    try {
      const c = rsa.encrypt(txt, peerPub);
      const s = rsa.sign(txt, myPriv);
      await fetchFn(`${PEER_URL}/msg`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ c, s }),
      });
    } catch (err) {
      console.error(`✖ [${PORT}] Erro ao enviar mensagem: ${err.message}`);
    }
  });
})();
