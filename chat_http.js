//O script inicializa um servidor HTTP em Express e, simultaneamente, 
// cria um par de chaves RSA local; ele pede ao usuário a URL do peer e 
// tenta periodicamente enviar sua chave pública em um POST para /msg até receber, do outro lado, 
// a chave pública oposta. A rota POST /msg funciona como um webhook interno que, ao receber {pub}, 
// armazena a chave pública do peer e devolve a própria, ou, ao receber {c, s},
//  descriptografa a mensagem com a chave privada local, verifica a assinatura usando a 
// chave pública do peer e exibe o texto no console. Quando o usuário digita algo no terminal, 
// o código criptografa e assina a mensagem com RSA antes de enviá-la ao peer via POST para /msg, garantindo confidencialidade e
// autenticidade em todo o fluxo.

const express  = require('express');
const readline = require('readline');

// fetch nativo do node
let fetchFn;
try { fetchFn = fetch; } catch { fetchFn = require('node-fetch'); }

const rsa = require('./rsa_puro');

const PORT = process.env.PORT || 5000;

//aqui criei uma função principal assíncrona que inicia o chat
(async () => {
  //garanto input
  //cria uma interface de leitura baseada no process.stdin e process.stdout , que garante o input e output do terminal processando linha por linha
  const rl  = readline.createInterface({ input: process.stdin, output: process.stdout });
  //aguarda resposta
  //define uma funcao do ask que recebe um prompt q e aguarda até que o usuário digite uma resposta, e retorna como uma promisse
  const ask = q => new Promise(res => rl.question(q, ans => res(ans)));

  // solicita a URL do peer no terminal 
  const PEER_URL = (await ask('Cole a URL (ou localhost) do outro ↦ '))
  //aqui removo espaços em branco no início e no final da URL, e removo a barra final se existir
    .trim()
    .replace(/\/$/, '');

  // aqui eu chamo uma função de geração de chave RSA, que gera um par de chaves pública e privada dentro de um array
  const [myPub, myPriv] = rsa.generate_keypair(); 
  //guardo a chave pública em uma variável para enviar ao peer, assim que ele chegar via HTTP
  //antes de existir um valor válido, a variável peerPub é nula
  let peerPub = null;
  //uso para log apenas para verificar se já enviei a chave pública uma vez pelo menos
  let hasSentPubOnce = false;

  // declaro uma funçao assíncrona que tenta enviar minha chave pública para o peer
  //fico chamando ela logo apos iniciar o server e fico enviando em tempo em tempo até que o peer responda com a chave pública dele
  async function trySendMyPub() {
    //se a peerbub já tiver sido recebida, não precisa enviar novamente, e quando handshake for concluído, não precisa enviar mais
    if (peerPub) return;
    //tento enviar minha chave pública para o peer via HTTP POST
    //no corpo eu envio um objeto JSON com a chave pública e converto os BigInts para strings para poder passar via json
    //se ela der 200 o peer já recebeu minha chave pública 
    try {
      await fetchFn(`${PEER_URL}/msg`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pub: { e: myPub.e.toString(), n: myPub.n.toString() } }),
      });
      //eu vejo no first se é a primeira vez que estou enviando a chave pública, e seto hasSentPubOnce para true
      //isso é só para log, não afeta o funcionamento do chat
      const first = !hasSentPubOnce;
      hasSentPubOnce = true;
      console.log(`⟳ [${PORT}] ${first ? '' : 'Retentando '}Handshake: enviei minha chave pública.`);
      //se der erro de conex ou timeout, geralmente é porque o peer não está rodando  e pego log
    } catch {
      const first = !hasSentPubOnce;
      hasSentPubOnce = true;
      console.log(`⚠ [${PORT}] ${first ? '' : 'Retentando '}Handshake: peer indisponível.`);
    }
  }

  //tudo vou jogar no express que defini, - app no caso
  const app = express();
  //defino o content type de applicatoin/json
  app.use(express.json());

  app.post('/msg', async (req, res) => {
    //JSON RECEBIDO =  COM 3 CAMPOS QUE TEM QUE SER EXTRAIDOS
    // aqui na mensagem eu divido o corpo da req, pub = quando o peer envia a chave pública dele, c = quando envia uma mensagem cifrada, 
    // s = assinatura condiz com a a mensagem cifrada
    const { pub, c, s } = req.body;

    //vejo se não recebi nenhuma chave ainda ainda e se o pub ta preenchido com a chave publica 
    if (pub && !peerPub) {
      //converto de novo para bigint, e ai o objeto peerPub recebe a chave pública do peer. uso para o E/N para ser usada depois
      //para criptografar e verificar mensagens
      peerPub = { e: BigInt(pub.e), n: BigInt(pub.n) };
      console.log(`▶ [${PORT}] Chave pública do peer recebida!`);

      // responder de volta a propria URL com minha chave pública
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

    // se o json tiver c e s, significa que é uma mensagem cifrada com assinatura
    if (c && s) {
      //se n receber a chave pública do peer ainda, não posso decifrar/verificar a mensagem, a mensagem veio cifrada antes do handshake
      if (!peerPub) {
        console.log(`⚠ [${PORT}] Mensagem chegou antes do handshake; descartando.`);
        //se o handshake der boa, chamo o decrypt passando o c - que é o meu chiphertext e o myPriv - que é minha chave privada
        //isso vai retornar o texto original da mensagem cifrada, por que só eu tenho a chave privada para conseguir decripitar
      } else {
        try {
          const msg = rsa.decrypt(c, myPriv);
          //passo o texto que acabei de decriptar e a assinatura s que veio junto e a chave publica do peer que supostamente assinou a mensagem
          // se a assinatura for válida, garantindo que a msg foi do mesmo da chave privada que corresponde ao peerPub, e retorno no verify
          const ok  = rsa.verify(msg, s, peerPub);
          console.log(`<peer> ${msg}   ${ok ? '✓' : '✗'}`);
        } catch (err) {
          console.error(`✖ [${PORT}] Erro decifrar/verificar: ${err.message}`);
        }
      }
    }
    res.json({ status: 'ok' });
  });

  // fazco com o express escutar na porta definida assincronamente
  app.listen(PORT, async () => {
    console.log(`🔒 [${PORT}] Chat HTTP rodando em http://localhost:${PORT}`);
    //assim que o servidor rodar eu tento enviar ja a chave publica ao peer , com ping 
    await trySendMyPub();
    //tento enviar a cada 3seg quando a peerbub é null
    const id = setInterval(() => {
      if (!peerPub) trySendMyPub(); else { clearInterval(id); console.log(`✔ [${PORT}] Handshake concluído.`); }
    }, 3000);
  });

  // assim q user digita algo no chat registro um listener para o evento 'line' do readline, qeu qnd user digita o callback é executado
  rl.on('line', async txt => {
    //se for vazio ignora
    if (!txt.trim()) return;
    if (!peerPub) { console.log(`⌛ [${PORT}] Aguardando chave pública do peer...`); return; }

    //sempre que o peer manda algo, tanto uma chave publica ou mensagem cifrada ele faz o post para /msg

    //uso a funcao do encrypt passando o txt e a chave public do peer - o C é a mensagem cifrada
    try {
      const c = rsa.encrypt(txt, peerPub);
      //o objeto s da assinatura que será verificada
      const s = rsa.sign(txt, myPriv);
      await fetchFn(`${PEER_URL}/msg`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        //pelo fetch nativo ja envia o json 
        body: JSON.stringify({ c, s }),
      });
    } catch (err) {
      console.error(`✖ [${PORT}] Erro ao enviar mensagem: ${err.message}`);
    }
  });
})();
