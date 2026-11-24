/**
 * Backend que conecta o Portal Grupoprima ao Google Drive — e, a partir
 * desta versão, também ao Firestore (banco real de documentos confirmados,
 * fila de conferência, homologações e auditoria) e a um upload real de
 * arquivo novo direto na pasta oficial do Drive.
 *
 * Objetivo desta versão: o portal publicado FORA do claude.ai (hoje em
 * GitHub Pages) deixa de depender de qualquer capability do Artifact
 * (`db`, `assets`, `mcp`) para suas partes "vivas" — tudo passa a falar
 * com ESTE backend, que é o único lugar com a credencial real do Google.
 *
 * Rotas de leitura de arquivo (inalteradas desta versão anterior):
 *  GET /files
 *      Lista os DOCUMENTOS (arquivos reais, nunca pastas) que existem
 *      dentro da pasta oficial — navegando recursivamente por dentro de
 *      QUALQUER subpasta que exista lá. Cada item já vem com o caminho da
 *      subpasta onde foi encontrado (campo `pasta`). Só metadados — não
 *      baixa o conteúdo aqui.
 *
 *  GET /api/documents/:id/file
 *      Devolve o arquivo original (binário) de um arquivo específico,
 *      IDENTIFICADO PELO driveFileId.
 *
 * Rotas novas — banco de dados (Firestore), coleções fixas e conhecidas
 * (nunca uma coleção arbitrária vinda de fora):
 *  GET    /api/db/:collection            lista todos os documentos
 *  PUT    /api/db/:collection/:id        grava/substitui um documento (set)
 *  POST   /api/db/:collection            cria um documento com id automático (add)
 *  DELETE /api/db/:collection/:id        remove um documento
 *
 * Rota nova (2026-11) — Chat com Claude: POST /api/chat/claude (um turno do assistente
 *  do Dashboard; usa ANTHROPIC_API_KEY e CLAUDE_ANALYSIS_MODEL já existentes; opcionais
 *  CLAUDE_CHAT_MODEL, CLAUDE_CHAT_EFFORT, CHAT_LIMITE_CHAMADAS_HORA/DIA, CHAT_LIMITE_GLOBAL_DIA). Ver bloco "CHAT COM CLAUDE".
 *
 * Rota nova (2026-09-22) — Análise Documental de Clientes (Fase 2):
 *  POST /api/client-analysis
 *      Recebe { id, clienteNome, documentos: [{ nome, textoExtraido }] } —
 *      só o TEXTO já extraído no navegador (pdf.js/OCR/mammoth/SheetJS),
 *      nunca o binário original — e chama de fato a API da Anthropic para
 *      ler e resumir os documentos do cliente (obrigações, riscos, prazos,
 *      valores, seguros, exigências documentais), no mesmo formato que o
 *      mock do frontend (mockClientAnalysis) já usava. Devolve
 *      { ok: true, resultado } — este endpoint NUNCA grava no Firestore
 *      sozinho, quem grava continua sendo o próprio portal (mesmo caminho
 *      que já gravava o resultado do mock), para manter um único lugar de
 *      escrita desse registro. Mesma linha de proteção que motivou a
 *      desativação total do Gemini em 2026-09-17: esta IA só LÊ e RESUME o
 *      que foi enviado, nunca decide sozinha o que fazer com um documento.
 *      Exige ANTHROPIC_API_KEY e CLAUDE_ANALYSIS_MODEL configuradas no
 *      ambiente (Secret Manager) — nunca no código-fonte nem em nenhum
 *      arquivo servido ao navegador. Ver notas de deploy no final do
 *      arquivo.
 *
 * Rota nova — upload real de arquivo novo:
 *  POST /api/documents/upload-file
 *      multipart/form-data: campo "arquivo" (o binário, obrigatório). Sobe
 *      o arquivo real para a pasta oficial do Drive (subpasta "Enviados
 *      pelo Portal", criada uma única vez) e devolve os metadados reais do
 *      arquivo criado (driveFileId, nome, tipo, tamanho) — SEM gravar nada
 *      no índice. Espelha de propósito o mesmo contrato que a capability
 *      "assets" do Artifact já tinha (persistir o binário, devolver um id
 *      real) — quem chama continua responsável por, depois, gravar o
 *      registro em documentos_confirmados via PUT /api/db/... (mesma rota
 *      genérica de banco acima), do jeito que o portal já fazia com
 *      `assetId`. Mantém as duas etapas (upload do binário e indexação)
 *      separadas de propósito: no portal, o upload acontece assim que a
 *      pessoa escolhe o arquivo, e a indexação só depois que ela confirma
 *      a classificação — igual já era com "assets".
 *
 * Segurança:
 *  - Todas as rotas exigem a mesma chave simples (BACKEND_ACCESS_KEY) no
 *    header "X-Portal-Key" — não é autenticação de usuário (não distingue
 *    quem é Iasmin de outra pessoa), é a barreira mínima enquanto não há
 *    login real no backend. Ver notas de deploy no final do arquivo.
 *  - As rotas de arquivo continuam verificando que o arquivo pedido está
 *    de fato dentro da árvore de DRIVE_FOLDER_ID antes de servir.
 *  - Este serviço agora tem escopo de ESCRITA no Drive (antes era só
 *    leitura) — necessário para o upload real funcionar. A pasta oficial
 *    precisa estar compartilhada com a conta de serviço como Editor (não
 *    só Leitor como antes) — ver notas de deploy.
 */

const express = require("express");
const multer = require("multer");
const { google } = require("googleapis");
const { Firestore, FieldValue } = require("@google-cloud/firestore");
const { Readable } = require("stream");
const { OAuth2Client } = require("google-auth-library");
const nodemailer = require("nodemailer");

const app = express();
// Limite subido de 2mb para 20mb em 2026-09-22: o novo endpoint
// /api/client-analysis recebe o TEXTO já extraído de vários documentos de
// cliente (contratos, anexos comerciais) de uma vez só — texto extraído de
// PDFs grandes pode passar de 2mb somado. As demais rotas JSON (/api/db/...)
// continuam com corpos pequenos, então o limite maior não muda o
// comportamento delas.
app.use(express.json({ limit: "20mb" }));

// ---------------------------------------------------------------------
// CORS: aceita UMA OU MAIS origens em ALLOWED_ORIGIN, separadas por
// vírgula (ex.: "https://iasmincruz555.github.io,https://claude.site") —
// necessário porque o mesmo backend agora serve tanto o portal publicado
// no GitHub Pages quanto a prévia dentro do Artifact. Sem essa variável
// definida, cai em "*" (aberto) só para não travar testes locais — isso é
// inseguro e deve ser corrigido antes de produção (ver notas no final).
// ---------------------------------------------------------------------
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGIN || "*")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
if (ALLOWED_ORIGINS.includes("*")) {
  console.warn(
    "[aviso] ALLOWED_ORIGIN não definida (ou contém \"*\") — CORS está aberto para " +
      "qualquer origem. Defina ALLOWED_ORIGIN com os domínios reais do portal antes " +
      "de ir para produção."
  );
}

app.use((req, res, next) => {
  const origin = req.get("Origin");
  if (ALLOWED_ORIGINS.includes("*")) {
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, PUT, POST, DELETE, OPTIONS");
  // "Authorization" foi acrescentado para o módulo Viagens e Despesas (token do Firebase Auth).
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Portal-Key, X-Portal-Session, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ---------------------------------------------------------------------
// Chave de acesso simples (defesa mínima) — igual à versão anterior.
// ---------------------------------------------------------------------
const BACKEND_ACCESS_KEY = process.env.BACKEND_ACCESS_KEY || null;
if (!BACKEND_ACCESS_KEY) {
  console.warn(
    "[aviso] BACKEND_ACCESS_KEY não definida — as rotas estão SEM nenhuma chave de acesso. " +
      "Qualquer pessoa com a URL consegue listar, baixar e ESCREVER documentos. " +
      "Defina BACKEND_ACCESS_KEY antes de ir para produção."
  );
}

function exigirChaveSomente(req, res, next) {
  if (!BACKEND_ACCESS_KEY) return next(); // sem chave configurada: modo aberto (só para dev local)
  const recebida = req.get("X-Portal-Key");
  if (recebida !== BACKEND_ACCESS_KEY) {
    return res.status(401).json({ erro: "Acesso não autorizado." });
  }
  next();
}

// ID da pasta oficial do Google Drive que este serviço tem permissão de
// servir: "PORTAL DOCUMENTAL | GRUPOPRIMA".
const DRIVE_FOLDER_ID =
  process.env.DRIVE_FOLDER_ID || "1n3uwQkMA6qCGaBi7g2kcHSsE2TIi8uSN";
// ID do Drive Compartilhado ("Portal Documental Grupoprima") onde a pasta
// oficial vive desde 2026-09-14 (migração de "Meu Drive" para um Drive
// Compartilhado). NECESSÁRIO em toda chamada `drive.files.list(...)` que
// busca o CONTEÚDO de uma pasta dentro de um Drive Compartilhado — sem
// `corpora: "drive"` + este `driveId`, a API do Google não retorna erro
// nenhum, só devolve uma lista vazia (causa raiz real de "GET /files"
// voltar `total: 0` depois da migração, diagnosticada em 2026-09-14/15
// via rota de diagnóstico temporária `/debug/quem-sou`). `drive.files.get`
// (busca por um ID específico) não precisa disso, só `supportsAllDrives`.
const DRIVE_ID =
  process.env.DRIVE_ID || "0AOGKdPj3tXYIUk9PVA";

function carregarCredenciais() {
  const b64 = process.env.GOOGLE_SERVICE_ACCOUNT_KEY_B64;
  if (b64) {
    return JSON.parse(Buffer.from(b64, "base64").toString("utf-8"));
  }
  const bruto = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  if (bruto) return JSON.parse(bruto);

  throw new Error(
    "Nenhuma credencial configurada. Defina GOOGLE_SERVICE_ACCOUNT_KEY_B64 (ou GOOGLE_SERVICE_ACCOUNT_KEY)."
  );
}

const credentials = carregarCredenciais();

// Escopo ampliado: antes só "drive.readonly". O upload real de documento
// novo exige escrita — por isso agora é "drive" (leitura + escrita), e a
// pasta oficial precisa estar compartilhada com a conta de serviço como
// Editor (não só Leitor). Sem isso, GET /files e GET /api/documents/:id/file
// continuam funcionando normalmente (são só leitura), mas o upload falha.
const auth = new google.auth.GoogleAuth({
  credentials,
  scopes: ["https://www.googleapis.com/auth/drive"],
});

const drive = google.drive({ version: "v3", auth });

// Firestore: usa a MESMA conta de serviço (precisa do papel "Cloud
// Datastore User" / roles/datastore.user no projeto — ver notas de
// deploy). databaseId "(default)" é o padrão de um projeto com Firestore
// em modo Nativo já criado.
const firestore = new Firestore({ credentials });

/** montarContentDisposition: cabeçalho seguro para QUALQUER nome de arquivo
 *  (acentos, aspas, quebras de linha, emoji). `filename=` leva só ASCII
 *  imprimível (sem aspas/barras); `filename*=` leva o nome real em UTF-8. */
function montarContentDisposition(tipo, nome) {
  const original = String(nome || "arquivo");
  const ascii =
    original
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^\x20-\x7e]/g, "_")
      .replace(/["\\]/g, "_")
      .trim() || "arquivo";
  const utf8 = encodeURIComponent(original).replace(
    /['()*]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase()
  );
  return `${tipo}; filename="${ascii}"; filename*=UTF-8''${utf8}`;
}

const FOLDER_MIME_TYPE = "application/vnd.google-apps.folder";

/** Confere se o arquivo pertence à árvore da pasta autorizada, subindo a
 *  cadeia de pastas-mãe a partir dele. */
async function pertenceAPastaAutorizada(fileId) {
  let idAtual = fileId;
  for (let nivel = 0; nivel < 8; nivel++) {
    const meta = await drive.files.get({
      fileId: idAtual,
      fields: "id, parents",
      supportsAllDrives: true,
    });
    const pais = meta.data.parents || [];
    if (pais.includes(DRIVE_FOLDER_ID)) return true;
    if (pais.length === 0) return false;
    idAtual = pais[0];
  }
  return false;
}

/** Percorre recursivamente a árvore de pastas a partir de `pastaId`,
 *  coletando todos os ARQUIVOS reais (nunca pastas) encontrados em
 *  qualquer nível, junto com o caminho de subpastas onde cada um está. */
// Pastas de uso INTERNO do portal, na raiz do Drive oficial: nunca fazem
// parte da documentação das Bases e NUNCA devem aparecer na sincronização
// nem na fila "Necessita de conferência" (pedido explícito da Iasmin,
// 2026-10-05, com prints). O download/visualização desses arquivos continua
// funcionando normalmente por id (GET /api/documents/:id/file) — só a
// LISTAGEM (GET /files, usada pela sincronização) deixa de enumerá-los.
//  - "HOMOLOGAÇÃO - ARQUIVOS DE RESPOSTA": anexos de resposta da Homologação;
//  - "INFORMAÇÕES FINANCEIRAS": respostas dos clientes (aba Informações
//    Financeiras).
//  - "PORTAL" (2026-10-08, reorganização do Drive pedida pela Iasmin): pasta-mãe
//    que agrupa TUDO que o próprio portal grava — "Enviados pelo Portal",
//    "ENVIO DE DOCUMENTAÇÕES EM LOTE", "HOMOLOGAÇÃO - ARQUIVOS DE RESPOSTA" e
//    "INFORMAÇÕES FINANCEIRAS". As documentações das bases ficam na pasta
//    irmã ("BASES GRUPOPRIMA LOGÍSTICA"), que continua sendo sincronizada.
const NOME_PASTA_PORTAL = process.env.PASTA_PORTAL_NOME || "PORTAL";
const PASTAS_INTERNAS_FORA_DA_SINCRONIZACAO = ["HOMOLOGAÇÃO - ARQUIVOS DE RESPOSTA", "INFORMAÇÕES FINANCEIRAS", NOME_PASTA_PORTAL];
function normalizarNomePasta(nome) {
  return String(nome || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .trim()
    .toLowerCase();
}
function ehPastaInternaForaDaSincronizacao(nome) {
  const alvo = normalizarNomePasta(nome);
  return PASTAS_INTERNAS_FORA_DA_SINCRONIZACAO.some((n) => normalizarNomePasta(n) === alvo);
}
async function listarArquivosRecursivo(pastaId, caminho = []) {
  const result = await drive.files.list({
    q: `'${pastaId}' in parents and trashed = false`,
    fields: "files(id, name, mimeType, size, modifiedTime)",
    pageSize: 200,
    orderBy: "name",
    supportsAllDrives: true,
    includeItemsFromAllDrives: true,
    corpora: "drive",
    driveId: DRIVE_ID,
  });

  const itens = result.data.files || [];
  const arquivos = [];

  for (const item of itens) {
    if (item.mimeType === FOLDER_MIME_TYPE) {
      // Só na RAIZ do Drive oficial (caminho vazio): pasta interna do portal.
      if (caminho.length === 0 && ehPastaInternaForaDaSincronizacao(item.name)) continue;
      const doSubnivel = await listarArquivosRecursivo(item.id, [...caminho, item.name]);
      arquivos.push(...doSubnivel);
    } else {
      arquivos.push({
        driveFileId: item.id,
        nomeOriginal: item.name,
        mimeType: item.mimeType,
        tamanho: item.size ? Number(item.size) : null,
        modificadoEm: item.modifiedTime,
        pasta: caminho.length > 0 ? caminho.join(" / ") : null,
      });
    }
  }

  return arquivos;
}

app.get("/files", exigirChaveDeAcesso, async (req, res) => {
  try {
    let arquivos = await listarArquivosRecursivo(DRIVE_FOLDER_ID);
    // Anexos de solicitações de OUTRAS pessoas não aparecem na listagem de quem não é Administrador.
    if (!ehAdminAtivo(req.portalUser)) {
      await garantirIndiceArquivos(false);
      arquivos = arquivos.filter((a) => !arquivoPrivadoDeOutro(a.driveFileId, req.portalUser));
    }
    res.json({ pasta: DRIVE_FOLDER_ID, total: arquivos.length, arquivos });
  } catch (err) {
    console.error("Erro ao listar arquivos da pasta:", err.message);
    res.status(500).json({ erro: "Não foi possível listar os documentos da pasta." });
  }
});

app.get("/api/documents/:id/file", exigirChaveDeAcesso, async (req, res) => {
  const fileId = req.params.id;

  try {
    const autorizado = await pertenceAPastaAutorizada(fileId);
    if (!autorizado) {
      return res.status(403).json({ erro: "Você não tem permissão para acessar este documento." });
    }

    if (!(await podeAbrirArquivo(fileId, req.portalUser))) {
      return res.status(403).json({ erro: "Você não tem permissão para acessar este documento." });
    }

    const meta = await drive.files.get({
      fileId,
      fields: "name, mimeType",
      supportsAllDrives: true,
    });

    const arquivo = await drive.files.get(
      { fileId, alt: "media", supportsAllDrives: true },
      { responseType: "stream" }
    );

    res.setHeader("Content-Type", meta.data.mimeType || "application/octet-stream");
    // Nome com acento/ç/espaços especiais (ex.: "Licença Sanitária ...pdf")
    // NÃO pode ir cru num cabeçalho HTTP — o Node recusa ("Invalid character
    // in header content") e a rota respondia 500 (relato da Iasmin,
    // 2026-10-09: documento novo com acento no nome não abria). Mesmo
    // formato já usado em viagens.js: fallback ASCII em filename= +
    // nome completo codificado em filename*=UTF-8''.
    res.setHeader("Content-Disposition", montarContentDisposition("inline", meta.data.name));
    // Cache no navegador (2026-09-30, pedido da Iasmin: reduzir custo de
    // "Data Transfer Out" do Cloud Run conforme mais gente usa o portal).
    // "private" porque é conteúdo autenticado (não deve ficar em cache
    // compartilhado/CDN) — só no navegador de quem acessou. 10 minutos é
    // curto o bastante pra nunca importar em termos de "documento
    // desatualizado" (cada versão de documento tem seu próprio
    // driveFileId neste portal — nunca reaproveita o mesmo id pra um
    // conteúdo diferente), mas já evita rebaixar o mesmo arquivo do zero
    // quando alguém clica em "Ver" e depois "Baixar", ou reabre o mesmo
    // documento/anexo mais de uma vez na mesma sessão.
    res.setHeader("Cache-Control", "private, max-age=600");

    arquivo.data.pipe(res);
  } catch (err) {
    console.error("Erro ao buscar arquivo no Drive:", err.message);

    if (err.code === 404) {
      return res.status(404).json({ erro: "Arquivo original não encontrado no repositório." });
    }
    return res.status(500).json({ erro: "Não foi possível localizar o arquivo original." });
  }
});

// =========================================================================
// BANCO DE DADOS (Firestore) — substitui a capability "db" do Artifact.
// Só estas coleções (lista fechada), nunca uma coleção arbitrária vinda de fora.
// =========================================================================
const COLECOES_PERMITIDAS = new Set([
  "documentos_confirmados",
  "conference_queue",
  "homologacoes",
  "audit_log",
  // Adicionada em 2026-09-22: sem ela, GET/PUT /api/db/client_document_analysis
  // respondia 400 "Coleção desconhecida" no site publicado — a aba "Análise
  // Documental de Clientes" nunca conseguia salvar nem carregar o histórico
  // fora do Artifact, mesmo antes de qualquer IA real entrar em cena.
  "client_document_analysis",
  // Adicionada em 2026-09-23: aba nova "Envio de Documentações em Lote"
  // (antes um modal efêmero dentro de Homologação, sem histórico nenhum).
  "batch_document_submissions",
  // Adicionada em 2026-09-25: "Meu Perfil" + login com conta própria (antes
  // era e-mail corporativo + senha única, sem cadastro). SEM esta linha,
  // GET/PUT /api/db/users responde 400 "Coleção desconhecida" e NINGUÉM
  // consegue logar — nem o admin semente (Iasmin) — porque authenticate()
  // depende de ler/escrever esta coleção pra tudo (login, criação de
  // usuário, troca de senha). Faltou nesta lista quando a função foi
  // publicada; corrigido depois que o login parou de funcionar em produção.
  // "users" SAIU desta lista em 2026-11: usuários agora só existem nas rotas
  // /api/auth/* e /api/usuarios (login no servidor, só Administrador gerencia).
  // Adicionada em 2026-09-28: registro de "arquivo excluído manualmente do
  // portal, nunca mais reaparecer numa sincronização futura"
  // (registrarArquivoExcluido/fetchArquivosExcluidosIds no index.html —
  // pedido original da Iasmin em 2026-09-21). Essa função sempre existiu no
  // frontend, mas SEM esta linha, tanto o PUT que registra a exclusão
  // quanto o GET que confere a lista antes de cada sincronização respondiam
  // 400 "Coleção desconhecida" — só que os dois lados chamam isso dentro de
  // um try/catch "nunca impede a ação principal", então a falha nunca
  // aparecia na tela: a exclusão em si sempre funcionava (o documento saía
  // do índice), só o REGISTRO da exclusão é que nunca era salvo de
  // verdade, e a sincronização seguinte, sem nada pra consultar, sempre
  // reencontrava e reindexava o mesmo arquivo. Faltou nesta lista desde que
  // a função foi criada; corrigido depois do relato da Iasmin de que
  // documentos excluídos estavam voltando.
  "arquivos_excluidos_drive",
  // Adicionada em 2026-10-05: aba nova "Informações Financeiras" (registro e
  // acompanhamento das informações financeiras obtidas nas negociações).
  // "financeiro_solicitacoes" guarda uma solicitação por documento (cliente,
  // e-mails, respostas versionadas, histórico). O modelo para o cliente é
  // FIXO e vai embutido no próprio portal (só download), então não existe
  // coleção para ele. SEM esta linha, GET/PUT /api/db/<coleção> responde 400
  // "Coleção desconhecida" e a aba nunca salva nem carrega nada.
  "financeiro_solicitacoes",
  // Adicionada em 2026-10-09: cache COMPARTILHADO da classificação automática
  // dos arquivos do Drive (um documento por arquivo). Antes cada aparelho
  // guardava esse cache só no próprio navegador — o celular (sem cache) ficava
  // vazio até reler e classificar todos os PDFs. Agora qualquer aparelho que
  // processa um arquivo grava o resultado aqui e todos os outros reaproveitam.
  "autodrive_cache",
]);

function exigirColecaoValida(req, res, next) {
  if (!COLECOES_PERMITIDAS.has(req.params.collection)) {
    return res.status(400).json({ erro: "Coleção desconhecida." });
  }
  next();
}

/** GET /api/db/:collection — lista todos os documentos da coleção.
 *  Formato de retorno pensado para bater 1:1 com o que o portal já espera
 *  de um snapshot do Firestore: [{ id, data }, ...]. */
app.get(
  "/api/db/:collection",
  exigirChaveDeAcesso,
  exigirColecaoValida,
  async (req, res) => {
    try {
      const snap = await firestore.collection(req.params.collection).get();
      let docs = snap.docs.map((d) => ({ id: d.id, data: d.data() }));
      // Privacidade por dono (NO SERVIDOR): quem não é Administrador só recebe os próprios registros.
      if (!ehAdminAtivo(req.portalUser)) {
        const campo = DONOS_POR_COLECAO[req.params.collection];
        if (campo) {
          docs = docs.filter((d) => pertenceAoUsuario(d.data && d.data[campo], req.portalUser));
        } else if (req.params.collection === "audit_log") {
          docs = docs.filter((d) => d.data && d.data.usuario === req.portalUser.nome);
        }
      }
      res.json({ docs });
    } catch (err) {
      console.error("Erro ao listar coleção:", err.message);
      res.status(500).json({ erro: "Não foi possível ler os dados agora." });
    }
  }
);

/** PUT /api/db/:collection/:id — grava/substitui um documento por inteiro
 *  (equivalente a .doc(id).set(data) sem merge — o corpo enviado é o
 *  documento completo, nunca um patch parcial). */
app.put(
  "/api/db/:collection/:id",
  exigirChaveDeAcesso,
  exigirColecaoValida,
  async (req, res) => {
    try {
      const corpo = req.body || {};
      if (req.params.collection === "audit_log") corpo.usuario = req.portalUser.nome; // o autor da ação é sempre quem está logado
      // Termo de Abertura de Projeto: a DATA DE CRIAÇÃO é do servidor. Na primeira
      // gravação do registro o servidor carimba `criadoEm` (momento real da criação);
      // nas gravações seguintes (edições, preenchimento das etapas...) o valor
      // original é preservado — o navegador não consegue alterá-lo.
      if (req.params.collection === "financeiro_solicitacoes") {
        const ref = firestore.collection(req.params.collection).doc(req.params.id);
        const criadoEm = await firestore.runTransaction(async (t) => {
          const snap = await t.get(ref);
          const existente = snap.exists ? snap.data() || {} : null;
          validarEscritaPrivada("financeiro_solicitacoes", existente, corpo, req.portalUser);
          if (existente && existente.criadoEm) {
            corpo.criadoEm = existente.criadoEm;
            if (existente.criadoEmServidor) corpo.criadoEmServidor = true;
          } else if (!existente) {
            corpo.criadoEm = new Date().toISOString();
            corpo.criadoEmServidor = true;
            if (Array.isArray(corpo.historico)) {
              const i = corpo.historico.findIndex((ev) => ev && ev.evento === "criada");
              if (i >= 0) corpo.historico[i] = { ...corpo.historico[i], at: corpo.criadoEm };
            }
          }
          t.set(ref, corpo);
          return corpo.criadoEm || null;
        });
        return res.json({ ok: true, id: req.params.id, criadoEm });
      }
      if (DONOS_POR_COLECAO[req.params.collection] && !ehAdminAtivo(req.portalUser)) {
        const atual = await firestore.collection(req.params.collection).doc(req.params.id).get();
        validarEscritaPrivada(req.params.collection, atual.exists ? atual.data() : null, corpo, req.portalUser);
      }
      await firestore
        .collection(req.params.collection)
        .doc(req.params.id)
        .set(corpo);
      res.json({ ok: true, id: req.params.id });
    } catch (err) {
      if (err && err.status === 403) return res.status(403).json({ erro: "Você não tem permissão para alterar este registro." });
      console.error("Erro ao gravar documento:", err.message);
      res.status(500).json({ erro: "Não foi possível salvar agora." });
    }
  }
);

/** POST /api/db/:collection — cria um documento novo com id automático
 *  (equivalente a .add(data)). */
app.post(
  "/api/db/:collection",
  exigirChaveDeAcesso,
  exigirColecaoValida,
  async (req, res) => {
    try {
      const corpo = req.body || {};
      if (req.params.collection === "audit_log") corpo.usuario = req.portalUser.nome;
      validarEscritaPrivada(req.params.collection, null, corpo, req.portalUser);
      if (req.params.collection === "financeiro_solicitacoes") {
        corpo.criadoEm = new Date().toISOString(); // data de criação sempre do servidor
        corpo.criadoEmServidor = true;
      }
      const ref = await firestore
        .collection(req.params.collection)
        .add(corpo);
      res.json({ ok: true, id: ref.id, ...(corpo.criadoEm && req.params.collection === "financeiro_solicitacoes" ? { criadoEm: corpo.criadoEm } : {}) });
    } catch (err) {
      if (err && err.status === 403) return res.status(403).json({ erro: "Você não tem permissão para criar este registro." });
      console.error("Erro ao criar documento:", err.message);
      res.status(500).json({ erro: "Não foi possível salvar agora." });
    }
  }
);

/** DELETE /api/db/:collection/:id — remove um documento. Nunca toca em
 *  nenhum arquivo no Drive — só o registro de índice, quando a coleção é
 *  documentos_confirmados (mesma regra que já existia no portal). */
app.delete(
  "/api/db/:collection/:id",
  exigirChaveDeAcesso,
  exigirColecaoValida,
  async (req, res) => {
    try {
      if (DONOS_POR_COLECAO[req.params.collection] && !ehAdminAtivo(req.portalUser)) {
        const atual = await firestore.collection(req.params.collection).doc(req.params.id).get();
        if (atual.exists) validarEscritaPrivada(req.params.collection, atual.data(), {}, req.portalUser);
      }
      await firestore
        .collection(req.params.collection)
        .doc(req.params.id)
        .delete();
      res.json({ ok: true });
    } catch (err) {
      if (err && err.status === 403) return res.status(403).json({ erro: "Você não tem permissão para excluir este registro." });
      console.error("Erro ao excluir documento:", err.message);
      res.status(500).json({ erro: "Não foi possível excluir agora." });
    }
  }
);

// =========================================================================
// UPLOAD REAL DE DOCUMENTO NOVO — sobe o arquivo de verdade para a pasta
// oficial do Drive e cria o registro correspondente em
// documentos_confirmados. Substitui a capability "assets" do Artifact.
// =========================================================================
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 30 * 1024 * 1024 }, // 30 MB (limite do Cloud Run por requisição: 32 MB)
});

/** nomeDoArquivoEnviado: o multer/busboy lê o nome do arquivo (cabeçalho do
 *  multipart) como latin1, o que transforma "Alteração" em "AlteraÃ§Ã£o" no
 *  Drive. Preferimos o campo "nomeArquivo" (UTF-8, enviado pelo portal); sem
 *  ele, reconvertemos o originalname de latin1 para UTF-8 quando isso gera um
 *  texto válido. */
function nomeDoArquivoEnviado(req) {
  const campo = typeof req.body?.nomeArquivo === "string" ? req.body.nomeArquivo.trim() : "";
  if (campo) return campo.normalize("NFC");
  const bruto = String(req.file?.originalname || "arquivo");
  try {
    if (!/[^\u0000-\u00ff]/.test(bruto)) {
      const conv = Buffer.from(bruto, "latin1").toString("utf8");
      if (!conv.includes("\uFFFD")) return conv.normalize("NFC");
    }
  } catch (_) {}
  return bruto.normalize("NFC");
}

const NOME_SUBPASTA_UPLOADS = "Enviados pelo Portal";
const cacheSubpastasPorCaminho = new Map(); // chave: caminho completo ("A/B/C") -> id da pasta no Drive

/** encontrarOuCriarSubpasta: garante que exista, dentro da pasta oficial do
 *  Drive, a árvore de subpastas indicada por `caminho` (array de nomes, ex.:
 *  ["Enviados pelo Portal"] ou ["ENVIO DE DOCUMENTAÇÕES EM LOTE", "Nestlé",
 *  "lote-abc123"]), criando cada nível que ainda não existir. Cacheia por
 *  caminho completo — e por cada nível intermediário — em memória do
 *  processo, para não repetir buscas quando o mesmo caminho for usado de
 *  novo (2026-09-23: generalizada a partir da antiga
 *  encontrarOuCriarSubpastaUploads(), que fazia isso só para um nível fixo;
 *  ela agora é só uma chamada desta função com 1 elemento — comportamento
 *  idêntico ao de sempre para todo o resto do portal). */
async function encontrarOuCriarSubpasta(caminho) {
  const niveis = (Array.isArray(caminho) ? caminho : [caminho])
    .map((n) => String(n || "").trim())
    .filter(Boolean);
  if (niveis.length === 0) {
    throw new Error("encontrarOuCriarSubpasta: caminho vazio.");
  }
  // Tudo que o portal grava no Drive vive dentro da pasta "PORTAL" (ver
  // NOME_PASTA_PORTAL): a raiz fica só com ela e com a pasta das bases.
  // Idempotente — um caminho que já comece por "PORTAL" não é prefixado de
  // novo. Quem chama continua passando o caminho "lógico" de sempre
  // (["Enviados pelo Portal"], ["ENVIO DE DOCUMENTAÇÕES EM LOTE", ...]).
  if (normalizarNomePasta(niveis[0]) !== normalizarNomePasta(NOME_PASTA_PORTAL)) {
    niveis.unshift(NOME_PASTA_PORTAL);
  }

  let paiId = DRIVE_FOLDER_ID;
  let caminhoParcial = "";
  for (const nome of niveis) {
    caminhoParcial = caminhoParcial ? `${caminhoParcial}/${nome}` : nome;
    const cacheado = cacheSubpastasPorCaminho.get(caminhoParcial);
    if (cacheado) {
      paiId = cacheado;
      continue;
    }
    const busca = await drive.files.list({
      q: `'${paiId}' in parents and trashed = false and mimeType = '${FOLDER_MIME_TYPE}' and name = '${nome.replace(/'/g, "\\'")}'`,
      fields: "files(id, name)",
      pageSize: 1,
      supportsAllDrives: true,
      includeItemsFromAllDrives: true,
      corpora: "drive",
      driveId: DRIVE_ID,
    });
    const existente = (busca.data.files || [])[0];
    let idNivel;
    if (existente) {
      idNivel = existente.id;
    } else {
      const criada = await drive.files.create({
        requestBody: {
          name: nome,
          mimeType: FOLDER_MIME_TYPE,
          parents: [paiId],
        },
        fields: "id",
        supportsAllDrives: true,
      });
      idNivel = criada.data.id;
    }
    cacheSubpastasPorCaminho.set(caminhoParcial, idNivel);
    paiId = idNivel;
  }
  return paiId;
}

/** Mantida por compatibilidade e clareza nos call sites padrão de upload
 *  (manual pelo site, ou documento classificado pelo chat) — nunca recebe
 *  pasta nenhuma, então sempre resolve para a mesma subpasta fixa de
 *  sempre. */
async function encontrarOuCriarSubpastaUploads() {
  return encontrarOuCriarSubpasta([NOME_SUBPASTA_UPLOADS]);
}

/**
 * POST /api/documents/upload-file
 * multipart/form-data:
 *   - arquivo: o binário real (obrigatório)
 *   - pasta: string opcional (ex.: "ENVIO DE DOCUMENTAÇÕES EM LOTE/Nestlé/
 *     lote-abc123") — quando ausente, comportamento idêntico ao de sempre
 *     (sobe para a subpasta fixa "Enviados pelo Portal"); quando presente,
 *     resolve/cria essa árvore de subpastas sob a raiz configurada e sobe
 *     o arquivo lá. Adicionado em 2026-09-23 para a aba "Envio de
 *     Documentações em Lote" ter uma pasta dedicada por cliente/solicitação
 *     no Drive, sem mudar nenhum outro chamador desta rota.
 *
 * Só sobe o binário para o Drive e devolve os metadados reais do arquivo
 * criado. Não decide nem grava classificação nenhuma — isso é
 * responsabilidade de quem chamou, usando depois PUT
 * /api/db/documentos_confirmados/:id com o registro completo (mesmo formato
 * que o portal já monta em buildConfirmedDocRecord).
 */
app.post(
  "/api/documents/upload-file",
  exigirChaveDeAcesso,
  upload.single("arquivo"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ erro: "Nenhum arquivo enviado (campo 'arquivo')." });
    }
    try {
      const pastaSolicitada = typeof req.body?.pasta === "string" ? req.body.pasta.trim() : "";
      const pastaDestinoId = pastaSolicitada
        ? await encontrarOuCriarSubpasta(pastaSolicitada.split("/"))
        : await encontrarOuCriarSubpastaUploads();

      const criado = await drive.files.create({
        requestBody: {
          name: nomeDoArquivoEnviado(req),
          parents: [pastaDestinoId],
        },
        media: {
          mimeType: req.file.mimetype || "application/octet-stream",
          body: Readable.from(req.file.buffer),
        },
        fields: "id, name, mimeType, size, modifiedTime",
        supportsAllDrives: true,
      });

      const arquivoDrive = criado.data;
      await registrarDonoArquivo(arquivoDrive.id, req.portalUser);
      res.json({
        ok: true,
        driveFileId: arquivoDrive.id,
        nomeOriginal: arquivoDrive.name,
        mimeType: arquivoDrive.mimeType,
        tamanho: arquivoDrive.size ? Number(arquivoDrive.size) : req.file.size,
        driveModifiedTime: arquivoDrive.modifiedTime,
      });
    } catch (err) {
      console.error("Erro no upload de arquivo:", err.message);
      res.status(500).json({ erro: "Não foi possível enviar o arquivo agora.", detalhe: String(err.message || "").slice(0, 160) });
    }
  }
);

/**
 * POST /api/documents/pasta  { pasta: "HOMOLOGAÇÃO - ARQUIVOS DE RESPOSTA/IASMIN/Cliente" }
 * Garante (cria se não existir) essa árvore de subpastas dentro da pasta
 * "PORTAL" e devolve o id e o link da pasta final. Usada (2026-10-20) para o
 * "link de homologação" apontar sozinho para a pasta do cliente no Drive.
 * Idempotente: chamar de novo devolve a mesma pasta. Mesma proteção das demais
 * rotas (X-Portal-Key) e mesma resolução de caminho do upload-file.
 */
app.post("/api/documents/pasta", exigirChaveDeAcesso, async (req, res) => {
  try {
    const pasta = typeof req.body?.pasta === "string" ? req.body.pasta.trim() : "";
    const niveis = pasta.split("/").map((n) => n.trim()).filter(Boolean);
    if (niveis.length === 0 || niveis.length > 6 || niveis.some((n) => n.length > 150)) {
      return res.status(400).json({ erro: "Caminho de pasta inválido." });
    }
    const id = await encontrarOuCriarSubpasta(niveis);
    res.json({ ok: true, folderId: id, link: `https://drive.google.com/drive/folders/${id}` });
  } catch (err) {
    console.error("Erro ao garantir pasta:", err.message);
    res.status(500).json({ erro: "Não foi possível criar a pasta agora." });
  }
});

// =========================================================================
// ANÁLISE DOCUMENTAL DE CLIENTES (Fase 2, 2026-09-22) — chama de fato a API
// da Anthropic para ler e resumir os documentos de um cliente (contratos,
// anexos comerciais, manuais de fornecedor, planilhas de tarifa). Recebe só
// o TEXTO já extraído no navegador (pdf.js/OCR/mammoth/SheetJS, mesmo motor
// já usado em "Envio de documentações em lote") — nunca o binário original
// — e NUNCA grava nada no Firestore sozinho: só devolve o resultado: quem
// grava continua sendo o próprio portal (mesmo caminho — persist(), em
// ClientAnalysisView — que já gravava o resultado do mock), para manter um
// único lugar de escrita desse registro.
//
// Mesma linha de proteção que motivou a desativação total do Gemini em
// 2026-09-17 ("não quero uma IA decidindo livremente quais documentos
// utilizar"): esta IA só LÊ e RESUME o que foi enviado — nunca decide se um
// documento deve ser aceito, nunca classifica um estabelecimento da
// Grupoprima, nunca recomenda aceitar/assinar/recusar nada, nunca toma
// nenhuma ação no portal. A resposta é forçada em JSON estrito via
// "tool use" da Anthropic (nunca texto livre reinterpretado por regex).
// =========================================================================
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || null;
const CLAUDE_ANALYSIS_MODEL = process.env.CLAUDE_ANALYSIS_MODEL || null;
// Esforço de raciocínio do modelo (low/medium/high). "medium" basta para ler e
// resumir documentos e reduz tempo, custo e risco de resposta cortada.
const CLAUDE_ANALYSIS_EFFORT = process.env.CLAUDE_ANALYSIS_EFFORT || "medium";

const ANALISE_CAMPOS_ARRAY_STRING = [
  "principaisPontos",
  "obrigacoesGrupoprima",
  "obrigacoesCliente",
  "condicoesComerciais",
  "prazosEVigencias",
  "segurosEGerenciamentoRisco",
  "documentacoesExigidas",
  "recomendacoesDeConferencia",
];

// Teto de texto enviado à Anthropic por documento e no total — controla
// custo/latência e mantém a chamada bem dentro da janela de contexto do
// modelo mesmo com vários contratos grandes anexados de uma vez. Quando
// corta um documento, avisa isso explicitamente no texto enviado ao
// modelo (ver chamarAnthropicParaAnalise), para ele nunca tratar o corte
// como "documento incompleto = suspeito" sem saber que a limitação é
// nossa, não do documento.
const ANALISE_MAX_CHARS_POR_DOCUMENTO = 150000;
const ANALISE_MAX_CHARS_TOTAL = 400000;

function truncarTextosParaAnalise(documentos) {
  let restante = ANALISE_MAX_CHARS_TOTAL;
  return documentos.map((doc) => {
    const texto = String(doc.textoExtraido || "");
    const tetoDoc = Math.min(ANALISE_MAX_CHARS_POR_DOCUMENTO, Math.max(0, restante));
    let usado = texto;
    let cortado = false;
    if (texto.length > tetoDoc) {
      usado = texto.slice(0, tetoDoc);
      cortado = true;
    }
    restante -= usado.length;
    return { nome: doc.nome, texto: usado, cortado };
  });
}

const ANALISE_TOOL_INPUT_SCHEMA = {
  type: "object",
  properties: {
    resumoExecutivo: { type: "string" },
    principaisPontos: { type: "array", items: { type: "string" } },
    pontosDeAtencao: {
      type: "array",
      items: {
        type: "object",
        properties: {
          titulo: { type: "string" },
          classificacao: { type: "string", enum: ["Informativo", "Atenção", "Crítico"] },
          confianca: { type: "number" },
          referencia: { type: "string" },
          descricao: { type: "string" },
        },
        required: ["titulo", "classificacao", "confianca", "descricao"],
      },
    },
    obrigacoesGrupoprima: { type: "array", items: { type: "string" } },
    obrigacoesCliente: { type: "array", items: { type: "string" } },
    condicoesComerciais: { type: "array", items: { type: "string" } },
    prazosEVigencias: { type: "array", items: { type: "string" } },
    segurosEGerenciamentoRisco: { type: "array", items: { type: "string" } },
    documentacoesExigidas: { type: "array", items: { type: "string" } },
    recomendacoesDeConferencia: { type: "array", items: { type: "string" } },
  },
  required: [
    "resumoExecutivo",
    "principaisPontos",
    "pontosDeAtencao",
    "obrigacoesGrupoprima",
    "obrigacoesCliente",
    "condicoesComerciais",
    "prazosEVigencias",
    "segurosEGerenciamentoRisco",
    "documentacoesExigidas",
    "recomendacoesDeConferencia",
  ],
};

// Modo "checklist" — usado só para documentos de compliance/requisitos (ex.:
// requisitos de segurança de um cliente para transportadoras) onde o que
// importa não é resumir com concisão, e sim listar e classificar TODA
// exigência encontrada, organizada pelos próprios tópicos do documento —
// o oposto do modo "padrao" acima, que prioriza brevidade. Ver
// ANALISE_CHECKLIST_SYSTEM_PROMPT abaixo para as regras completas.
const ANALISE_CHECKLIST_TOOL_INPUT_SCHEMA = {
  type: "object",
  properties: {
    objetivoResumo: { type: "string" },
    identificacaoDocumento: { type: "string" },
    secoes: {
      type: "array",
      items: {
        type: "object",
        properties: {
          titulo: { type: "string" },
          contexto: { type: "string" },
          itens: {
            type: "array",
            items: {
              type: "object",
              properties: {
                classificacao: { type: "string", enum: ["Obrigatório", "Condicional", "Recomendado"] },
                descricao: { type: "string" },
                referencia: { type: "string" },
              },
              required: ["classificacao", "descricao"],
            },
          },
        },
        required: ["titulo", "itens"],
      },
    },
  },
  required: ["objetivoResumo", "identificacaoDocumento", "secoes"],
};

const ANALISE_SYSTEM_PROMPT = `Você é um assistente que ajuda a equipe da Grupoprima Logística a revisar documentos recebidos de clientes (contratos, anexos comerciais, manuais de fornecedor, planilhas de tarifa) ANTES de aceitar, assinar ou operar de acordo com essa documentação.

Sua única tarefa é LER e RESUMIR o que foi enviado — você nunca decide se um documento deve ser aceito, nunca classifica um estabelecimento da Grupoprima, nunca recomenda aceitar/assinar/recusar nada, e nunca toma nenhuma ação fora de preencher o resultado pedido.

Regras obrigatórias, sem exceção:
- Baseie cada afirmação exclusivamente no texto fornecido a seguir — nunca complete com conhecimento geral sobre contratos de transporte/logística que não esteja no documento.
- Nunca invente datas, valores, CNPJs, nomes de cláusula ou número de cláusula que não apareçam literalmente no texto.
- Quando um ponto não puder ser confirmado com confiança razoável, use "confianca" baixa (0.5 ou menos) nesse ponto de atenção e registre isso também em "recomendacoesDeConferencia" — nunca apresente como certeza.
- Preencha "referencia" só quando for possível apontar de fato a cláusula/trecho/página de origem no texto recebido; caso contrário deixe uma string vazia — nunca invente uma referência.
- Alguns documentos podem ter sido cortados por limite de tamanho (isso aparece marcado no próprio texto abaixo, quando acontecer) — trate o conteúdo cortado como incompleto, nunca como ausente ou suspeito por si só.
- Nunca recomende aceitar, assinar ou recusar o documento — descreva só obrigações, riscos e pontos de atenção; a decisão é sempre de uma pessoa responsável na Grupoprima.
- Preencha o resultado só com o formulário fornecido (chamando a ferramenta "registrar_analise") — nunca responda em texto livre.

Formato exigido: um RESUMO de verdade, não uma transcrição do documento. O resultado é impresso em papel timbrado e precisa ser curto o bastante pra ser lido de pé, sem perder nenhum ponto importante. Siga à risca:
- Cada item de qualquer lista é UMA frase curta e direta (uma linha, no máximo duas) — nunca um parágrafo dentro de um item.
- "resumoExecutivo": no máximo 4-5 frases.
- "principaisPontos": no máximo 6 itens — só os mais relevantes/estratégicos, nunca uma lista exaustiva de tudo que está no documento.
- "pontosDeAtencao": no máximo 6-8 itens, priorizando primeiro os "Crítico", depois "Atenção", depois "Informativo" — junte num único item pontos que tratem do mesmo assunto em vez de criar vários itens parecidos. Cada "descricao" tem no máximo 2 frases curtas.
- "obrigacoesGrupoprima", "obrigacoesCliente", "condicoesComerciais", "prazosEVigencias", "segurosEGerenciamentoRisco", "documentacoesExigidas": agrupe itens relacionados num único item sempre que fizer sentido — por exemplo, várias certidões exigidas viram um item só ("Certidões negativas: Federal, Estadual, Municipal, FGTS e Trabalhista") em vez de um item por certidão; um cronograma com muitas datas vira poucos itens agrupando etapas próximas ("D0-D2: divulgação, NDA e envio do edital/base de dados") em vez de um item por data.
- NUNCA repita a mesma informação em mais de uma seção — se uma obrigação já está detalhada em "documentacoesExigidas", em "obrigacoesGrupoprima" ela é só citada em 1 frase (ex.: "Apresentar toda a documentação jurídica, operacional, financeira e de compliance exigida até D+7"), nunca listada de novo por extenso.
- Resumir NUNCA significa omitir uma obrigação, prazo, valor ou exigência documental real do documento — significa condensar COMO isso é dito, sem perder NENHUM conteúdo importante. Nunca sacrifique um ponto obrigatório só pra caber no limite de itens; se sobrar algo relevante depois de agrupar ao máximo, ainda assim inclua.`;

const ANALISE_CHECKLIST_SYSTEM_PROMPT = `Você é um assistente que ajuda a equipe da Grupoprima Logística a ler documentos de compliance/requisitos enviados por clientes (ex.: requisitos de segurança para transportadoras, manuais de exigências de fornecedor, políticas de compliance) ANTES de aceitar, assinar ou operar de acordo com essa documentação.

Sua única tarefa é LER o documento e produzir um CHECKLIST COMPLETO de exigências — você nunca decide se um documento deve ser aceito, nunca classifica um estabelecimento da Grupoprima, nunca recomenda aceitar/assinar/recusar nada, e nunca toma nenhuma ação fora de preencher o resultado pedido.

Este modo é o OPOSTO do modo de resumo executivo: aqui o objetivo NÃO é ser conciso — é ser EXAUSTIVO. Cada exigência real do documento precisa aparecer em algum item. Nunca omita uma exigência só para deixar o resultado mais curto.

Regras obrigatórias, sem exceção:
- Baseie cada item exclusivamente no texto fornecido a seguir — nunca complete com conhecimento geral sobre segurança/compliance/transporte que não esteja no documento.
- Nunca invente datas, valores, números de cláusula, nomes de norma ou exigência que não apareçam literalmente no texto.
- Organize os itens em "secoes" seguindo os PRÓPRIOS tópicos/capítulos do documento (ex.: se o documento tem uma seção sobre rastreamento de veículos e outra sobre seleção de motoristas, crie uma seção para cada uma, com o título que o documento usa ou um título fiel ao conteúdo) — nunca reaproveite nomes de seção de outro tipo de análise, e nunca junte tudo em uma seção só se o documento tiver estrutura própria.
- Classifique CADA item como "Obrigatório", "Condicional" ou "Recomendado", usando a própria linguagem do documento como critério:
  - "Obrigatório": o texto usa linguagem de obrigação (deve, obrigatório, é necessário, shall, must, required, mandatory) ou apresenta a exigência sem ressalva.
  - "Condicional": a exigência só se aplica em certas situações, tem exceção, depende de outro fator, ou o texto usa linguagem de possibilidade/condição (se aplicável, quando, exceto, unless, where applicable).
  - "Recomendado": o texto usa linguagem de sugestão, não-obrigatoriedade ou boa prática (recomendado, sugerido, should [quando claramente não-mandatório], best practice, idealmente).
  - Quando a classificação não estiver clara pelo texto, use "Condicional" (nunca "Obrigatório" por padrão em caso de dúvida — marcar algo como obrigatório sem certeza é mais arriscado do que marcar como condicional).
- Preencha "referencia" só quando for possível apontar de fato a cláusula/seção/página de origem no texto recebido; caso contrário deixe uma string vazia — nunca invente uma referência.
- "contexto" de uma seção é opcional — use só quando uma frase curta ajudar a entender o propósito daquela seção; caso contrário deixe uma string vazia.
- "identificacaoDocumento": preencha só com metadados que o próprio documento declara sobre si mesmo (nome/título, número de versão, data, partes/assinantes, alterações em relação a uma versão anterior) — deixe como string vazia se o documento não declarar nada disso; nunca invente.
- "objetivoResumo": 3 a 4 frases descrevendo do que trata o documento e o que ele exige, de forma neutra — nunca inclua recomendação de aceitar/assinar/recusar.
- Alguns documentos podem ter sido cortados por limite de tamanho (isso aparece marcado no próprio texto abaixo, quando acontecer) — trate o conteúdo cortado como incompleto, nunca como ausente ou suspeito por si só.
- Nunca recomende aceitar, assinar ou recusar o documento — a decisão é sempre de uma pessoa responsável na Grupoprima.
- Preencha o resultado só com o formulário fornecido (chamando a ferramenta "registrar_checklist") — nunca responda em texto livre.

Formato: cada item de "itens" é uma frase objetiva descrevendo UMA exigência (não um parágrafo) — mas, diferente do modo resumo, NÃO agrupe várias exigências distintas em um único item só para reduzir a contagem: se o documento lista 5 exigências separadas, registre 5 itens separados, cada um com sua própria classificação (elas podem ter classificações diferentes entre si).`;

async function chamarAnthropicParaAnalise({ clienteNome, documentos, modo }) {
  const ehChecklist = modo === "checklist";
  const partesDocumentos = documentos
    .map((d, i) => {
      const aviso = d.cortado
        ? "\n[AVISO: este documento foi cortado por limite de tamanho — o texto abaixo é só o início dele.]"
        : "";
      return `--- Documento ${i + 1}: ${d.nome} ---${aviso}\n${d.texto}`;
    })
    .join("\n\n");
  const nomeFerramenta = ehChecklist ? "registrar_checklist" : "registrar_analise";
  const userContent = `Cliente: ${clienteNome}\n\nDocumentos enviados (texto já extraído):\n\n${partesDocumentos}\n\nAnalise os documentos acima e preencha o formulário chamando a ferramenta "${nomeFerramenta}", seguindo à risca as regras do system prompt.`;

  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: CLAUDE_ANALYSIS_MODEL,
      // Modelos 5.x têm raciocínio adaptativo: não aceitam tool_choice forçado
      // ("tool"/"any"). Usamos "auto" e o prompt já ordena chamar a ferramenta.
      // max_tokens maior porque o raciocínio também conta no limite.
      max_tokens: 16000,
      output_config: { effort: CLAUDE_ANALYSIS_EFFORT },
      system: ehChecklist ? ANALISE_CHECKLIST_SYSTEM_PROMPT : ANALISE_SYSTEM_PROMPT,
      messages: [{ role: "user", content: userContent }],
      tools: [
        {
          name: nomeFerramenta,
          description: ehChecklist
            ? "Registra o checklist estruturado e completo de exigências do documento de compliance/requisitos."
            : "Registra o resultado estruturado da análise documental do cliente.",
          input_schema: ehChecklist ? ANALISE_CHECKLIST_TOOL_INPUT_SCHEMA : ANALISE_TOOL_INPUT_SCHEMA,
        },
      ],
      tool_choice: { type: "auto" },
    }),
  });

  if (!resp.ok) {
    let detalhe = "";
    try {
      const corpoErro = await resp.json();
      detalhe = corpoErro && corpoErro.error && corpoErro.error.message ? corpoErro.error.message : "";
    } catch (e) {}
    throw new Error(`API da Anthropic respondeu ${resp.status}${detalhe ? `: ${detalhe}` : ""}.`);
  }

  const corpo = await resp.json();
  const blocoFerramenta = (corpo.content || []).find(
    (b) => b.type === "tool_use" && b.name === nomeFerramenta
  );
  // Diagnóstico leve (sem conteúdo de documento): ajuda a entender falhas.
  try {
    const u = corpo.usage || {};
    console.log(
      `[analise] modo=${modo} stop_reason=${corpo.stop_reason} entrada=${u.input_tokens} saida=${u.output_tokens} blocos=${(corpo.content || []).map((b) => b.type).join(",")} chaves=${blocoFerramenta && blocoFerramenta.input ? Object.keys(blocoFerramenta.input).join(",") : "-"}`
    );
  } catch (e) {}
  if (corpo.stop_reason === "max_tokens") {
    throw new Error("A resposta da IA foi cortada por limite de tamanho. Tente com menos documentos.");
  }
  if (!blocoFerramenta || !blocoFerramenta.input) {
    throw new Error("A API da Anthropic não devolveu o resultado estruturado esperado.");
  }
  return normalizarEntradaFerramenta(blocoFerramenta.input);
}

// Às vezes o modelo devolve uma lista/objeto como TEXTO JSON dentro do campo
// (ex.: secoes: "[...]"). Converte de volta para o tipo certo antes de validar.
function normalizarEntradaFerramenta(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const out = Array.isArray(obj) ? obj.slice() : { ...obj };
  for (const k of Object.keys(out)) {
    const v = out[k];
    if (typeof v === "string") {
      const t = v.trim();
      if ((t.startsWith("[") && t.endsWith("]")) || (t.startsWith("{") && t.endsWith("}"))) {
        try {
          out[k] = JSON.parse(t);
        } catch (e) {}
      }
    }
  }
  return out;
}

function validarResultadoAnalise(resultado) {
  if (!resultado || typeof resultado !== "object") return "resultado vazio ou em formato inválido";
  if (typeof resultado.resumoExecutivo !== "string" || !resultado.resumoExecutivo.trim()) {
    return "campo 'resumoExecutivo' ausente ou vazio";
  }
  if (!Array.isArray(resultado.pontosDeAtencao)) return "campo 'pontosDeAtencao' ausente ou não é uma lista";
  for (const campo of ANALISE_CAMPOS_ARRAY_STRING) {
    if (!Array.isArray(resultado[campo])) return `campo '${campo}' ausente ou não é uma lista`;
  }
  for (const pt of resultado.pontosDeAtencao) {
    if (!pt || typeof pt !== "object") return "um item de 'pontosDeAtencao' não é um objeto válido";
    if (!["Informativo", "Atenção", "Crítico"].includes(pt.classificacao)) {
      return `classificação inválida em 'pontosDeAtencao': "${pt.classificacao}"`;
    }
    if (typeof pt.confianca !== "number" || pt.confianca < 0 || pt.confianca > 1) {
      return "campo 'confianca' inválido em um item de 'pontosDeAtencao' (precisa ser número entre 0 e 1)";
    }
  }
  return null;
}

function validarResultadoAnaliseChecklist(resultado) {
  if (!resultado || typeof resultado !== "object") return "resultado vazio ou em formato inválido";
  if (typeof resultado.objetivoResumo !== "string" || !resultado.objetivoResumo.trim()) {
    return "campo 'objetivoResumo' ausente ou vazio";
  }
  if (typeof resultado.identificacaoDocumento !== "string") {
    return "campo 'identificacaoDocumento' ausente ou não é texto";
  }
  if (!Array.isArray(resultado.secoes) || resultado.secoes.length === 0) {
    return "campo 'secoes' ausente ou não é uma lista";
  }
  for (const secao of resultado.secoes) {
    if (!secao || typeof secao !== "object") return "uma seção não é um objeto válido";
    if (typeof secao.titulo !== "string" || !secao.titulo.trim()) return "uma seção está sem 'titulo'";
    if (!Array.isArray(secao.itens)) return `campo 'itens' ausente ou não é uma lista na seção "${secao.titulo}"`;
    for (const item of secao.itens) {
      if (!item || typeof item !== "object") return `um item da seção "${secao.titulo}" não é um objeto válido`;
      if (!["Obrigatório", "Condicional", "Recomendado"].includes(item.classificacao)) {
        return `classificação inválida em um item da seção "${secao.titulo}": "${item.classificacao}"`;
      }
      if (typeof item.descricao !== "string" || !item.descricao.trim()) {
        return `um item da seção "${secao.titulo}" está sem 'descricao'`;
      }
    }
  }
  return null;
}

/**
 * POST /api/client-analysis
 * body: { id, clienteNome, documentos: [{ nome, textoExtraido }], modo? }
 *
 * "modo" é opcional — "padrao" (default, mantém compatibilidade com quem
 * não envia o campo) produz o resumo executivo de sempre; "checklist" é o
 * modo exaustivo para documentos de compliance/requisitos, que classifica
 * cada exigência encontrada (Obrigatório/Condicional/Recomendado) em vez
 * de resumir. O "modo" efetivamente usado é sempre ecoado de volta no
 * resultado, para o frontend nunca precisar adivinhar qual formato veio.
 *
 * Chama a API da Anthropic para ler os documentos do cliente e devolve
 * { ok: true, resultado }, no mesmo formato que o mock do frontend
 * (mockClientAnalysis) já usava — quem grava o resultado no Firestore
 * continua sendo o próprio portal (persist(), em ClientAnalysisView),
 * como já fazia com o mock. Nunca inventa um resultado quando a API da
 * Anthropic falha ou devolve algo fora do formato esperado — devolve
 * erro claro, e o portal marca o item como "erro" (nunca finge sucesso).
 */
app.post("/api/client-analysis", exigirChaveDeAcesso, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    console.error("[erro] ANTHROPIC_API_KEY não configurada — endpoint /api/client-analysis indisponível.");
    return res
      .status(500)
      .json({ erro: "A análise por IA ainda não está configurada neste servidor (chave da Anthropic ausente)." });
  }
  if (!CLAUDE_ANALYSIS_MODEL) {
    console.error("[erro] CLAUDE_ANALYSIS_MODEL não configurada — endpoint /api/client-analysis indisponível.");
    return res
      .status(500)
      .json({ erro: "A análise por IA ainda não está configurada neste servidor (modelo não definido)." });
  }
  const { clienteNome, documentos, modo: modoBruto } = req.body || {};
  const modo = modoBruto === "checklist" ? "checklist" : "padrao";
  if (!clienteNome || !Array.isArray(documentos) || documentos.length === 0) {
    return res
      .status(400)
      .json({ erro: "Requisição inválida: informe 'clienteNome' e pelo menos um documento com texto extraído." });
  }
  const documentosValidos = documentos.filter(
    (d) => d && typeof d.textoExtraido === "string" && d.textoExtraido.trim()
  );
  if (documentosValidos.length === 0) {
    return res.status(400).json({ erro: "Nenhum documento com texto extraído foi enviado." });
  }
  try {
    const documentosTruncados = truncarTextosParaAnalise(documentosValidos);
    const resultadoBruto = await chamarAnthropicParaAnalise({ clienteNome, documentos: documentosTruncados, modo });
    const erroValidacao =
      modo === "checklist" ? validarResultadoAnaliseChecklist(resultadoBruto) : validarResultadoAnalise(resultadoBruto);
    if (erroValidacao) {
      console.error("Resultado da Anthropic fora do formato esperado:", erroValidacao);
      return res
        .status(502)
        .json({ erro: `A IA devolveu um resultado em formato inesperado (${erroValidacao}) — tente novamente.` });
    }
    res.json({ ok: true, resultado: { ...resultadoBruto, modo, mock: false, geradoEm: new Date().toISOString() } });
  } catch (err) {
    console.error("Erro ao chamar a API da Anthropic:", err.message);
    res
      .status(502)
      .json({ erro: `Não foi possível concluir a análise por IA agora (${err.message}). Tente novamente em alguns instantes.` });
  }
});

// =========================================================================
// CHAT COM CLAUDE (2026-11) — POST /api/chat/claude
//
// Um "turno" do assistente do Dashboard: o navegador manda a conversa, o
// system prompt e a lista de FERRAMENTAS (só o esquema — quem EXECUTA as
// ferramentas é o próprio portal, com os dados reais já carregados), este
// endpoint chama a API da Anthropic com a chave guardada aqui no servidor
// (nunca no navegador) e devolve a resposta do modelo SEM alterar nada
// (inclusive blocos de raciocínio, que precisam voltar intactos no turno
// seguinte). Se o modelo pedir uma ferramenta (tool_use), o navegador
// executa, anexa o resultado e chama de novo — o laço fica no portal.
// Exige sessão válida e usuário ATIVO (pendente/desativado → 403).
// Variáveis: ANTHROPIC_API_KEY (já existe), CLAUDE_CHAT_MODEL (opcional;
// se vazia usa CLAUDE_ANALYSIS_MODEL), CLAUDE_CHAT_EFFORT (low/medium/high,
// padrão low — resposta rápida e barata), CHAT_LIMITE_CHAMADAS_HORA
// (padrão 150 por usuário).
// =========================================================================
const CLAUDE_CHAT_MODEL = process.env.CLAUDE_CHAT_MODEL || null;
const CLAUDE_CHAT_EFFORT = process.env.CLAUDE_CHAT_EFFORT || "low";
// ---- ECONOMIA (todos ajustáveis por variável de ambiente) ------------------
// Respostas do assistente são curtas: teto de saída baixo. Limites por usuário
// (hora e dia) e um "fusível" global por dia protegem a conta da Anthropic de
// uso excessivo ou de laços acidentais. Respostas idênticas são reaproveitadas
// por alguns minutos (cache) sem nenhuma chamada nova à API.
const CHAT_MAX_TOKENS = Number(process.env.CHAT_MAX_TOKENS) || 2000;
const CHAT_MAX_BYTES_CONVERSA = 150 * 1024;
const CHAT_MAX_FERRAMENTAS = 25;
const CHAT_LIMITE_CHAMADAS_HORA = Number(process.env.CHAT_LIMITE_CHAMADAS_HORA) || 60;
const CHAT_LIMITE_CHAMADAS_DIA = Number(process.env.CHAT_LIMITE_CHAMADAS_DIA) || 300;
const CHAT_LIMITE_GLOBAL_DIA = Number(process.env.CHAT_LIMITE_GLOBAL_DIA) || 2000;
const CHAT_CACHE_TTL_MS = 10 * 60 * 1000;
const CHAT_CACHE_MAX = 200;
const CHAT_TIMEOUT_MS = 90 * 1000;
const chatChamadasPorUsuario = new Map(); // chave -> [timestamps]
const chatCache = new Map(); // hash -> { ate, resposta }
const chatUso = { dia: "", chamadas: 0, cacheLocal: 0, entrada: 0, saida: 0, cacheLido: 0, cacheEscrito: 0, porUsuario: {} };
function chatDiaAtual() {
  return new Date().toISOString().slice(0, 10);
}
function chatUsoGarantirDia() {
  const d = chatDiaAtual();
  if (chatUso.dia !== d) {
    Object.assign(chatUso, { dia: d, chamadas: 0, cacheLocal: 0, entrada: 0, saida: 0, cacheLido: 0, cacheEscrito: 0, porUsuario: {} });
  }
}
function chatHashTurno(turno, modelo) {
  return require("crypto")
    .createHash("sha256")
    .update(JSON.stringify([modelo, CLAUDE_CHAT_EFFORT, turno.system, turno.tools, turno.messages]))
    .digest("hex");
}
function chatCacheLer(h) {
  const e = chatCache.get(h);
  if (!e) return null;
  if (e.ate < Date.now()) {
    chatCache.delete(h);
    return null;
  }
  return e.resposta;
}
function chatCacheGravar(h, resposta) {
  if (chatCache.size >= CHAT_CACHE_MAX) chatCache.delete(chatCache.keys().next().value);
  chatCache.set(h, { ate: Date.now() + CHAT_CACHE_TTL_MS, resposta });
}

function chatExcedeuLimite(chave) {
  const agora = Date.now();
  const lista = (chatChamadasPorUsuario.get(chave) || []).filter((t) => agora - t < 24 * 60 * 60 * 1000);
  const naHora = lista.filter((t) => agora - t < 60 * 60 * 1000).length;
  if (naHora >= CHAT_LIMITE_CHAMADAS_HORA || lista.length >= CHAT_LIMITE_CHAMADAS_DIA) {
    chatChamadasPorUsuario.set(chave, lista);
    return true;
  }
  lista.push(agora);
  chatChamadasPorUsuario.set(chave, lista);
  return false;
}

const CHAT_TIPOS_BLOCO = new Set(["text", "tool_use", "tool_result", "thinking", "redacted_thinking"]);

/** Valida/sanea o corpo do turno. Devolve { erro } ou { system, messages, tools }. */
function validarTurnoChat(body) {
  const b = body || {};
  const system = typeof b.system === "string" ? b.system.slice(0, 30000) : "";
  if (!Array.isArray(b.messages) || b.messages.length === 0 || b.messages.length > 80) {
    return { erro: "Conversa inválida." };
  }
  const messages = [];
  for (const m of b.messages) {
    if (!m || (m.role !== "user" && m.role !== "assistant")) return { erro: "Conversa inválida." };
    if (typeof m.content === "string") {
      if (!m.content.trim()) return { erro: "Conversa inválida." };
      messages.push({ role: m.role, content: m.content.slice(0, 30000) });
    } else if (Array.isArray(m.content) && m.content.length > 0) {
      for (const bloco of m.content) {
        if (!bloco || !CHAT_TIPOS_BLOCO.has(bloco.type)) return { erro: "Conversa inválida." };
      }
      messages.push({ role: m.role, content: m.content });
    } else {
      return { erro: "Conversa inválida." };
    }
  }
  if (messages[0].role !== "user" || messages[messages.length - 1].role !== "user") {
    return { erro: "Conversa inválida." };
  }
  let tools = [];
  if (b.tools !== undefined) {
    if (!Array.isArray(b.tools) || b.tools.length > CHAT_MAX_FERRAMENTAS) return { erro: "Ferramentas inválidas." };
    for (const t of b.tools) {
      if (!t || typeof t.name !== "string" || !/^[a-zA-Z0-9_-]{1,64}$/.test(t.name)) {
        return { erro: "Ferramentas inválidas." };
      }
      tools.push({
        name: t.name,
        description: String(t.description || "").slice(0, 6000),
        input_schema:
          t.input_schema && typeof t.input_schema === "object" ? t.input_schema : { type: "object", properties: {} },
      });
    }
  }
  if (Buffer.byteLength(JSON.stringify({ system, messages, tools }), "utf8") > CHAT_MAX_BYTES_CONVERSA) {
    return { erro: "A conversa ficou grande demais — comece uma nova conversa." };
  }
  return { system, messages, tools };
}

app.post("/api/chat/claude", exigirChaveDeAcesso, async (req, res) => {
  const modelo = CLAUDE_CHAT_MODEL || CLAUDE_ANALYSIS_MODEL;
  if (!ANTHROPIC_API_KEY || !modelo) {
    console.error("[chat] ANTHROPIC_API_KEY ou modelo (CLAUDE_CHAT_MODEL/CLAUDE_ANALYSIS_MODEL) não configurados.");
    return res
      .status(503)
      .json({ erro: "A conversa por IA ainda não está configurada neste servidor.", codigo: "chat_nao_configurado" });
  }
  const turno = validarTurnoChat(req.body);
  if (turno.erro) return res.status(400).json({ erro: turno.erro });
  chatUsoGarantirDia();
  // Resposta idêntica já obtida há pouco (mesmo modelo, instruções, ferramentas e conversa,
  // inclusive resultados de ferramenta): reaproveita, sem custo e sem contar no limite.
  const hashTurno = chatHashTurno(turno, modelo);
  const emCache = chatCacheLer(hashTurno);
  if (emCache) {
    chatUso.cacheLocal += 1;
    return res.json({ ...emCache, doCache: true });
  }
  if (chatUso.chamadas >= CHAT_LIMITE_GLOBAL_DIA) {
    return res.status(429).json({
      erro: "O limite diário de uso do assistente foi atingido. Ele volta a responder amanhã; consultas diretas a documentos continuam funcionando.",
      codigo: "chat_limite",
    });
  }
  const chaveUsuario = String((req.portalUser && (req.portalUser.email || req.portalUser.id)) || "").toLowerCase();
  if (chatExcedeuLimite(chaveUsuario)) {
    return res.status(429).json({
      erro: "Limite de mensagens do assistente por hora atingido. Tente de novo em alguns minutos.",
      codigo: "chat_limite",
    });
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), CHAT_TIMEOUT_MS);
  try {
    // Cache de prompt da Anthropic: instruções+ferramentas (system) e a conversa até aqui
    // são relidos a ~10% do custo nas rodadas seguintes (laço de ferramentas, perguntas seguidas).
    const mensagens = turno.messages.map((m) => ({ role: m.role, content: m.content }));
    const ultima = mensagens[mensagens.length - 1];
    if (typeof ultima.content === "string") {
      ultima.content = [{ type: "text", text: ultima.content, cache_control: { type: "ephemeral" } }];
    } else if (Array.isArray(ultima.content) && ultima.content.length > 0) {
      const blocos = ultima.content.slice();
      blocos[blocos.length - 1] = { ...blocos[blocos.length - 1], cache_control: { type: "ephemeral" } };
      ultima.content = blocos;
    }
    const corpo = {
      model: modelo,
      max_tokens: CHAT_MAX_TOKENS,
      output_config: { effort: CLAUDE_CHAT_EFFORT },
      messages: mensagens,
    };
    if (turno.system) {
      corpo.system = [{ type: "text", text: turno.system, cache_control: { type: "ephemeral" } }];
    }
    if (turno.tools.length > 0) {
      corpo.tools = turno.tools;
      corpo.tool_choice = { type: "auto" };
    }
    const chamarApi = () =>
      fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": ANTHROPIC_API_KEY,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify(corpo),
        signal: ctrl.signal,
      });
    let resp = await chamarApi();
    let detalhe = "";
    if (!resp.ok) {
      try {
        const e = await resp.clone().json();
        detalhe = e && e.error && e.error.message ? e.error.message : "";
      } catch (e) {}
      // Alguns modelos (ex.: os menores/mais baratos) não aceitam "effort": repete uma vez sem ele.
      if (resp.status === 400 && /effort|output_config/i.test(detalhe)) {
        delete corpo.output_config;
        resp = await chamarApi();
        detalhe = "";
      }
    }
    if (!resp.ok) {
      if (!detalhe) {
        try {
          const e = await resp.json();
          detalhe = e && e.error && e.error.message ? e.error.message : "";
        } catch (e) {}
      }
      console.error(`[chat] API da Anthropic respondeu ${resp.status}${detalhe ? `: ${detalhe}` : ""}`);
      const limite = resp.status === 429 || resp.status === 529;
      return res.status(limite ? 429 : 502).json({
        erro: limite
          ? "O assistente está com muita demanda agora. Tente de novo em instantes."
          : "Não foi possível falar com a IA agora. Tente novamente.",
        codigo: limite ? "chat_ocupado" : "chat_falha",
      });
    }
    const r = await resp.json();
    const u = r.usage || {};
    try {
      chatUso.chamadas += 1;
      chatUso.entrada += u.input_tokens || 0;
      chatUso.saida += u.output_tokens || 0;
      chatUso.cacheLido += u.cache_read_input_tokens || 0;
      chatUso.cacheEscrito += u.cache_creation_input_tokens || 0;
      const nome = String((req.portalUser && req.portalUser.nome) || chaveUsuario);
      chatUso.porUsuario[nome] = (chatUso.porUsuario[nome] || 0) + 1;
      console.log(
        `[chat] stop_reason=${r.stop_reason} entrada=${u.input_tokens} saida=${u.output_tokens} cache_lido=${u.cache_read_input_tokens || 0} cache_escrito=${u.cache_creation_input_tokens || 0} blocos=${(r.content || []).map((x) => x.type).join(",")}`
      );
    } catch (e) {}
    const resposta = { ok: true, content: r.content || [], stop_reason: r.stop_reason || null, usage: r.usage || null };
    if (r.stop_reason === "end_turn" || r.stop_reason === "tool_use") chatCacheGravar(hashTurno, resposta);
    res.json(resposta);
  } catch (err) {
    const abortou = err && err.name === "AbortError";
    console.error("[chat] erro:", abortou ? "tempo esgotado" : err && err.message);
    res.status(abortou ? 504 : 502).json({
      erro: abortou ? "A IA demorou demais para responder. Tente novamente." : "Não foi possível falar com a IA agora.",
      codigo: "chat_falha",
    });
  } finally {
    clearTimeout(timer);
  }
});

/** GET /api/chat/uso — contadores do dia (só Administrador): chamadas à IA, reaproveitadas do cache, tokens. */
app.get("/api/chat/uso", exigirAdmin, (req, res) => {
  chatUsoGarantirDia();
  res.json({
    ok: true,
    dia: chatUso.dia,
    chamadasIA: chatUso.chamadas,
    respostasDoCache: chatUso.cacheLocal,
    tokensEntrada: chatUso.entrada,
    tokensSaida: chatUso.saida,
    tokensCacheLidos: chatUso.cacheLido,
    tokensCacheEscritos: chatUso.cacheEscrito,
    chamadasPorUsuario: chatUso.porUsuario,
    limites: { porUsuarioHora: CHAT_LIMITE_CHAMADAS_HORA, porUsuarioDia: CHAT_LIMITE_CHAMADAS_DIA, globalDia: CHAT_LIMITE_GLOBAL_DIA },
    modelo: CLAUDE_CHAT_MODEL || CLAUDE_ANALYSIS_MODEL || null,
    effort: CLAUDE_CHAT_EFFORT,
  });
});

// =========================================================================
// SEGURANÇA DE ACESSO (2026-11) — login no SERVIDOR, sessão assinada,
// cadastro com código por e-mail, status "aguardando autorização",
// gestão de usuários só para Administrador e privacidade por dono.
//
// Antes: o login era conferido no navegador (hash comparado contra a
// coleção "users", lida por qualquer um que tivesse a chave do portal) e
// o servidor não sabia QUEM estava chamando — só que a chave X-Portal-Key
// estava correta. Agora:
//
//  - POST /api/auth/login confere e-mail + senha AQUI e devolve um token
//    de sessão assinado (HMAC). O navegador manda esse token no cabeçalho
//    X-Portal-Session em TODA chamada ao backend.
//  - A sessão (coleção "sessoes") tem "ultimaAtividade". Ela só é renovada
//    por POST /api/auth/atividade (enviado pelo navegador quando a pessoa
//    realmente interage: clique, tecla, toque, rolagem) — as consultas
//    automáticas (polling) NÃO renovam. Passou 30 minutos sem atividade
//    real, a sessão deixa de valer (401 sessao_expirada) em qualquer rota.
//  - Toda rota de dados passa por exigirChaveDeAcesso, que agora exige
//    chave + sessão válida + usuário com status "ativo". Quem está
//    "aguardando_autorizacao" só consegue chamar /api/auth/sessao,
//    /api/auth/atividade e /api/auth/sair.
//  - Registros de solicitações (homologações, lotes, análises, financeiro)
//    são filtrados e protegidos NO SERVIDOR pelo dono (ver DONOS_POR_COLECAO):
//    quem não é Administrador só lê/grava/exclui os próprios — inclusive
//    por acesso direto à API e aos anexos.
// =========================================================================
const nodeCrypto = require("crypto");
const { promisify } = require("util");
const scryptAsync = promisify(nodeCrypto.scrypt);

const SESSAO_INATIVIDADE_MS = 30 * 60 * 1000; // 30 min sem atividade real
const COL_USUARIOS = "users";
const COL_SESSOES = "sessoes";
const COL_CADASTROS_PENDENTES = "cadastros_pendentes";
const COL_DONOS_ARQUIVOS = "arquivos_donos";
const DOMINIO_CADASTRO = "grupoprimalog.com.br";
// Senha inicial de contas criadas/redefinidas pelo Administrador: vem SOMENTE da variável de
// ambiente SENHA_INICIAL_PADRAO (Cloud Run). Não existe valor embutido no código.
const SENHA_INICIAL_PADRAO = String(process.env.SENHA_INICIAL_PADRAO || "");
const SENHA_INICIAL_CONFIGURADA = SENHA_INICIAL_PADRAO.length >= 8;
const MSG_SENHA_INICIAL_AUSENTE =
  "A senha inicial padrão não está configurada no servidor (variável SENHA_INICIAL_PADRAO, mínimo 8 caracteres).";
const PERFIS_VALIDOS = ["admin", "comercial", "usuario"]; // níveis que JÁ existem; nenhum novo
const STATUS_PENDENTE = "aguardando_autorizacao";
const CODIGO_VALIDADE_MS = 10 * 60 * 1000; // código vale 10 minutos
const CODIGO_MAX_TENTATIVAS = 5;
const CODIGO_REENVIO_INTERVALO_MS = 60 * 1000;
const CODIGO_MAX_REENVIOS = 5;
const MSG_PENDENTE =
  "Seu cadastro foi realizado com sucesso e está aguardando autorização de acesso. Para liberar sua utilização da plataforma, entre em contato com o administrador responsável e informe que seu cadastro foi concluído.";

// ---- segredo de assinatura da sessão --------------------------------------
// SESSION_SECRET (opcional, Secret Manager). Sem ela, um segredo aleatório é
// gerado uma vez e guardado em Firestore (coleção interna "config_seguranca",
// fora de COLECOES_PERMITIDAS — nenhuma rota genérica a alcança).
let segredoSessao = process.env.SESSION_SECRET || null;
const segredoPronto = (async () => {
  if (segredoSessao) return;
  try {
    const ref = firestore.collection("config_seguranca").doc("sessao");
    let snap = await ref.get();
    if (!(snap.exists && snap.data().segredo)) {
      try {
        await ref.create({
          segredo: nodeCrypto.randomBytes(48).toString("hex"),
          criadoEm: new Date().toISOString(),
        });
      } catch (_) {
        /* outra instância criou ao mesmo tempo — lemos abaixo */
      }
      snap = await ref.get();
    }
    segredoSessao = snap.data().segredo;
  } catch (e) {
    console.error("[seguranca] não foi possível ler/gravar o segredo da sessão:", e && e.message);
    segredoSessao = nodeCrypto.randomBytes(48).toString("hex"); // vale só nesta instância
  }
})();

function assinarSid(sid) {
  return nodeCrypto.createHmac("sha256", segredoSessao).update(sid).digest("base64url");
}
function iguaisSeguro(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && nodeCrypto.timingSafeEqual(x, y);
}

// ---- senhas ---------------------------------------------------------------
async function hashSenhaSrv(senha) {
  const salt = nodeCrypto.randomBytes(16);
  const chave = await scryptAsync(String(senha), salt, 64);
  return "scrypt:" + salt.toString("hex") + ":" + chave.toString("hex");
}
function fnvFallbackHash(texto) {
  let h1 = 0xdeadbeef ^ texto.length;
  let h2 = 0x41c6ce57 ^ texto.length;
  for (let i = 0; i < texto.length; i++) {
    const ch = texto.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return "fnv:" + (h1 >>> 0).toString(16).padStart(8, "0") + (h2 >>> 0).toString(16).padStart(8, "0");
}
/** Confere a senha contra o hash guardado. Aceita o formato novo (scrypt) e
 *  os formatos legados gravados pelo navegador (sha256:/fnv:) — quem entrar
 *  com um hash legado é promovido para scrypt no próprio login. */
async function conferirSenhaSrv(senha, armazenado) {
  const s = String(senha || "");
  const h = String(armazenado || "");
  if (h.startsWith("scrypt:")) {
    const [, saltHex, chaveHex] = h.split(":");
    if (!saltHex || !chaveHex) return { ok: false };
    const calc = await scryptAsync(s, Buffer.from(saltHex, "hex"), 64);
    return { ok: iguaisSeguro(calc.toString("hex"), chaveHex), legado: false };
  }
  if (h.startsWith("sha256:")) {
    const calc = "sha256:" + nodeCrypto.createHash("sha256").update(s, "utf8").digest("hex");
    return { ok: iguaisSeguro(calc, h), legado: true };
  }
  if (h.startsWith("fnv:")) return { ok: iguaisSeguro(fnvFallbackHash(s), h), legado: true };
  return { ok: false };
}
function senhaAtendeRequisitoMinimoSrv(senha) {
  const s = String(senha || "");
  return s.length >= 6 && s.length <= 200 && /[a-zA-Z]/.test(s) && /[0-9]/.test(s);
}
const REQUISITO_SENHA_MSG_SRV =
  "A nova senha deve ter pelo menos 6 caracteres, incluindo ao menos 1 letra e 1 número.";

// ---- utilidades de usuário -------------------------------------------------
function normEmail(e) {
  return String(e || "").trim().toLowerCase();
}
function emailValido(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 160;
}
function statusEfetivo(u) {
  return (u && u.status) || "ativo";
}
function usuarioPublico(u) {
  return {
    id: u.id,
    nome: u.nome,
    email: u.email,
    perfil: statusEfetivo(u) === STATUS_PENDENTE ? null : u.perfil || null,
    status: statusEfetivo(u),
    precisaTrocarSenha: !!u.precisaTrocarSenha,
    preferencias: u.preferencias || { tema: "claro", notificacoes: true },
    ultimoAcesso: u.ultimoAcesso || null,
    criadoEm: u.criadoEm || null,
  };
}
function usuarioVisaoAdmin(u) {
  return {
    ...usuarioPublico(u),
    perfil: u.perfil || null,
    criadoPor: u.criadoPor || null,
    emailConfirmadoEm: u.emailConfirmadoEm || null,
    autorizadoEm: u.autorizadoEm || null,
    autorizadoPor: u.autorizadoPor || null,
    historicoAcesso: Array.isArray(u.historicoAcesso) ? u.historicoAcesso : [],
  };
}
function ehAdminAtivo(u) {
  return !!u && u.perfil === "admin" && statusEfetivo(u) === "ativo";
}

const cacheUsuarios = new Map(); // id -> { dados, lidoEm }
function invalidarCacheUsuario(id) {
  cacheUsuarios.delete(id);
}
async function lerUsuarioPorId(id, forcar) {
  if (!id) return null;
  const c = cacheUsuarios.get(id);
  if (!forcar && c && Date.now() - c.lidoEm < 10000) return c.dados;
  const snap = await firestore.collection(COL_USUARIOS).doc(id).get();
  const dados = snap.exists ? { ...snap.data(), id: snap.id } : null;
  cacheUsuarios.set(id, { dados, lidoEm: Date.now() });
  return dados;
}
async function acharUsuarioPorEmail(email) {
  const e = normEmail(email);
  if (!e) return null;
  const direto = await lerUsuarioPorId(slugUserId(e), true);
  if (direto && normEmail(direto.email) === e) return direto;
  const q = await firestore.collection(COL_USUARIOS).where("email", "==", e).limit(1).get();
  if (!q.empty) return { ...q.docs[0].data(), id: q.docs[0].id };
  // e-mails antigos gravados com maiúsculas: último recurso, varredura
  const todos = await firestore.collection(COL_USUARIOS).get();
  const d = todos.docs.find((x) => normEmail(x.data().email) === e);
  return d ? { ...d.data(), id: d.id } : null;
}
async function gravarUsuario(u) {
  const { ...dados } = u;
  await firestore.collection(COL_USUARIOS).doc(u.id).set(dados);
  invalidarCacheUsuario(u.id);
}

// Administrador-semente (igual ao que o navegador criava): só se a coleção estiver vazia.
(async () => {
  try {
    const q = await firestore.collection(COL_USUARIOS).limit(1).get();
    if (!q.empty) return;
    if (!SENHA_INICIAL_CONFIGURADA) {
      console.error("[usuarios] administrador-semente não criado: " + MSG_SENHA_INICIAL_AUSENTE);
      return;
    }
    const email = "iasmin.oliveira@grupoprimalog.com.br";
    await gravarUsuario({
      id: slugUserId(email),
      nome: "Iasmin Oliveira",
      email,
      perfil: "admin",
      senhaHash: await hashSenhaSrv(SENHA_INICIAL_PADRAO),
      precisaTrocarSenha: true,
      status: "ativo",
      criadoEm: new Date().toISOString(),
      criadoPor: "sistema",
      ultimoAcesso: null,
      preferencias: { tema: "claro", notificacoes: true },
    });
  } catch (e) {
    console.error("[seguranca] semente de usuário:", e && e.message);
  }
})();

// ---- sessões --------------------------------------------------------------
const cacheSessoes = new Map(); // sid -> { dados, lidoEm }
async function lerSessao(sid, forcar) {
  const c = cacheSessoes.get(sid);
  if (!forcar && c && Date.now() - c.lidoEm < 15000) return c.dados;
  const snap = await firestore.collection(COL_SESSOES).doc(sid).get();
  if (!snap.exists) {
    cacheSessoes.delete(sid);
    return null;
  }
  const dados = snap.data();
  cacheSessoes.set(sid, { dados, lidoEm: Date.now() });
  return dados;
}
async function encerrarSessao(sid) {
  cacheSessoes.delete(sid);
  try {
    await firestore.collection(COL_SESSOES).doc(sid).delete();
  } catch (_) {}
}
async function encerrarSessoesDoUsuario(uid) {
  for (const [sid, c] of cacheSessoes) if (c.dados && c.dados.uid === uid) cacheSessoes.delete(sid);
  try {
    const q = await firestore.collection(COL_SESSOES).where("uid", "==", uid).get();
    await Promise.all(q.docs.map((d) => d.ref.delete()));
  } catch (_) {}
}
async function criarSessao(u, req) {
  await segredoPronto;
  const sid = nodeCrypto.randomBytes(24).toString("base64url");
  const agora = Date.now();
  const dados = {
    uid: u.id,
    email: normEmail(u.email),
    criadoEm: new Date(agora).toISOString(),
    ultimaAtividade: agora,
    ip: ipDe(req),
  };
  await firestore.collection(COL_SESSOES).doc(sid).set(dados);
  cacheSessoes.set(sid, { dados, lidoEm: agora });
  // limpeza oportunista de sessões vencidas deste usuário
  firestore
    .collection(COL_SESSOES)
    .where("uid", "==", u.id)
    .get()
    .then((q) =>
      Promise.all(
        q.docs
          .filter((d) => agora - (d.data().ultimaAtividade || 0) > SESSAO_INATIVIDADE_MS)
          .map((d) => d.ref.delete())
      )
    )
    .catch(() => {});
  return sid + "." + assinarSid(sid);
}
function ipDe(req) {
  const xf = String((req && req.get && req.get("X-Forwarded-For")) || "").split(",")[0].trim();
  return xf || (req && req.ip) || "";
}

const MSG_SESSAO = {
  sessao_invalida: "Sua sessão não é mais válida. Entre novamente.",
  sessao_expirada: "Sua sessão expirou por inatividade. Entre novamente.",
  acesso_desativado: "Este acesso está desativado. Fale com o administrador do portal.",
};
/** Valida o cabeçalho X-Portal-Session. Devolve { sid, sessao, usuario } ou { erro }. */
async function resolverSessao(req) {
  await segredoPronto;
  const bruto = String(req.get("X-Portal-Session") || "");
  const i = bruto.indexOf(".");
  if (i < 1) return { erro: "sessao_invalida" };
  const sid = bruto.slice(0, i);
  const ass = bruto.slice(i + 1);
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(sid) || !iguaisSeguro(ass, assinarSid(sid))) {
    return { erro: "sessao_invalida" };
  }
  let s = await lerSessao(sid, false);
  if (!s) return { erro: "sessao_invalida" };
  const agora = Date.now();
  if (agora - (s.ultimaAtividade || 0) > SESSAO_INATIVIDADE_MS) {
    s = await lerSessao(sid, true); // outra instância pode ter renovado
    if (!s) return { erro: "sessao_invalida" };
    if (agora - (s.ultimaAtividade || 0) > SESSAO_INATIVIDADE_MS) {
      await encerrarSessao(sid);
      return { erro: "sessao_expirada" };
    }
  }
  const usuario = await lerUsuarioPorId(s.uid, false);
  if (!usuario) {
    await encerrarSessao(sid);
    return { erro: "sessao_invalida" };
  }
  if (statusEfetivo(usuario) === "inativo") {
    await encerrarSessao(sid);
    return { erro: "acesso_desativado" };
  }
  return { sid, sessao: s, usuario };
}

function chaveDoPortalConfere(req) {
  if (!BACKEND_ACCESS_KEY) return true;
  return req.get("X-Portal-Key") === BACKEND_ACCESS_KEY;
}
/** Chave + sessão válida, em QUALQUER status (inclusive "aguardando autorização"). */
async function exigirSessaoQualquerStatus(req, res, next) {
  try {
    if (!chaveDoPortalConfere(req)) return res.status(401).json({ erro: "Acesso não autorizado." });
    const r = await resolverSessao(req);
    if (r.erro) return res.status(401).json({ erro: MSG_SESSAO[r.erro], codigo: r.erro });
    req.portalUser = r.usuario;
    req.portalSid = r.sid;
    req.portalSessao = r.sessao;
    next();
  } catch (err) {
    console.error("[seguranca] erro ao validar sessão:", err && err.message);
    res.status(500).json({ erro: "Não foi possível validar o acesso agora." });
  }
}
/** Chave + sessão válida + usuário ATIVO e autorizado. É o novo exigirChaveDeAcesso. */
function exigirChaveDeAcesso(req, res, next) {
  exigirSessaoQualquerStatus(req, res, (err) => {
    if (err) return next(err);
    if (statusEfetivo(req.portalUser) === STATUS_PENDENTE) {
      return res.status(403).json({ erro: MSG_PENDENTE, codigo: "aguardando_autorizacao" });
    }
    if (statusEfetivo(req.portalUser) !== "ativo") {
      return res.status(403).json({ erro: "Acesso não autorizado.", codigo: "acesso_desativado" });
    }
    next();
  });
}
function exigirAdmin(req, res, next) {
  exigirChaveDeAcesso(req, res, (err) => {
    if (err) return next(err);
    if (!ehAdminAtivo(req.portalUser)) {
      return res.status(403).json({ erro: "Somente administradores podem fazer isso." });
    }
    next();
  });
}

// ---- limites de tentativa ---------------------------------------------------
const falhasLogin = new Map(); // email -> { n, ate }
function loginBloqueado(email) {
  const f = falhasLogin.get(email);
  return f && f.ate && f.ate > Date.now() ? Math.ceil((f.ate - Date.now()) / 60000) : 0;
}
function registrarFalhaLogin(email) {
  const f = falhasLogin.get(email) || { n: 0, ate: 0 };
  f.n += 1;
  if (f.n >= 8) {
    f.ate = Date.now() + 10 * 60 * 1000;
    f.n = 0;
  }
  falhasLogin.set(email, f);
}
const inicioCadastroPorIp = new Map(); // ip -> [timestamps]
function limiteCadastroPorIpExcedido(ip) {
  const agora = Date.now();
  const lista = (inicioCadastroPorIp.get(ip) || []).filter((t) => agora - t < 60 * 60 * 1000);
  lista.push(agora);
  inicioCadastroPorIp.set(ip, lista);
  return lista.length > 10;
}

function eventoHistorico(evento, extra) {
  return { evento, em: new Date().toISOString(), ...(extra || {}) };
}
function respostaLoginOk(u, token) {
  return { ok: true, token, user: usuarioPublico(u), mensagemPendente: statusEfetivo(u) === STATUS_PENDENTE ? MSG_PENDENTE : undefined };
}

// ---- rotas de autenticação --------------------------------------------------
app.post("/api/auth/login", async (req, res) => {
  try {
    if (!chaveDoPortalConfere(req)) return res.status(401).json({ erro: "Acesso não autorizado." });
    const email = normEmail(req.body && req.body.email);
    const senha = String((req.body && req.body.senha) || "");
    if (!email) return res.json({ ok: false, message: "Informe seu e-mail corporativo." });
    if (!emailValido(email)) return res.json({ ok: false, message: "Informe um e-mail em formato válido." });
    if (!senha) return res.json({ ok: false, message: "Informe sua senha." });
    const espera = loginBloqueado(email);
    if (espera) {
      return res.json({ ok: false, message: `Muitas tentativas incorretas. Tente novamente em ${espera} minuto(s).` });
    }
    const u = await acharUsuarioPorEmail(email);
    if (!u) return res.json({ ok: false, message: "E-mail não encontrado. Fale com o administrador do portal." });
    if (statusEfetivo(u) === "inativo") {
      return res.json({ ok: false, message: "Este acesso está desativado. Fale com o administrador do portal." });
    }
    const conf = await conferirSenhaSrv(senha, u.senhaHash);
    if (!conf.ok) {
      registrarFalhaLogin(email);
      return res.json({ ok: false, message: "Senha incorreta. Tente novamente." });
    }
    falhasLogin.delete(email);
    const atualizado = { ...u, ultimoAcesso: new Date().toISOString() };
    if (conf.legado) atualizado.senhaHash = await hashSenhaSrv(senha);
    await gravarUsuario(atualizado);
    const token = await criarSessao(atualizado, req);
    res.json(respostaLoginOk(atualizado, token));
  } catch (err) {
    console.error("[auth] login:", err && err.message);
    res.status(500).json({ ok: false, message: "Não foi possível entrar agora. Tente novamente." });
  }
});

// Sessão atual: o navegador chama ao abrir a página para validar a sessão guardada.
app.get("/api/auth/sessao", exigirSessaoQualquerStatus, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const restanteMs = Math.max(0, SESSAO_INATIVIDADE_MS - (Date.now() - (req.portalSessao.ultimaAtividade || 0)));
  res.json({ ok: true, user: usuarioPublico(req.portalUser), restanteMs });
});
// Batimento de atividade REAL (só o navegador, quando a pessoa interage).
app.post("/api/auth/atividade", exigirSessaoQualquerStatus, async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const agora = Date.now();
    const s = { ...req.portalSessao, ultimaAtividade: agora };
    cacheSessoes.set(req.portalSid, { dados: s, lidoEm: agora });
    await firestore.collection(COL_SESSOES).doc(req.portalSid).update({ ultimaAtividade: agora });
    const fresco = await lerUsuarioPorId(req.portalUser.id, true); // reflete autorização/perfil novos
    res.json({ ok: true, user: usuarioPublico(fresco || req.portalUser), restanteMs: SESSAO_INATIVIDADE_MS });
  } catch (err) {
    console.error("[auth] atividade:", err && err.message);
    res.status(500).json({ ok: false });
  }
});
app.post("/api/auth/sair", exigirSessaoQualquerStatus, async (req, res) => {
  await encerrarSessao(req.portalSid);
  res.json({ ok: true });
});

// Troca de senha da própria pessoa (usuário ATIVO).
app.post("/api/auth/alterar-senha", exigirChaveDeAcesso, async (req, res) => {
  try {
    const u = req.portalUser;
    const { senhaAtual, novaSenha } = req.body || {};
    if (!novaSenha) return res.json({ ok: false, message: "Informe a nova senha." });
    if (!senhaAtendeRequisitoMinimoSrv(novaSenha)) return res.json({ ok: false, message: REQUISITO_SENHA_MSG_SRV });
    // No primeiro acesso (senha inicial/redefinida) a pessoa acabou de digitar a senha para entrar.
    if (!u.precisaTrocarSenha) {
      if (!senhaAtual) return res.json({ ok: false, message: "Informe sua senha atual." });
      const conf = await conferirSenhaSrv(senhaAtual, u.senhaHash);
      if (!conf.ok) return res.json({ ok: false, message: "Senha atual incorreta." });
    }
    await gravarUsuario({ ...u, senhaHash: await hashSenhaSrv(novaSenha), precisaTrocarSenha: false });
    res.json({ ok: true });
  } catch (err) {
    console.error("[auth] alterar-senha:", err && err.message);
    res.status(500).json({ ok: false, message: "Não foi possível alterar a senha agora." });
  }
});
// Preferências da própria pessoa (tema, notificações...).
app.put("/api/auth/preferencias", exigirChaveDeAcesso, async (req, res) => {
  try {
    const entrada = (req.body && req.body.preferencias) || {};
    const novas = { ...(req.portalUser.preferencias || { tema: "claro", notificacoes: true }) };
    for (const [k, v] of Object.entries(entrada).slice(0, 20)) {
      if (!/^[A-Za-z0-9_]{1,40}$/.test(k)) continue;
      if (typeof v === "boolean" || (typeof v === "string" && v.length <= 40) || typeof v === "number") novas[k] = v;
    }
    await gravarUsuario({ ...req.portalUser, preferencias: novas });
    res.json({ ok: true, preferencias: novas });
  } catch (err) {
    console.error("[auth] preferencias:", err && err.message);
    res.status(500).json({ ok: false });
  }
});

// ---- cadastro com código por e-mail corporativo ---------------------------
function gerarCodigo() {
  return String(nodeCrypto.randomInt(0, 1000000)).padStart(6, "0");
}
function hashCodigo(email, codigo) {
  return nodeCrypto.createHmac("sha256", segredoSessao).update("cod:" + email + ":" + codigo).digest("hex");
}
async function enviarCodigoPorEmail(email, nome, codigo) {
  if (!emailTransporter) {
    const e = new Error("email_nao_configurado");
    e.codigo = "email_nao_configurado";
    throw e;
  }
  await emailTransporter.sendMail({
    from: `"Portal Documental | Grupoprima" <${GMAIL_NOTIFICATIONS_USER}>`,
    to: email,
    subject: "Código de confirmação do seu cadastro — Portal Documental | Grupoprima",
    html:
      `<p>Olá${nome ? ", " + escaparHtmlEmail(nome) : ""}.</p>` +
      `<p>Use o código abaixo para confirmar o seu cadastro no Portal Documental | Grupoprima:</p>` +
      `<p style="font-size:28px;letter-spacing:6px;font-weight:700;">${codigo}</p>` +
      `<p>O código vale por 10 minutos e só pode ser usado uma vez. Se você não pediu este cadastro, ignore este e-mail.</p>`,
  });
}
const MSG_FALHA_EMAIL =
  "Não foi possível enviar o código para o seu e-mail agora. Tente novamente em instantes ou fale com o administrador do portal.";

app.post("/api/auth/cadastro/iniciar", async (req, res) => {
  try {
    if (!chaveDoPortalConfere(req)) return res.status(401).json({ erro: "Acesso não autorizado." });
    if (limiteCadastroPorIpExcedido(ipDe(req))) {
      return res.json({ ok: false, message: "Muitas solicitações de cadastro. Tente novamente mais tarde." });
    }
    await segredoPronto;
    const nome = String((req.body && req.body.nome) || "").trim().replace(/\s+/g, " ");
    const email = normEmail(req.body && req.body.email);
    const senha = String((req.body && req.body.senha) || "");
    if (!nome) return res.json({ ok: false, message: "Informe seu nome completo." });
    if (nome.length > 120) return res.json({ ok: false, message: "Nome muito longo." });
    if (!email) return res.json({ ok: false, message: "Informe seu e-mail corporativo." });
    if (!emailValido(email)) return res.json({ ok: false, message: "Informe um e-mail em formato válido." });
    if (!email.endsWith("@" + DOMINIO_CADASTRO)) {
      return res.json({ ok: false, message: `O cadastro é permitido apenas para e-mails @${DOMINIO_CADASTRO}.` });
    }
    if (!senha) return res.json({ ok: false, message: "Crie uma senha." });
    if (!senhaAtendeRequisitoMinimoSrv(senha)) return res.json({ ok: false, message: REQUISITO_SENHA_MSG_SRV });
    if (await acharUsuarioPorEmail(email)) {
      return res.json({ ok: false, message: "Este e-mail já tem cadastro. Faça login normalmente." });
    }
    const ref = firestore.collection(COL_CADASTROS_PENDENTES).doc(slugUserId(email));
    const existente = await ref.get();
    const agora = Date.now();
    if (existente.exists && agora - (existente.data().ultimoEnvioMs || 0) < CODIGO_REENVIO_INTERVALO_MS) {
      return res.json({ ok: false, message: "Um código acabou de ser enviado. Aguarde 1 minuto para pedir outro." });
    }
    const codigo = gerarCodigo();
    await enviarCodigoPorEmail(email, nome, codigo);
    await ref.set({
      nome,
      email,
      senhaHash: await hashSenhaSrv(senha),
      codigoHash: hashCodigo(email, codigo),
      expiraEm: agora + CODIGO_VALIDADE_MS,
      tentativas: 0,
      reenvios: 0,
      ultimoEnvioMs: agora,
      criadoEm: new Date(agora).toISOString(),
    });
    res.json({ ok: true, validadeMinutos: CODIGO_VALIDADE_MS / 60000 });
  } catch (err) {
    console.error("[auth] cadastro/iniciar:", err && err.message);
    res.json({ ok: false, message: err && err.codigo === "email_nao_configurado" ? MSG_FALHA_EMAIL : MSG_FALHA_EMAIL });
  }
});

app.post("/api/auth/cadastro/reenviar", async (req, res) => {
  try {
    if (!chaveDoPortalConfere(req)) return res.status(401).json({ erro: "Acesso não autorizado." });
    await segredoPronto;
    const email = normEmail(req.body && req.body.email);
    if (!emailValido(email)) return res.json({ ok: false, message: "Informe um e-mail em formato válido." });
    const ref = firestore.collection(COL_CADASTROS_PENDENTES).doc(slugUserId(email));
    const snap = await ref.get();
    if (!snap.exists) return res.json({ ok: false, message: "Não há cadastro em andamento para este e-mail. Comece o cadastro de novo." });
    const c = snap.data();
    const agora = Date.now();
    if (agora - (c.ultimoEnvioMs || 0) < CODIGO_REENVIO_INTERVALO_MS) {
      const falta = Math.ceil((CODIGO_REENVIO_INTERVALO_MS - (agora - c.ultimoEnvioMs)) / 1000);
      return res.json({ ok: false, message: `Aguarde ${falta} segundos para pedir um novo código.`, aguardarSegundos: falta });
    }
    if ((c.reenvios || 0) >= CODIGO_MAX_REENVIOS) {
      await ref.delete();
      return res.json({ ok: false, message: "Limite de reenvios atingido. Comece o cadastro novamente." });
    }
    const codigo = gerarCodigo();
    await enviarCodigoPorEmail(email, c.nome, codigo);
    await ref.set({
      ...c,
      codigoHash: hashCodigo(email, codigo),
      expiraEm: agora + CODIGO_VALIDADE_MS,
      tentativas: 0,
      reenvios: (c.reenvios || 0) + 1,
      ultimoEnvioMs: agora,
    });
    res.json({ ok: true, validadeMinutos: CODIGO_VALIDADE_MS / 60000 });
  } catch (err) {
    console.error("[auth] cadastro/reenviar:", err && err.message);
    res.json({ ok: false, message: MSG_FALHA_EMAIL });
  }
});

app.post("/api/auth/cadastro/confirmar", async (req, res) => {
  try {
    if (!chaveDoPortalConfere(req)) return res.status(401).json({ erro: "Acesso não autorizado." });
    await segredoPronto;
    const email = normEmail(req.body && req.body.email);
    const codigo = String((req.body && req.body.codigo) || "").replace(/\s+/g, "");
    if (!emailValido(email)) return res.json({ ok: false, message: "Informe um e-mail em formato válido." });
    if (!/^\d{6}$/.test(codigo)) return res.json({ ok: false, message: "Informe o código de 6 dígitos enviado ao seu e-mail." });
    const ref = firestore.collection(COL_CADASTROS_PENDENTES).doc(slugUserId(email));
    const snap = await ref.get();
    if (!snap.exists) return res.json({ ok: false, message: "Não há cadastro aguardando confirmação para este e-mail. Comece o cadastro de novo." });
    const c = snap.data();
    if (Date.now() > (c.expiraEm || 0)) {
      return res.json({ ok: false, expirado: true, message: "O código expirou. Peça um novo código." });
    }
    if ((c.tentativas || 0) >= CODIGO_MAX_TENTATIVAS) {
      return res.json({ ok: false, expirado: true, message: "Limite de tentativas atingido. Peça um novo código." });
    }
    if (!iguaisSeguro(hashCodigo(email, codigo), c.codigoHash)) {
      const tentativas = (c.tentativas || 0) + 1;
      await ref.update({ tentativas });
      const restantes = CODIGO_MAX_TENTATIVAS - tentativas;
      return res.json({
        ok: false,
        message: restantes > 0 ? `Código incorreto. Você ainda tem ${restantes} tentativa(s).` : "Limite de tentativas atingido. Peça um novo código.",
        ...(restantes <= 0 ? { expirado: true } : {}),
      });
    }
    // Código correto: uso único — apaga o cadastro pendente ANTES de criar o usuário.
    await ref.delete();
    if (await acharUsuarioPorEmail(email)) {
      return res.json({ ok: false, message: "Este e-mail já tem cadastro. Faça login normalmente." });
    }
    const agora = new Date().toISOString();
    const novo = {
      id: slugUserId(email),
      nome: c.nome,
      email,
      perfil: null, // nenhum nível até um administrador autorizar
      senhaHash: c.senhaHash,
      precisaTrocarSenha: false,
      status: STATUS_PENDENTE,
      criadoEm: agora,
      criadoPor: "autocadastro",
      emailConfirmadoEm: agora,
      ultimoAcesso: agora,
      preferencias: { tema: "claro", notificacoes: true },
      historicoAcesso: [eventoHistorico("cadastro_confirmado", { porNome: c.nome, porEmail: email })],
    };
    await gravarUsuario(novo);
    const token = await criarSessao(novo, req);
    res.json(respostaLoginOk(novo, token));
  } catch (err) {
    console.error("[auth] cadastro/confirmar:", err && err.message);
    res.json({ ok: false, message: "Não foi possível confirmar o cadastro agora. Tente novamente." });
  }
});

// ---- gestão de usuários (somente Administrador) --------------------------
async function contarAdminsAtivos(excluirId) {
  const q = await firestore.collection(COL_USUARIOS).get();
  return q.docs.filter((d) => d.id !== excluirId && d.data().perfil === "admin" && statusEfetivo(d.data()) === "ativo").length;
}
function atorDe(req) {
  return { porNome: req.portalUser.nome, porEmail: req.portalUser.email };
}
app.get("/api/usuarios", exigirAdmin, async (req, res) => {
  try {
    const q = await firestore.collection(COL_USUARIOS).get();
    res.setHeader("Cache-Control", "no-store");
    res.json({ ok: true, usuarios: q.docs.map((d) => usuarioVisaoAdmin({ ...d.data(), id: d.id })) });
  } catch (err) {
    console.error("[usuarios] listar:", err && err.message);
    res.status(500).json({ ok: false, message: "Não foi possível carregar os usuários agora." });
  }
});
// Dados da própria pessoa (Meu Perfil) — qualquer usuário ativo.
app.get("/api/usuarios/eu", exigirChaveDeAcesso, (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json({ ok: true, usuario: usuarioPublico(req.portalUser) });
});
app.post("/api/usuarios", exigirAdmin, async (req, res) => {
  try {
    const nome = String((req.body && req.body.nome) || "").trim().replace(/\s+/g, " ");
    const email = normEmail(req.body && req.body.email);
    const perfil = String((req.body && req.body.perfil) || "");
    if (!nome || nome.length > 120) return res.json({ ok: false, message: "Informe o nome do usuário." });
    if (!emailValido(email)) return res.json({ ok: false, message: "Informe um e-mail válido." });
    if (!PERFIS_VALIDOS.includes(perfil)) return res.json({ ok: false, message: "Perfil de acesso inválido." });
    if (!SENHA_INICIAL_CONFIGURADA) return res.json({ ok: false, message: MSG_SENHA_INICIAL_AUSENTE });
    if (await acharUsuarioPorEmail(email)) return res.json({ ok: false, message: "Já existe um usuário com este e-mail." });
    const agora = new Date().toISOString();
    const novo = {
      id: slugUserId(email),
      nome,
      email,
      perfil,
      senhaHash: await hashSenhaSrv(SENHA_INICIAL_PADRAO),
      precisaTrocarSenha: true,
      status: "ativo",
      criadoEm: agora,
      criadoPor: req.portalUser.nome || req.portalUser.email || "admin",
      ultimoAcesso: null,
      preferencias: { tema: "claro", notificacoes: true },
      historicoAcesso: [eventoHistorico("criado_pelo_administrador", { perfil, ...atorDe(req) })],
    };
    await gravarUsuario(novo);
    res.json({ ok: true, usuario: usuarioVisaoAdmin(novo) });
  } catch (err) {
    console.error("[usuarios] criar:", err && err.message);
    res.status(500).json({ ok: false, message: "Não foi possível criar o usuário agora." });
  }
});
app.put("/api/usuarios/:id", exigirAdmin, async (req, res) => {
  try {
    const alvo = await lerUsuarioPorId(req.params.id, true);
    if (!alvo) return res.status(404).json({ ok: false, message: "Usuário não encontrado." });
    const body = req.body || {};
    const novo = { ...alvo };
    const hist = Array.isArray(alvo.historicoAcesso) ? [...alvo.historicoAcesso] : [];
    const ator = atorDe(req);
    const ehEu = alvo.id === req.portalUser.id;
    if (typeof body.nome === "string") {
      const n = body.nome.trim().replace(/\s+/g, " ");
      if (!n || n.length > 120) return res.json({ ok: false, message: "Nome inválido." });
      novo.nome = n;
    }
    if (body.perfil !== undefined && body.perfil !== alvo.perfil) {
      if (!PERFIS_VALIDOS.includes(body.perfil)) return res.json({ ok: false, message: "Perfil de acesso inválido." });
      if (statusEfetivo(alvo) === STATUS_PENDENTE) {
        return res.json({ ok: false, message: "Este cadastro está aguardando autorização. Use \"Autorizar\" para definir o perfil." });
      }
      if (ehEu) return res.json({ ok: false, message: "Você não pode alterar o seu próprio perfil de acesso." });
      if (alvo.perfil === "admin" && statusEfetivo(alvo) === "ativo" && (await contarAdminsAtivos(alvo.id)) === 0) {
        return res.json({ ok: false, message: "É preciso manter pelo menos um administrador ativo." });
      }
      hist.push(eventoHistorico("perfil_alterado", { de: alvo.perfil || null, para: body.perfil, ...ator }));
      novo.perfil = body.perfil;
    }
    if (body.status !== undefined && body.status !== statusEfetivo(alvo)) {
      if (!["ativo", "inativo"].includes(body.status)) return res.json({ ok: false, message: "Status inválido." });
      if (ehEu) return res.json({ ok: false, message: "Você não pode desativar o seu próprio acesso." });
      if (body.status === "ativo" && statusEfetivo(alvo) === STATUS_PENDENTE) {
        return res.json({ ok: false, message: "Este cadastro está aguardando autorização. Use \"Autorizar\" para definir o perfil." });
      }
      if (body.status === "inativo" && alvo.perfil === "admin" && statusEfetivo(alvo) === "ativo" && (await contarAdminsAtivos(alvo.id)) === 0) {
        return res.json({ ok: false, message: "É preciso manter pelo menos um administrador ativo." });
      }
      hist.push(eventoHistorico(body.status === "inativo" ? "acesso_revogado" : "acesso_reativado", ator));
      novo.status = body.status;
    }
    novo.historicoAcesso = hist;
    await gravarUsuario(novo);
    if (novo.status === "inativo") await encerrarSessoesDoUsuario(novo.id);
    res.json({ ok: true, usuario: usuarioVisaoAdmin(novo) });
  } catch (err) {
    console.error("[usuarios] editar:", err && err.message);
    res.status(500).json({ ok: false, message: "Não foi possível salvar as alterações agora." });
  }
});
app.post("/api/usuarios/:id/autorizar", exigirAdmin, async (req, res) => {
  try {
    const alvo = await lerUsuarioPorId(req.params.id, true);
    if (!alvo) return res.status(404).json({ ok: false, message: "Usuário não encontrado." });
    if (alvo.id === req.portalUser.id) return res.json({ ok: false, message: "Você não pode autorizar o seu próprio acesso." });
    if (statusEfetivo(alvo) !== STATUS_PENDENTE) return res.json({ ok: false, message: "Este usuário não está aguardando autorização." });
    const perfil = String((req.body && req.body.perfil) || "");
    if (!PERFIS_VALIDOS.includes(perfil)) return res.json({ ok: false, message: "Escolha um nível de acesso existente." });
    const agora = new Date().toISOString();
    const ator = atorDe(req);
    const novo = {
      ...alvo,
      perfil,
      status: "ativo",
      autorizadoEm: agora,
      autorizadoPor: { nome: ator.porNome, email: ator.porEmail },
      historicoAcesso: [...(Array.isArray(alvo.historicoAcesso) ? alvo.historicoAcesso : []), eventoHistorico("acesso_autorizado", { perfil, ...ator })],
    };
    await gravarUsuario(novo);
    res.json({ ok: true, usuario: usuarioVisaoAdmin(novo) });
  } catch (err) {
    console.error("[usuarios] autorizar:", err && err.message);
    res.status(500).json({ ok: false, message: "Não foi possível autorizar agora." });
  }
});
app.post("/api/usuarios/:id/redefinir-senha", exigirAdmin, async (req, res) => {
  try {
    const alvo = await lerUsuarioPorId(req.params.id, true);
    if (!alvo) return res.status(404).json({ ok: false, message: "Usuário não encontrado." });
    if (!SENHA_INICIAL_CONFIGURADA) return res.status(400).json({ ok: false, message: MSG_SENHA_INICIAL_AUSENTE });
    const novo = {
      ...alvo,
      senhaHash: await hashSenhaSrv(SENHA_INICIAL_PADRAO),
      precisaTrocarSenha: true,
      historicoAcesso: [...(Array.isArray(alvo.historicoAcesso) ? alvo.historicoAcesso : []), eventoHistorico("senha_redefinida", atorDe(req))],
    };
    await gravarUsuario(novo);
    await encerrarSessoesDoUsuario(novo.id);
    res.json({ ok: true });
  } catch (err) {
    console.error("[usuarios] redefinir-senha:", err && err.message);
    res.status(500).json({ ok: false, message: "Não foi possível redefinir a senha agora." });
  }
});
app.delete("/api/usuarios/:id", exigirAdmin, async (req, res) => {
  try {
    const alvo = await lerUsuarioPorId(req.params.id, true);
    if (!alvo) return res.json({ ok: true });
    if (alvo.id === req.portalUser.id) return res.json({ ok: false, message: "Você não pode excluir o seu próprio usuário." });
    if (alvo.perfil === "admin" && statusEfetivo(alvo) === "ativo" && (await contarAdminsAtivos(alvo.id)) === 0) {
      return res.json({ ok: false, message: "É preciso manter pelo menos um administrador ativo." });
    }
    await encerrarSessoesDoUsuario(alvo.id);
    await firestore.collection(COL_USUARIOS).doc(alvo.id).delete();
    invalidarCacheUsuario(alvo.id);
    res.json({ ok: true });
  } catch (err) {
    console.error("[usuarios] excluir:", err && err.message);
    res.status(500).json({ ok: false, message: "Não foi possível excluir o usuário agora." });
  }
});

// ---- privacidade por dono ----------------------------------------------------
// Coleção -> campo que identifica o responsável ({ nome, email }) em cada registro.
const DONOS_POR_COLECAO = {
  homologacoes: "consultor", // Homologação, Atualização de Homologação
  batch_document_submissions: "usuarioSolicitante", // Envio de Documentações em Lote
  client_document_analysis: "usuario", // Análise Documental de Clientes
  financeiro_solicitacoes: "consultor", // Informações Financeiras / Termo de Abertura de Projeto
};
/** Mesma regra de registroPertenceAoUsuario() do navegador: e-mail (sem
 *  diferenciar maiúsculas) quando os dois lados têm; senão, o nome. */
function pertenceAoUsuario(responsavel, u) {
  if (!u || !responsavel || typeof responsavel !== "object") return false;
  const emR = normEmail(responsavel.email);
  const emU = normEmail(u.email);
  if (emR && emU) return emR === emU;
  const nmR = String(responsavel.nome || "").trim().toLowerCase();
  const nmU = String(u.nome || "").trim().toLowerCase();
  return !!nmR && nmR === nmU;
}
function erroProibido() {
  const e = new Error("proibido");
  e.status = 403;
  return e;
}
/** Confere, para quem NÃO é Administrador, se pode gravar este documento. */
function validarEscritaPrivada(colecao, existente, corpo, u) {
  const campo = DONOS_POR_COLECAO[colecao];
  if (!campo || ehAdminAtivo(u)) return;
  if (existente && !pertenceAoUsuario(existente[campo], u)) throw erroProibido();
  if (!corpo[campo] || typeof corpo[campo] !== "object") {
    corpo[campo] = { nome: u.nome, email: u.email };
  } else if (!pertenceAoUsuario(corpo[campo], u)) {
    throw erroProibido();
  }
}

// ---- anexos: quem pode abrir cada arquivo do Drive -----------------------------
const REGEX_ID_ARQUIVO = /"(?:driveFileId|fileId)"\s*:\s*"([^"]{5,200})"/g;
let indiceArquivos = { em: 0, privados: new Map(), corporativos: new Set() };
async function reconstruirIndiceArquivos() {
  const privados = new Map(); // fileId -> Set(chave do dono)
  const corporativos = new Set();
  const chaveDono = (r) => {
    if (!r || typeof r !== "object") return null;
    const em = normEmail(r.email);
    return em ? em : "nome:" + String(r.nome || "").trim().toLowerCase();
  };
  for (const [col, campo] of Object.entries(DONOS_POR_COLECAO)) {
    const snap = await firestore.collection(col).get();
    snap.docs.forEach((d) => {
      const dados = d.data() || {};
      const dono = chaveDono(dados[campo]);
      if (!dono) return;
      const texto = JSON.stringify(dados);
      let m;
      REGEX_ID_ARQUIVO.lastIndex = 0;
      while ((m = REGEX_ID_ARQUIVO.exec(texto))) {
        if (!privados.has(m[1])) privados.set(m[1], new Set());
        privados.get(m[1]).add(dono);
      }
    });
  }
  for (const col of ["documentos_confirmados", "conference_queue"]) {
    const snap = await firestore.collection(col).get();
    snap.docs.forEach((d) => {
      const texto = JSON.stringify(d.data() || {});
      let m;
      REGEX_ID_ARQUIVO.lastIndex = 0;
      while ((m = REGEX_ID_ARQUIVO.exec(texto))) corporativos.add(m[1]);
    });
  }
  indiceArquivos = { em: Date.now(), privados, corporativos };
}
async function garantirIndiceArquivos(forcar) {
  if (forcar || Date.now() - indiceArquivos.em > 30000) await reconstruirIndiceArquivos();
}
function chavesDoUsuario(u) {
  return [normEmail(u.email), "nome:" + String(u.nome || "").trim().toLowerCase()];
}
/** true = bloqueado: o arquivo pertence a um registro privado de OUTRA pessoa. */
function arquivoPrivadoDeOutro(fileId, u) {
  if (indiceArquivos.corporativos.has(fileId)) return false;
  const donos = indiceArquivos.privados.get(fileId);
  if (!donos) return false;
  return !chavesDoUsuario(u).some((k) => donos.has(k));
}
async function podeAbrirArquivo(fileId, u) {
  if (ehAdminAtivo(u)) return true;
  await garantirIndiceArquivos(false);
  const decide = async () => {
    if (arquivoPrivadoDeOutro(fileId, u)) return false;
    if (indiceArquivos.privados.has(fileId) || indiceArquivos.corporativos.has(fileId)) return true;
    // Fora de qualquer registro: vale quem enviou o arquivo (se foi enviado pelo portal).
    const d = await firestore.collection(COL_DONOS_ARQUIVOS).doc(fileId).get();
    if (d.exists) {
      const dono = d.data();
      return normEmail(dono.email) === normEmail(u.email);
    }
    return true; // arquivo comum da pasta do Drive (documentação corporativa)
  };
  if (await decide()) return true;
  await garantirIndiceArquivos(true); // pode ser um registro salvo há instantes
  return decide();
}
async function registrarDonoArquivo(fileId, u) {
  try {
    await firestore.collection(COL_DONOS_ARQUIVOS).doc(fileId).set({
      email: normEmail(u.email),
      nome: u.nome,
      em: new Date().toISOString(),
    });
  } catch (_) {}
}

// =========================================================================
// LOGIN COM GOOGLE (2026-09-29) — rota nova: POST /api/auth/google
//
// Até aqui não existia nenhum backend de autenticação de verdade: o login
// por e-mail/senha (authenticate(), em index.html) faz tudo no navegador —
// hash da senha e busca na coleção "users" via o proxy genérico de banco
// (/api/db/users). Um comentário do próprio index.html já antecipava isso:
// "quando houver backend de autenticação de verdade, authenticate() passa
// a ser POST /api/auth/login".
//
// "Entrar com Google" é ADICIONAL ao login por senha (não substitui nada) e
// PRECISA ser conferido aqui no servidor — um token do Google não pode ser
// validado com segurança só no navegador, porque a assinatura precisa ser
// checada contra as chaves públicas do Google. Esta rota faz só isso:
// confirma "esta pessoa é realmente dona deste e-mail" e, se o e-mail já
// existir como usuário ativo em "users", devolve o mesmo formato de sucesso
// que authenticate() já devolve — o Google NUNCA cria conta nova sozinho,
// só prova identidade de um e-mail que já precisa estar cadastrado (mesma
// regra de hoje: só um admin cria usuário, em UsersManagementView).
// =========================================================================
const GOOGLE_OAUTH_CLIENT_ID = process.env.GOOGLE_OAUTH_CLIENT_ID || null;
const googleOAuthClient = GOOGLE_OAUTH_CLIENT_ID
  ? new OAuth2Client(GOOGLE_OAUTH_CLIENT_ID)
  : null;
if (!googleOAuthClient) {
  console.warn(
    "[aviso] GOOGLE_OAUTH_CLIENT_ID não definida — \"Entrar com Google\" está desativado " +
      "(a rota /api/auth/google responde ok:false em vez de verificar qualquer token)."
  );
}

/** Mesma lógica de slugUserId() em index.html (linha ~2632) — precisa ficar
 *  IDÊNTICA, porque é a chave usada para achar o documento do usuário em
 *  "users" a partir de um e-mail (id = slug do e-mail em minúsculas). */
function slugUserId(email) {
  return (
    (email || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "_") || "usuario"
  );
}

/** Verifica a assinatura/validade de um ID token do Google (credencial
 *  devolvida pelo Google Identity Services no navegador) e devolve o
 *  payload decodificado ({ email, email_verified, name, ... }). Nunca
 *  confia em nada do token sem essa verificação — é exatamente o que essa
 *  biblioteca oficial do Google faz (busca as chaves públicas do Google e
 *  confere assinatura, emissor, audiência e validade). */
async function verificarGoogleIdToken(credential) {
  if (!googleOAuthClient) {
    throw new Error("GOOGLE_OAUTH_CLIENT_ID não configurado no servidor.");
  }
  const ticket = await googleOAuthClient.verifyIdToken({
    idToken: credential,
    audience: GOOGLE_OAUTH_CLIENT_ID,
  });
  return ticket.getPayload();
}

app.post("/api/auth/google", exigirChaveSomente, async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!credential) {
      return res.json({ ok: false, message: "Credencial do Google ausente." });
    }
    if (!googleOAuthClient) {
      return res.json({
        ok: false,
        message: "Login com Google ainda não está configurado neste servidor.",
      });
    }
    let payload;
    try {
      payload = await verificarGoogleIdToken(credential);
    } catch (erroVerificacao) {
      console.error("Falha ao verificar credencial do Google:", erroVerificacao.message);
      return res.json({
        ok: false,
        message: "Não foi possível confirmar seu acesso com o Google. Tente novamente.",
      });
    }
    if (!payload?.email || !payload.email_verified) {
      return res.json({
        ok: false,
        message: "Não foi possível confirmar seu e-mail do Google.",
      });
    }
    const u = await acharUsuarioPorEmail(payload.email);
    if (!u) {
      return res.json({
        ok: false,
        message: "E-mail não encontrado. Fale com o administrador do portal.",
      });
    }
    if (statusEfetivo(u) === "inativo") {
      return res.json({
        ok: false,
        message: "Este acesso está desativado. Fale com o administrador do portal.",
      });
    }
    const atualizado = { ...u, ultimoAcesso: new Date().toISOString() };
    await gravarUsuario(atualizado);
    const token = await criarSessao(atualizado, req);
    return res.json(respostaLoginOk(atualizado, token));
  } catch (err) {
    console.error("Erro em /api/auth/google:", err.message);
    return res.json({
      ok: false,
      message: "Não foi possível verificar seu acesso com o Google agora.",
    });
  }
});

// =========================================================================
// NOTIFICAÇÕES POR E-MAIL — HOMOLOGAÇÃO (2026-09-29) — rota nova:
// POST /api/homologacao/notify
//
// Pedido da Iasmin: ela (admin) recebe um aviso quando entra uma nova
// solicitação de homologação; o consultor que pediu aquela homologação
// específica (campo consultor.email, já salvo em cada registro) recebe um
// aviso quando ela fica "em andamento" e quando é "concluída". "Cancelada"
// de propósito NÃO dispara e-mail (não foi pedido).
//
// Não existia NENHUM envio de e-mail neste projeto antes — construído do
// zero com nodemailer via uma conta Gmail dedicada (SMTP com senha de
// app). Assim como o restante do backend, e-mail é 100% best-effort: se
// não estiver configurado, ou se o envio falhar, a rota devolve
// {ok:false, message} (nunca 500) — quem chama (index.html) sempre faz a
// chamada em "fire-and-forget" e NUNCA deixa isso bloquear salvar ou
// atualizar uma homologação de verdade.
// =========================================================================
const GMAIL_NOTIFICATIONS_USER = process.env.GMAIL_NOTIFICATIONS_USER || null;
const GMAIL_NOTIFICATIONS_APP_PASSWORD = process.env.GMAIL_NOTIFICATIONS_APP_PASSWORD || null;
const emailTransporter =
  GMAIL_NOTIFICATIONS_USER && GMAIL_NOTIFICATIONS_APP_PASSWORD
    ? nodemailer.createTransport({
        service: "gmail",
        auth: { user: GMAIL_NOTIFICATIONS_USER, pass: GMAIL_NOTIFICATIONS_APP_PASSWORD },
      })
    : null;
if (!emailTransporter) {
  console.warn(
    "[aviso] GMAIL_NOTIFICATIONS_USER/GMAIL_NOTIFICATIONS_APP_PASSWORD não definidas — " +
      "notificações por e-mail de Homologação estão desativadas."
  );
}

function formatarDataBr(iso) {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleDateString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
    });
  } catch (e) {
    return "-";
  }
}

function montarEmailNovaSolicitacao({ cliente, consultor, dataSolicitacao, bases, fluxo, tipoAtualizacao }) {
  const nomeConsultor = consultor?.nome || "Usuário do portal";
  const basesTexto = Array.isArray(bases) && bases.length ? bases.join(", ") : "-";
  // fluxo "atualizacao" (2026-10-20): nova demanda documental de um cliente
  // JÁ cadastrado (aba "Atualização de Homologação"). Sem `fluxo` (ou
  // "homologacao") o e-mail continua exatamente como era.
  const ehAtualizacao = fluxo === "atualizacao";
  return {
    subject: ehAtualizacao ? `${cliente} | Nova Atualização de Homologação` : `${cliente} | Nova Homologação`,
    html:
      (ehAtualizacao
        ? `<p>Uma nova atualização de homologação foi solicitada no Portal Documental | Grupoprima.</p>`
        : `<p>Uma nova homologação foi solicitada no Portal Documental | Grupoprima.</p>`) +
      `<ul>` +
      `<li><strong>Cliente:</strong> ${cliente}</li>` +
      (ehAtualizacao && tipoAtualizacao ? `<li><strong>Tipo de atualização:</strong> ${tipoAtualizacao}</li>` : ``) +
      `<li><strong>Solicitada por:</strong> ${nomeConsultor}</li>` +
      `<li><strong>Data da solicitação:</strong> ${formatarDataBr(dataSolicitacao)}</li>` +
      `<li><strong>Bases:</strong> ${basesTexto}</li>` +
      `</ul>` +
      `<p>Acesse o Portal Documental para acompanhar.</p>`,
  };
}

function montarEmailStatusHomologacao({ cliente, consultor, status, dataConclusao, fluxo }) {
  const nomeConsultor = consultor?.nome || "Usuário do portal";
  const ehAtualizacao = fluxo === "atualizacao";
  const rotulo = ehAtualizacao ? "Atualização de Homologação" : "Homologação";
  const rotuloMin = ehAtualizacao ? "atualização de homologação" : "homologação";
  if (status === "concluida") {
    return {
      subject: `${cliente} | ${rotulo} Concluída`,
      html:
        `<p>Olá, ${nomeConsultor}.</p>` +
        `<p>A ${rotuloMin} de <strong>${cliente}</strong> foi marcada como <strong>concluída</strong>` +
        (dataConclusao ? ` em ${formatarDataBr(dataConclusao)}.` : `.`) +
        `</p><p>Acesse o Portal Documental para ver os detalhes.</p>`,
    };
  }
  return {
    subject: `${cliente} | ${rotulo} em andamento`,
    html:
      `<p>Olá, ${nomeConsultor}.</p>` +
      `<p>A ${rotuloMin} de <strong>${cliente}</strong> está agora <strong>em andamento</strong>.</p>` +
      `<p>Acesse o Portal Documental para acompanhar.</p>`,
  };
}

// Notificação de NOVA solicitação de homologação: por pedido explícito da
// Iasmin (2026-09-30), vai só para o e-mail dela — não mais para "todos os
// administradores ativos" (esse era o comportamento original, trocado a
// pedido dela depois de testar).
const HOMOLOGACAO_NOVA_SOLICITACAO_EMAIL = "iasmin.oliveira@grupoprimalog.com.br";

// Arquivos de resposta anexados ao e-mail de "Concluída" (2026-10-01,
// pedido explícito da Iasmin): "Quando a homologação for marcada como
// concluida, os arquivos adicionados nesse campo devem ir em anexo no
// email enviado ao consultor/usuário solicitante." Baixa cada arquivo do
// Shared Drive (mesma chamada já usada em GET /api/documents/:id/file,
// só trocando responseType de "stream" para "arraybuffer" — aqui o
// conteúdo precisa virar um Buffer inteiro na memória pra virar anexo do
// nodemailer, não ser repassado direto pra um response HTTP). Limite
// total de ~20MB — abaixo do limite comum de ~25MB de provedores de
// e-mail (contando a sobra pro resto da mensagem) — arquivos que não
// couberem, ou que falharem ao baixar, são OMITIDOS do e-mail (nunca
// derrubam o envio inteiro) e listados na própria mensagem, apontando o
// consultor de volta pro Portal.
const HOMOLOGACAO_ANEXOS_EMAIL_MAX_BYTES = 20 * 1024 * 1024;

async function baixarBytesDoDrive(fileId) {
  const resposta = await drive.files.get(
    { fileId, alt: "media", supportsAllDrives: true },
    { responseType: "arraybuffer" }
  );
  return Buffer.from(resposta.data);
}

async function prepararAnexosEmailHomologacao(anexosResposta) {
  const lista = Array.isArray(anexosResposta) ? anexosResposta.filter(Boolean) : [];
  const attachments = [];
  const omitidos = [];
  let totalBytes = 0;
  for (const anexo of lista) {
    // Corrigido em 2026-10-01 (relato da Iasmin: um e-mail de "Concluída"
    // saiu sem os anexos, em silêncio) — antes um anexo sem driveFileId
    // (upload ainda pendente, ou que caiu no fallback de asset fora do
    // Drive oficial) era filtrado ANTES de chegar aqui, no frontend
    // (notificarHomologacao em index.html), então o e-mail saía sem
    // anexo e SEM NENHUM AVISO. Agora o frontend manda todo mundo, e é
    // aqui que se decide o que realmente consegue ser anexado — o que não
    // tem driveFileId entra direto como omitido, com o mesmo aviso no
    // corpo do e-mail que qualquer outra falha.
    if (!anexo.driveFileId) {
      omitidos.push(anexo.nome || "arquivo sem nome");
      continue;
    }
    const tamanho = Number(anexo.tamanho) || 0;
    if (totalBytes + tamanho > HOMOLOGACAO_ANEXOS_EMAIL_MAX_BYTES) {
      omitidos.push(anexo.nome || "arquivo sem nome");
      continue;
    }
    try {
      const bytes = await baixarBytesDoDrive(anexo.driveFileId);
      attachments.push({
        filename: anexo.nome || "arquivo",
        content: bytes,
        contentType: anexo.tipo || "application/octet-stream",
      });
      totalBytes += bytes.length;
    } catch (err) {
      console.error(`Erro ao baixar anexo de resposta "${anexo.nome}" do Drive:`, err.message);
      omitidos.push(anexo.nome || "arquivo sem nome");
    }
  }
  return { attachments, omitidos };
}

app.post("/api/homologacao/notify", exigirChaveDeAcesso, async (req, res) => {
  if (!emailTransporter) {
    return res.json({ ok: false, message: "Notificações por e-mail não configuradas." });
  }
  try {
    const { tipo, cliente, consultor, dataSolicitacao, dataConclusao, bases, anexosResposta, fluxo, tipoAtualizacao } = req.body || {};
    if (!cliente) {
      return res.json({ ok: false, message: "Requisição inválida: informe 'cliente'." });
    }
    let destinatarios = [];
    let conteudo = null;
    if (tipo === "nova_solicitacao") {
      destinatarios = [HOMOLOGACAO_NOVA_SOLICITACAO_EMAIL];
      conteudo = montarEmailNovaSolicitacao({ cliente, consultor, dataSolicitacao, bases, fluxo, tipoAtualizacao });
    } else if (tipo === "em_andamento" || tipo === "concluida") {
      if (consultor?.email) destinatarios = [consultor.email];
      conteudo = montarEmailStatusHomologacao({ cliente, consultor, status: tipo, dataConclusao, fluxo });
    } else {
      return res.json({ ok: false, message: "Tipo de notificação desconhecido." });
    }
    if (!destinatarios.length) {
      return res.json({ ok: false, message: "Nenhum destinatário encontrado para esta notificação." });
    }
    let attachments = [];
    if (tipo === "concluida" && Array.isArray(anexosResposta) && anexosResposta.length > 0) {
      const preparo = await prepararAnexosEmailHomologacao(anexosResposta);
      attachments = preparo.attachments;
      if (preparo.omitidos.length > 0) {
        conteudo = {
          ...conteudo,
          html:
            conteudo.html +
            `<p style="color:#8a6d3b;">Obs.: ${preparo.omitidos.length === 1 ? "o arquivo" : "os arquivos"} ` +
            `${preparo.omitidos.map((n) => `"${n}"`).join(", ")} não ${preparo.omitidos.length === 1 ? "pôde" : "puderam"} ` +
            `ser anexado${preparo.omitidos.length === 1 ? "" : "s"} a este e-mail — acesse o Portal Documental para baixá-lo${preparo.omitidos.length === 1 ? "" : "s"}.</p>`,
        };
      }
    }
    await emailTransporter.sendMail({
      from: `"Portal Documental | Grupoprima" <${GMAIL_NOTIFICATIONS_USER}>`,
      to: destinatarios.join(","),
      subject: conteudo.subject,
      html: conteudo.html,
      ...(attachments.length > 0 ? { attachments } : {}),
    });
    return res.json({ ok: true });
  } catch (err) {
    console.error("Erro em /api/homologacao/notify:", err.message);
    return res.json({ ok: false, message: "Não foi possível enviar a notificação agora." });
  }
});

// ---------------------------------------------------------------------
// COFRE DE CREDENCIAIS DE HOMOLOGAÇÃO (2026-10-20, pedido da Iasmin)
//
// Quando a modalidade de envio de uma homologação é "Plataforma do cliente",
// o consultor informa URL + login + senha. Login e senha NUNCA vão para a
// coleção "homologacoes" (lida por qualquer usuário do portal, via
// /api/db/homologacoes) — ficam aqui, criptografados em repouso:
//
//   - AES-256-GCM, chave derivada (scrypt) da variável de ambiente
//     HOMOLOGACAO_CRED_KEY — que só existe no Cloud Run, nunca no código
//     nem em nenhum arquivo servido ao navegador. Use um segredo aleatório
//     longo (32+ caracteres) e guarde-o no Secret Manager.
//   - Coleção própria "homologacao_credenciais" (1 documento por
//     homologação), de propósito FORA de COLECOES_PERMITIDAS: nenhuma rota
//     genérica /api/db/... consegue lê-la ou listá-la.
//   - O id da homologação entra como dado autenticado (AAD) do GCM: um
//     registro copiado para outro id não decifra.
//   - Sem HOMOLOGACAO_CRED_KEY as rotas respondem { ok:false,
//     motivo:"nao_configurado" } — o portal então cai no comportamento
//     antigo (senha só em memória da sessão) e AVISA isso na tela; nunca
//     finge que guardou.
//   - Revelar exige, além da chave do portal, o e-mail de um usuário
//     Administrador ativo (conferido em "users"). ATENÇÃO: o login do portal
//     é feito no navegador (não há sessão no servidor), então essa conferência
//     é uma barreira adicional, não uma garantia criptográfica de identidade.
//   - Login e senha nunca são escritos em log.
// ---------------------------------------------------------------------
const crypto = require("crypto");
const HOMOLOGACAO_CRED_KEY_RAW = process.env.HOMOLOGACAO_CRED_KEY || null;
const homologacaoCredKey = HOMOLOGACAO_CRED_KEY_RAW
  ? crypto.scryptSync(HOMOLOGACAO_CRED_KEY_RAW, "grupoprima-homologacao-credenciais-v1", 32)
  : null;
if (!homologacaoCredKey) {
  console.warn(
    "[aviso] HOMOLOGACAO_CRED_KEY não definida — o cofre de credenciais de Homologação está " +
      "desativado (a senha da plataforma do cliente fica só em memória, na sessão de quem cadastrou)."
  );
}
const COLECAO_HOMOLOG_CREDENCIAIS = "homologacao_credenciais";
const HOMOLOG_ID_VALIDO = /^[A-Za-z0-9_-]{1,100}$/;

function cifrarCredenciais(homologId, objeto) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", homologacaoCredKey, iv);
  cipher.setAAD(Buffer.from(homologId, "utf8"));
  const data = Buffer.concat([cipher.update(JSON.stringify(objeto), "utf8"), cipher.final()]);
  return {
    v: 1,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
}
function decifrarCredenciais(homologId, doc) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    homologacaoCredKey,
    Buffer.from(doc.iv, "base64")
  );
  decipher.setAAD(Buffer.from(homologId, "utf8"));
  decipher.setAuthTag(Buffer.from(doc.tag, "base64"));
  const claro = Buffer.concat([decipher.update(Buffer.from(doc.data, "base64")), decipher.final()]);
  return JSON.parse(claro.toString("utf8"));
}
function exigirIdHomologacao(req, res, next) {
  if (!HOMOLOG_ID_VALIDO.test(req.params.id || "")) {
    return res.status(400).json({ ok: false, message: "Identificador inválido." });
  }
  next();
}

// Status do cofre: o formulário usa para dizer a verdade sobre onde a senha fica.
app.get("/api/homologacao/credenciais/status", exigirChaveDeAcesso, (req, res) => {
  res.json({ ok: true, configurado: !!homologacaoCredKey });
});

// Grava (ou atualiza) login e/ou senha. Campos omitidos mantêm o valor atual.
/** Credenciais de uma homologação: só o Administrador ou o consultor dono do registro. */
async function podeMexerNasCredenciais(homologId, u) {
  if (ehAdminAtivo(u)) return true;
  const d = await firestore.collection("homologacoes").doc(homologId).get();
  if (!d.exists) return true; // registro ainda não salvo: a credencial é de quem está cadastrando
  return pertenceAoUsuario(d.data().consultor, u);
}
app.put("/api/homologacao/:id/credenciais", exigirChaveDeAcesso, exigirIdHomologacao, async (req, res) => {
  if (!homologacaoCredKey) return res.json({ ok: false, motivo: "nao_configurado" });
  try {
    if (!(await podeMexerNasCredenciais(req.params.id, req.portalUser))) {
      return res.status(403).json({ ok: false, message: "Acesso não autorizado." });
    }
    const { login, senha } = req.body || {};
    const loginOk = typeof login === "string" && login.length > 0 && login.length <= 300;
    const senhaOk = typeof senha === "string" && senha.length > 0 && senha.length <= 300;
    if (!loginOk && !senhaOk) {
      return res.status(400).json({ ok: false, message: "Informe login e/ou senha." });
    }
    const ref = firestore.collection(COLECAO_HOMOLOG_CREDENCIAIS).doc(req.params.id);
    let atual = {};
    const existente = await ref.get();
    if (existente.exists) {
      try {
        atual = decifrarCredenciais(req.params.id, existente.data());
      } catch (e) {
        atual = {}; // registro ilegível (chave trocada): recomeça só com o que veio agora
      }
    }
    const novo = {
      login: loginOk ? login : atual.login || "",
      senha: senhaOk ? senha : atual.senha || "",
    };
    await ref.set({ ...cifrarCredenciais(req.params.id, novo), atualizadoEm: new Date().toISOString() });
    return res.json({ ok: true });
  } catch (err) {
    console.error("Erro ao gravar credenciais de homologação:", err.message);
    return res.status(500).json({ ok: false, message: "Não foi possível guardar as credenciais agora." });
  }
});

// Revela login e senha — só para Administrador ativo (ver nota acima).
app.post("/api/homologacao/:id/credenciais/revelar", exigirChaveDeAcesso, exigirIdHomologacao, async (req, res) => {
  if (!homologacaoCredKey) return res.json({ ok: false, motivo: "nao_configurado" });
  try {
    // A identidade vem da SESSÃO assinada (não mais do e-mail enviado no corpo).
    if (!ehAdminAtivo(req.portalUser)) {
      return res.status(403).json({ ok: false, message: "Somente a equipe responsável pode revelar as credenciais." });
    }
    const doc = await firestore.collection(COLECAO_HOMOLOG_CREDENCIAIS).doc(req.params.id).get();
    if (!doc.exists) return res.json({ ok: false, motivo: "inexistente" });
    const cred = decifrarCredenciais(req.params.id, doc.data());
    return res.json({ ok: true, login: cred.login || "", senha: cred.senha || "" });
  } catch (err) {
    console.error("Erro ao revelar credenciais de homologação:", err.message);
    return res.status(500).json({ ok: false, message: "Não foi possível revelar as credenciais agora." });
  }
});

// Remove as credenciais (homologação excluída, ou modalidade trocada).
app.delete("/api/homologacao/:id/credenciais", exigirChaveDeAcesso, exigirIdHomologacao, async (req, res) => {
  try {
    if (!(await podeMexerNasCredenciais(req.params.id, req.portalUser))) {
      return res.status(403).json({ ok: false, message: "Acesso não autorizado." });
    }
    await firestore.collection(COLECAO_HOMOLOG_CREDENCIAIS).doc(req.params.id).delete();
    return res.json({ ok: true });
  } catch (err) {
    console.error("Erro ao remover credenciais de homologação:", err.message);
    return res.status(500).json({ ok: false, message: "Não foi possível remover as credenciais agora." });
  }
});

// ---------------------------------------------------------------------
// POST /api/financeiro/encaminhar-email (2026-10-09, pedido da Iasmin)
//
// Etapa "Encaminhar ao Financeiro" das Informações Financeiras: ao registrar
// o encaminhamento no portal, o e-mail passa a ser ENVIADO de verdade (antes
// o portal só registrava e a pessoa mandava por fora). Mesma lógica das
// notificações de Homologação (/api/homologacao/notify): mesmo transporter
// Gmail, mesmo preparo de anexo (baixa do Drive, limite ~20MB, o que não
// couber/falhar é omitido e avisado no corpo — nunca derruba o envio).
//   - 1º e-mail do campo "E-mail(s) do Financeiro" = destinatário (TO);
//     os demais (depois do ";") = CÓPIA (CC).
//   - observações do encaminhamento vão no corpo do e-mail;
//   - o arquivo da resposta do cliente (versão encaminhada) vai em anexo.
// Falha de envio nunca vira 500 — responde { ok:false, message } e o
// frontend só avisa; o registro do encaminhamento no portal já foi salvo.
// ---------------------------------------------------------------------
function escaparHtmlEmail(valor) {
  return String(valor == null ? "" : valor)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function separarEmailsFinanceiro(entrada) {
  const lista = Array.isArray(entrada) ? entrada : String(entrada || "").split(/[;,\s]+/);
  const vistos = new Set();
  const emails = [];
  for (const bruto of lista) {
    const e = String(bruto || "").trim();
    if (!e) continue;
    const k = e.toLowerCase();
    if (vistos.has(k)) continue;
    vistos.add(k);
    emails.push(e);
  }
  const valido = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
  return { para: emails[0] || null, copia: emails.slice(1), invalido: emails.find((e) => !valido(e)) || null };
}

function montarEmailEncaminhamentoFinanceiro({ cliente, consultor, emailCliente, dataEncaminhamento, versaoResposta, observacoes, encaminhadoPor, nomeArquivo }) {
  const obs = String(observacoes || "").trim();
  const linhas = [
    `<li><strong>Cliente:</strong> ${escaparHtmlEmail(cliente)}</li>`,
    consultor?.nome ? `<li><strong>Consultor:</strong> ${escaparHtmlEmail(consultor.nome)}</li>` : "",
    emailCliente ? `<li><strong>E-mail do cliente:</strong> ${escaparHtmlEmail(emailCliente)}</li>` : "",
    dataEncaminhamento ? `<li><strong>Data do encaminhamento:</strong> ${formatarDataBr(dataEncaminhamento + "T12:00:00")}</li>` : "",
    versaoResposta ? `<li><strong>Versão da resposta:</strong> ${escaparHtmlEmail(versaoResposta)}</li>` : "",
    nomeArquivo ? `<li><strong>Arquivo:</strong> ${escaparHtmlEmail(nomeArquivo)}</li>` : "",
  ].join("");
  return {
    subject: `${cliente} | Informações Financeiras — resposta do cliente`,
    html:
      `<p>Olá.</p>` +
      `<p>Segue em anexo a resposta do cliente <strong>${escaparHtmlEmail(cliente)}</strong> com as informações financeiras` +
      (encaminhadoPor ? `, encaminhada por <strong>${escaparHtmlEmail(encaminhadoPor)}</strong>` : "") +
      `.</p><ul>${linhas}</ul>` +
      (obs ? `<p><strong>Observações:</strong></p><p style="white-space:pre-wrap;">${escaparHtmlEmail(obs)}</p>` : ""),
  };
}

app.post("/api/financeiro/encaminhar-email", exigirChaveDeAcesso, async (req, res) => {
  if (!emailTransporter) {
    return res.json({ ok: false, message: "Envio de e-mail não configurado no servidor." });
  }
  try {
    const { cliente, consultor, emailCliente, emailsFinanceiro, dataEncaminhamento, versaoResposta, observacoes, encaminhadoPor, remetente, anexo } = req.body || {};
    if (!cliente) return res.json({ ok: false, message: "Requisição inválida: informe 'cliente'." });
    const dest = separarEmailsFinanceiro(emailsFinanceiro);
    if (!dest.para) return res.json({ ok: false, message: "Nenhum e-mail do Financeiro informado." });
    if (dest.invalido) return res.json({ ok: false, message: `O e-mail "${dest.invalido}" não parece válido.` });

    let conteudo = montarEmailEncaminhamentoFinanceiro({
      cliente, consultor, emailCliente, dataEncaminhamento, versaoResposta, observacoes, encaminhadoPor, nomeArquivo: anexo?.nome,
    });
    let attachments = [];
    if (anexo) {
      const preparo = await prepararAnexosEmailHomologacao([anexo]);
      attachments = preparo.attachments;
      if (preparo.omitidos.length > 0) {
        conteudo = {
          ...conteudo,
          html:
            conteudo.html +
            `<p style="color:#8a6d3b;">Obs.: o arquivo "${escaparHtmlEmail(preparo.omitidos[0])}" não pôde ser anexado a este e-mail — ` +
            `acesse o Portal Documental para baixá-lo.</p>`,
        };
      }
    }
    const replyTo = remetente?.email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(remetente.email) ? remetente.email : undefined;
    await emailTransporter.sendMail({
      from: `"Portal Documental | Grupoprima" <${GMAIL_NOTIFICATIONS_USER}>`,
      to: dest.para,
      ...(dest.copia.length > 0 ? { cc: dest.copia.join(",") } : {}),
      ...(replyTo ? { replyTo } : {}),
      subject: conteudo.subject,
      html: conteudo.html,
      ...(attachments.length > 0 ? { attachments } : {}),
    });
    return res.json({ ok: true, anexado: attachments.length > 0, para: dest.para, copia: dest.copia });
  } catch (err) {
    console.error("Erro em /api/financeiro/encaminhar-email:", err.message);
    return res.json({ ok: false, message: "Não foi possível enviar o e-mail agora." });
  }
});

// ---------------------------------------------------------------------
// ENTRADA AUTOMÁTICA EM "VIAGENS E DESPESAS" (2026-10-20) — remove o segundo
// login. POST /api/viagens/sessao-portal { email }:
//   1. exige a chave X-Portal-Key (a mesma de todo o portal);
//   2. confere que o e-mail é de um usuário ATIVO da coleção "users" do portal;
//   3. localiza (ou cria, na 1ª entrada) o perfil em "viagens_perfis":
//        admin do portal → administrador; demais → consultor (gestor = um
//        administrador ativo). Perfis que já existem (inclusive financeiro e
//        gestor escolhido) NUNCA são alterados aqui;
//   4. devolve um custom token do Firebase Auth. O navegador troca esse token
//      por um ID token normal — e tudo o que o módulo já faz (verificação do
//      token, perfil lido do banco, viagem por viagem) continua igual.
// ATENÇÃO (decisão da Iasmin, 2026-10-20): a identidade vem do login do
// PORTAL, que é feito no navegador. Quem conhecer a chave do portal e o
// e-mail de um usuário ativo consegue entrar como ele neste módulo.
// ---------------------------------------------------------------------
const VG_PERFIS_COL = "viagens_perfis";
let vgAuthAdmin = null;
function vgAuthFirebaseAdmin() {
  if (vgAuthAdmin) return vgAuthAdmin;
  const { initializeApp, getApps, cert, applicationDefault } = require("firebase-admin/app");
  const { getAuth } = require("firebase-admin/auth");
  const pid = process.env.FIREBASE_PROJECT_ID || (credentials && credentials.project_id);
  const fbApp = getApps().length
    ? getApps()[0]
    : initializeApp({ credential: credentials ? cert(credentials) : applicationDefault(), projectId: pid });
  vgAuthAdmin = getAuth(fbApp);
  return vgAuthAdmin;
}
async function vgGarantirPerfil(authAdmin, usuarioPortal, perfisAtuais) {
  const mail = String(usuarioPortal.email || "").trim().toLowerCase();
  const existente = perfisAtuais.find((p) => String(p.email || "").trim().toLowerCase() === mail);
  if (existente) return existente;
  const ehAdmin = String(usuarioPortal.perfil || "").toLowerCase() === "admin";
  let rec;
  try { rec = await authAdmin.getUserByEmail(mail); } catch (e) { rec = null; }
  if (!rec) rec = await authAdmin.createUser({ email: mail, displayName: usuarioPortal.nome || mail, disabled: false });
  const agora = new Date().toISOString();
  const doc = {
    uid: rec.uid,
    nome: usuarioPortal.nome || mail,
    email: mail,
    perfil: ehAdmin ? "administrador" : "consultor",
    gestorId: null,
    gestorNome: "",
    ativo: true,
    criadoEm: agora,
    criadoPor: "portal",
    atualizadoEm: agora,
  };
  if (!ehAdmin) {
    const gestor = perfisAtuais.find((p) => p.perfil === "administrador" && p.ativo !== false);
    if (gestor) { doc.gestorId = gestor.uid; doc.gestorNome = gestor.nome || ""; }
  }
  await firestore.collection(VG_PERFIS_COL).doc(rec.uid).set(doc);
  perfisAtuais.push(doc);
  return doc;
}
// Aquece o firebase-admin na subida da instância (a 1ª entrada no módulo não paga a inicialização).
try { vgAuthFirebaseAdmin(); } catch (_) {}
app.post("/api/viagens/sessao-portal", exigirChaveDeAcesso, async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    // Identidade = a da SESSÃO assinada do portal (o e-mail do corpo da requisição é ignorado).
    const mail = normEmail(req.portalUser && req.portalUser.email);
    if (!mail || mail.length > 160 || !mail.includes("@")) {
      return res.status(400).json({ erro: "Sessão sem e-mail de usuário." });
    }
    // OTIMIZAÇÃO (2026-11): caminho rápido por leitura direta — o documento do
    // usuário tem como id o próprio e-mail "slugificado" (slugUserId) e o perfil
    // do módulo é achado por consulta de igualdade; antes cada entrada lia as
    // coleções "users" e "viagens_perfis" INTEIRAS. Se qualquer uma não for
    // achada assim, cai no caminho completo de sempre (mesma regra de antes).
    let usuarios = null;
    const carregarUsuarios = async () => {
      if (!usuarios) usuarios = (await firestore.collection("users").get()).docs.map((d) => d.data());
      return usuarios;
    };
    let up = null;
    try {
      const rapido = await firestore.collection("users").doc(slugUserId(mail)).get();
      if (rapido.exists && String(rapido.data().email || "").trim().toLowerCase() === mail) up = rapido.data();
    } catch (_) {}
    if (!up) up = (await carregarUsuarios()).find((u) => String(u.email || "").trim().toLowerCase() === mail);
    if (!up || up.status === "inativo") {
      return res.status(403).json({ erro: "Seu acesso ao portal não está ativo. Fale com o administrador." });
    }
    const authAdmin = vgAuthFirebaseAdmin();
    let perfil = null;
    try {
      const q = await firestore.collection(VG_PERFIS_COL).where("email", "==", mail).limit(1).get();
      if (!q.empty) { const d = q.docs[0]; perfil = { ...d.data(), uid: d.data().uid || d.id }; }
    } catch (_) {}
    if (!perfil) {
      const perfSnap = await firestore.collection(VG_PERFIS_COL).get();
      const perfis = perfSnap.docs.map((d) => ({ ...d.data(), uid: d.data().uid || d.id }));
      perfil = perfis.find((p) => String(p.email || "").trim().toLowerCase() === mail);
      if (!perfil) {
        // Consultor entrando sem nenhum administrador cadastrado no módulo:
        // cadastra antes um administrador ativo do portal para ser o gestor.
        const ehAdmin = String(up.perfil || "").toLowerCase() === "admin";
        if (!ehAdmin && !perfis.some((p) => p.perfil === "administrador" && p.ativo !== false)) {
          const adm = (await carregarUsuarios()).find((u) => String(u.perfil || "").toLowerCase() === "admin" && u.status !== "inativo" && u.email);
          if (adm) await vgGarantirPerfil(authAdmin, adm, perfis);
        }
        perfil = await vgGarantirPerfil(authAdmin, up, perfis);
      }
    }
    if (perfil.ativo === false) {
      return res.status(403).json({ erro: "Seu acesso ao módulo não está liberado. Fale com o administrador." });
    }
    const token = await authAdmin.createCustomToken(perfil.uid);
    res.json({ token });
  } catch (err) {
    console.error("[viagens] sessao-portal:", err && err.message);
    res.status(500).json({ erro: "Não foi possível entrar no módulo agora. Tente novamente." });
  }
});

// ---------------------------------------------------------------------
// MÓDULO "VIAGENS E DESPESAS" (2026-10) — rotas em /api/viagens/*.
// Autenticação própria: ID token do Firebase Auth verificado AQUI (header
// Authorization: Bearer). NÃO usa a chave X-Portal-Key nem o proxy genérico
// /api/db (as coleções viagens_* não estão — e não devem entrar — na
// lista COLECOES_PERMITIDAS). Ver viagens.js e LEIA-ME-VIAGENS.md.
// ---------------------------------------------------------------------
try {
  require("./viagens").montar(app, { express, firestore, credentials, env: process.env });
} catch (err) {
  // Se o módulo não puder iniciar (ex.: dependência faltando), o restante do portal continua no ar.
  console.error("[viagens] módulo NÃO iniciado:", err && err.message);
}

// ---------------------------------------------------------------------
// INFORMAÇÕES LOGÍSTICAS (2026-10-19) — GET /logistica/diesel: preço médio do
// diesel S-10 e variação semanal, lidos automaticamente das planilhas oficiais
// da ANP (ver logistica.js). Protegida pela mesma chave X-Portal-Key das demais
// rotas. Se o módulo não iniciar, o restante do portal continua no ar.
// ---------------------------------------------------------------------
try {
  require("./logistica").montar(app, { exigir: exigirChaveDeAcesso });
} catch (err) {
  console.error("[logistica] módulo NÃO iniciado:", err && err.message);
}

// Erros de corpo (ex.: arquivo grande demais) sempre em JSON, sem detalhes internos.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err && err.type === "entity.too.large") return res.status(413).json({ erro: "Conteúdo muito grande." });
  if (err && err.code === "LIMIT_FILE_SIZE") return res.status(413).json({ erro: "Arquivo grande demais.", detalhe: "limite de 30 MB por arquivo" });
  if (err && err.type === "entity.parse.failed") return res.status(400).json({ erro: "Requisição inválida." });
  console.error("Erro não tratado:", err && err.message);
  res.status(500).json({ erro: "Erro interno." });
});

app.get("/", (req, res) => {
  res.send("Proxy de documentos do Portal Grupoprima está funcionando.");
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

/**
 * ---------------------------------------------------------------------
 * NOTAS DE DEPLOY (ler antes de colocar em produção)
 * ---------------------------------------------------------------------
 * Variáveis de ambiente (mesmas de antes + o que mudou):
 *
 *   GOOGLE_SERVICE_ACCOUNT_KEY_B64  (sem mudança) conteúdo do JSON da
 *                                   conta de serviço, em base64.
 *   BACKEND_ACCESS_KEY              (sem mudança) senha longa enviada no
 *                                   header "X-Portal-Key".
 *   ALLOWED_ORIGIN                  AGORA aceita várias origens separadas
 *                                   por vírgula, ex.:
 *       https://iasmincruz555.github.io,https://claude.site
 *   DRIVE_FOLDER_ID                 (sem mudança).
 *   ANTHROPIC_API_KEY               NOVA (2026-09-22) — chave da API da
 *                                   Anthropic, só para o endpoint
 *                                   /api/client-analysis. Guarde no Google
 *                                   Secret Manager e injete como variável
 *                                   de ambiente do Cloud Run (nunca no
 *                                   código, nunca em nenhum arquivo servido
 *                                   ao navegador). Sem ela definida, o
 *                                   endpoint responde 500 com uma mensagem
 *                                   clara em vez de tentar chamar a API.
 *   CLAUDE_ANALYSIS_MODEL           NOVA (2026-09-22) — id do modelo Claude
 *                                   a usar no /api/client-analysis (ex.: um
 *                                   modelo atual da família Claude na API
 *                                   da Anthropic). Proposital deixar sem
 *                                   valor padrão no código: sem essa
 *                                   variável, o endpoint responde 500 com
 *                                   mensagem clara em vez de adivinhar um
 *                                   modelo.
 *   GOOGLE_OAUTH_CLIENT_ID          NOVA (2026-09-29) — Client ID OAuth tipo
 *                                   "Web application", usado por
 *                                   /api/auth/google para conferir a
 *                                   assinatura do token que o botão "Entrar
 *                                   com Google" manda. Sem ela, a rota
 *                                   responde ok:false (login com Google fica
 *                                   desativado, mas o login por senha
 *                                   continua normal). O MESMO valor também
 *                                   precisa ser colado em index.html, na
 *                                   constante GOOGLE_OAUTH_CLIENT_ID.
 *   HOMOLOGACAO_CRED_KEY            NOVA (2026-10-20) — segredo aleatório longo
 *                                   (32+ caracteres) que criptografa login e
 *                                   senha da "Plataforma do cliente" das
 *                                   homologações (AES-256-GCM, coleção
 *                                   própria "homologacao_credenciais"). Guarde
 *                                   no Secret Manager e injete como variável do
 *                                   Cloud Run. Sem ela, a senha continua só em
 *                                   memória (comportamento antigo) e o
 *                                   formulário avisa isso. NÃO troque depois de
 *                                   em uso: credenciais já gravadas deixam de
 *                                   ser legíveis.
 *   GMAIL_NOTIFICATIONS_USER        NOVA (2026-09-29) — endereço Gmail/
 *                                   Workspace que envia as notificações de
 *                                   Homologação (ex.: notificacoes@
 *                                   grupoprimalog.com.br).
 *   GMAIL_NOTIFICATIONS_APP_PASSWORD NOVA (2026-09-29) — senha de app (16
 *                                   caracteres, gerada em
 *                                   myaccount.google.com/apppasswords) da
 *                                   conta acima — exige verificação em 2
 *                                   etapas ativada nela. Sem as duas
 *                                   variáveis, /api/homologacao/notify
 *                                   responde ok:false (nunca quebra o
 *                                   fluxo de criar/atualizar homologação).
 *   (sem variável nova) ANEXOS NO E-MAIL DE CONCLUSÃO (2026-10-01) — os
 *                                   arquivos de resposta anexados em
 *                                   HomologacaoDetailView agora vão em
 *                                   anexo no e-mail de "Concluída", 100%
 *                                   reaproveitando a conta Gmail acima —
 *                                   nenhuma variável de ambiente nova.
 *
 * Passos que só você consegue fazer (fora deste código):
 *
 *  1) Firestore: no mesmo projeto Google Cloud da conta de serviço,
 *     ativar a API do Firestore e criar um banco em modo NATIVO (se ainda
 *     não existir um). Console: Firestore → Criar banco de dados → modo
 *     Nativo → mesma região do Cloud Run (southamerica-east1).
 *
 *  2) Dar à conta de serviço permissão para usar o Firestore — papel
 *     "Cloud Datastore User" (roles/datastore.user) no projeto.
 *
 *  3) Trocar a permissão da conta de serviço na pasta oficial do Drive de
 *     Leitor para EDITOR (Google Drive → botão direito na pasta "PORTAL
 *     DOCUMENTAL | GRUPOPRIMA" → Compartilhar → localizar o e-mail da
 *     conta de serviço → trocar de "Leitor" para "Editor"). Sem isso, as
 *     rotas de leitura continuam funcionando, mas todo upload falha.
 *
 *  4) Anthropic (2026-09-22): criar/obter uma chave de API em
 *     https://console.anthropic.com (conta separada da Iasmin, com
 *     faturamento próprio — não é a mesma conta do claude.ai). Guardar essa
 *     chave no Secret Manager e associá-la ao Cloud Run como a variável
 *     ANTHROPIC_API_KEY (Console do Cloud Run → editar serviço → Variáveis
 *     e secrets → Referenciar um secret). Definir também
 *     CLAUDE_ANALYSIS_MODEL com o id do modelo desejado.
 *
 *  5) Login com Google (2026-09-29): no Console do Google Cloud (mesmo
 *     projeto da conta de serviço) → "APIs e serviços" → "Credenciais" →
 *     "Criar credenciais" → "ID do cliente OAuth" → tipo "Aplicativo da
 *     Web". Em "Origens JavaScript autorizadas", adicionar o domínio real
 *     do portal publicado (ex.: https://iasmincruz555.github.io). Não
 *     precisa de "URI de redirecionamento". Copiar o Client ID gerado
 *     (termina em ".apps.googleusercontent.com") e usá-lo em DOIS lugares:
 *     como a variável de ambiente GOOGLE_OAUTH_CLIENT_ID aqui no Cloud Run,
 *     E colado na constante GOOGLE_OAUTH_CLIENT_ID dentro de index.html
 *     antes de publicar. Se a tela pedir para configurar a "tela de
 *     consentimento OAuth" primeiro, tipo "Interno" é o mais simples
 *     (exige Google Workspace) — "Externo" também funciona, só exige
 *     publicar o app ou adicionar cada e-mail de teste manualmente.
 *
 *  6) Notificações por e-mail (2026-09-29): escolher uma conta Gmail ou
 *     Workspace para ser a remetente (pode ser a própria conta da Iasmin
 *     ou um endereço dedicado, ex.: notificacoes@grupoprimalog.com.br).
 *     Ativar a verificação em 2 etapas nessa conta (obrigatório para gerar
 *     senha de app) em myaccount.google.com/security, depois gerar uma
 *     "Senha de app" em myaccount.google.com/apppasswords. Definir
 *     GMAIL_NOTIFICATIONS_USER (o endereço) e
 *     GMAIL_NOTIFICATIONS_APP_PASSWORD (a senha de app de 16 caracteres,
 *     sem espaços) como variáveis de ambiente do Cloud Run.
 *
 * Este backend agora tem escopo de ESCRITA no Drive, escreve no Firestore,
 * chama a API da Anthropic e (desde 2026-09-29) verifica login do Google e
 * envia e-mail — todos exigem os passos manuais acima antes de funcionar de
 * verdade; sem eles, as rotas novas respondem com um erro claro (nunca
 * fingem ter verificado um login ou enviado um e-mail que não aconteceu).
 * ---------------------------------------------------------------------
 */
