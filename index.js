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
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Portal-Key");
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

function exigirChaveDeAcesso(req, res, next) {
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
    const arquivos = await listarArquivosRecursivo(DRIVE_FOLDER_ID);
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
    res.setHeader("Content-Disposition", `inline; filename="${meta.data.name}"`);

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
// Só estas quatro coleções, nunca uma coleção arbitrária vinda de fora.
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
      const docs = snap.docs.map((d) => ({ id: d.id, data: d.data() }));
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
      await firestore
        .collection(req.params.collection)
        .doc(req.params.id)
        .set(req.body || {});
      res.json({ ok: true, id: req.params.id });
    } catch (err) {
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
      const ref = await firestore
        .collection(req.params.collection)
        .add(req.body || {});
      res.json({ ok: true, id: ref.id });
    } catch (err) {
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
      await firestore
        .collection(req.params.collection)
        .doc(req.params.id)
        .delete();
      res.json({ ok: true });
    } catch (err) {
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
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB
});

const NOME_SUBPASTA_UPLOADS = "Enviados pelo Portal";
let idSubpastaUploadsCache = null;

/** encontrarOuCriarSubpastaUploads: garante que exista, dentro da pasta
 *  oficial, uma subpasta fixa para receber arquivos enviados por este
 *  backend (upload manual pelo site, ou documento enviado pela Iasmin no
 *  chat com o Claude e classificado por ele) — nunca mistura esses
 *  arquivos soltos na raiz nem dentro das subpastas de organização manual
 *  já existentes (ex.: "ALVARÁS", "CNPJ"). Cria a subpasta uma única vez;
 *  nas próximas chamadas reaproveita o id (em memória do processo). */
async function encontrarOuCriarSubpastaUploads() {
  if (idSubpastaUploadsCache) return idSubpastaUploadsCache;
  const busca = await drive.files.list({
    q: `'${DRIVE_FOLDER_ID}' in parents and trashed = false and mimeType = '${FOLDER_MIME_TYPE}' and name = '${NOME_SUBPASTA_UPLOADS.replace(/'/g, "\\'")}'`,
    fields: "files(id, name)",
    pageSize: 1,
    supportsAllDrives: true,
    includeItemsFromAllDrives: true,
    corpora: "drive",
    driveId: DRIVE_ID,
  });
  const existente = (busca.data.files || [])[0];
  if (existente) {
    idSubpastaUploadsCache = existente.id;
    return existente.id;
  }
  const criada = await drive.files.create({
    requestBody: {
      name: NOME_SUBPASTA_UPLOADS,
      mimeType: FOLDER_MIME_TYPE,
      parents: [DRIVE_FOLDER_ID],
    },
    fields: "id",
    supportsAllDrives: true,
  });
  idSubpastaUploadsCache = criada.data.id;
  return criada.data.id;
}

/**
 * POST /api/documents/upload-file
 * multipart/form-data:
 *   - arquivo: o binário real (obrigatório)
 *
 * Só sobe o binário para a pasta oficial do Drive (subpasta "Enviados pelo
 * Portal") e devolve os metadados reais do arquivo criado. Não decide nem
 * grava classificação nenhuma — isso é responsabilidade de quem chamou,
 * usando depois PUT /api/db/documentos_confirmados/:id com o registro
 * completo (mesmo formato que o portal já monta em buildConfirmedDocRecord).
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
      const pastaDestinoId = await encontrarOuCriarSubpastaUploads();

      const criado = await drive.files.create({
        requestBody: {
          name: req.file.originalname,
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
      res.status(500).json({ erro: "Não foi possível enviar o arquivo agora." });
    }
  }
);

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

const ANALISE_SYSTEM_PROMPT = `Você é um assistente que ajuda a equipe da Grupoprima Logística a revisar documentos recebidos de clientes (contratos, anexos comerciais, manuais de fornecedor, planilhas de tarifa) ANTES de aceitar, assinar ou operar de acordo com essa documentação.

Sua única tarefa é LER e RESUMIR o que foi enviado — você nunca decide se um documento deve ser aceito, nunca classifica um estabelecimento da Grupoprima, nunca recomenda aceitar/assinar/recusar nada, e nunca toma nenhuma ação fora de preencher o resultado pedido.

Regras obrigatórias, sem exceção:
- Baseie cada afirmação exclusivamente no texto fornecido a seguir — nunca complete com conhecimento geral sobre contratos de transporte/logística que não esteja no documento.
- Nunca invente datas, valores, CNPJs, nomes de cláusula ou número de cláusula que não apareçam literalmente no texto.
- Quando um ponto não puder ser confirmado com confiança razoável, use "confianca" baixa (0.5 ou menos) nesse ponto de atenção e registre isso também em "recomendacoesDeConferencia" — nunca apresente como certeza.
- Preencha "referencia" só quando for possível apontar de fato a cláusula/trecho/página de origem no texto recebido; caso contrário deixe uma string vazia — nunca invente uma referência.
- Alguns documentos podem ter sido cortados por limite de tamanho (isso aparece marcado no próprio texto abaixo, quando acontecer) — trate o conteúdo cortado como incompleto, nunca como ausente ou suspeito por si só.
- Nunca recomende aceitar, assinar ou recusar o documento — descreva só obrigações, riscos e pontos de atenção; a decisão é sempre de uma pessoa responsável na Grupoprima.
- Preencha o resultado só com o formulário fornecido (chamando a ferramenta "registrar_analise") — nunca responda em texto livre.`;

async function chamarAnthropicParaAnalise({ clienteNome, documentos }) {
  const partesDocumentos = documentos
    .map((d, i) => {
      const aviso = d.cortado
        ? "\n[AVISO: este documento foi cortado por limite de tamanho — o texto abaixo é só o início dele.]"
        : "";
      return `--- Documento ${i + 1}: ${d.nome} ---${aviso}\n${d.texto}`;
    })
    .join("\n\n");
  const userContent = `Cliente: ${clienteNome}\n\nDocumentos enviados (texto já extraído):\n\n${partesDocumentos}\n\nAnalise os documentos acima e preencha o formulário chamando a ferramenta "registrar_analise", seguindo à risca as regras do system prompt.`;

  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: CLAUDE_ANALYSIS_MODEL,
      max_tokens: 8192,
      system: ANALISE_SYSTEM_PROMPT,
      messages: [{ role: "user", content: userContent }],
      tools: [
        {
          name: "registrar_analise",
          description: "Registra o resultado estruturado da análise documental do cliente.",
          input_schema: ANALISE_TOOL_INPUT_SCHEMA,
        },
      ],
      tool_choice: { type: "tool", name: "registrar_analise" },
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
    (b) => b.type === "tool_use" && b.name === "registrar_analise"
  );
  if (!blocoFerramenta || !blocoFerramenta.input) {
    throw new Error("A API da Anthropic não devolveu o resultado estruturado esperado.");
  }
  return blocoFerramenta.input;
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

/**
 * POST /api/client-analysis
 * body: { id, clienteNome, documentos: [{ nome, textoExtraido }] }
 *
 * Chama a API da Anthropic para ler e resumir os documentos do cliente e
 * devolve { ok: true, resultado }, no mesmo formato que o mock do
 * frontend (mockClientAnalysis) já usava — quem grava o resultado no
 * Firestore continua sendo o próprio portal (persist(), em
 * ClientAnalysisView), como já fazia com o mock. Nunca inventa um
 * resultado quando a API da Anthropic falha ou devolve algo fora do
 * formato esperado — devolve erro claro, e o portal marca o item como
 * "erro" (nunca finge sucesso).
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
  const { clienteNome, documentos } = req.body || {};
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
    const resultadoBruto = await chamarAnthropicParaAnalise({ clienteNome, documentos: documentosTruncados });
    const erroValidacao = validarResultadoAnalise(resultadoBruto);
    if (erroValidacao) {
      console.error("Resultado da Anthropic fora do formato esperado:", erroValidacao);
      return res
        .status(502)
        .json({ erro: `A IA devolveu um resultado em formato inesperado (${erroValidacao}) — tente novamente.` });
    }
    res.json({ ok: true, resultado: { ...resultadoBruto, mock: false, geradoEm: new Date().toISOString() } });
  } catch (err) {
    console.error("Erro ao chamar a API da Anthropic:", err.message);
    res
      .status(502)
      .json({ erro: `Não foi possível concluir a análise por IA agora (${err.message}). Tente novamente em alguns instantes.` });
  }
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
 * Este backend agora tem escopo de ESCRITA no Drive, escreve no Firestore
 * e (desde 2026-09-22) chama a API da Anthropic — todos exigem os passos
 * manuais acima antes de funcionar de verdade; sem eles, as rotas novas
 * respondem com erro 500 claro (nunca fingem ter salvo ou gerado algo que
 * não foi salvo/gerado de verdade).
 * ---------------------------------------------------------------------
 */
