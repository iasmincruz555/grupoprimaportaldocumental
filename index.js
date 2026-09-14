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
app.use(express.json({ limit: "2mb" }));
 
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
    });
 
    const arquivo = await drive.files.get(
      { fileId, alt: "media" },
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
 * Este backend agora tem escopo de ESCRITA no Drive e escreve no
 * Firestore — ambos exigem os passos manuais acima antes de funcionar de
 * verdade; sem eles, as rotas novas respondem com erro 500 claro (nunca
 * fingem ter salvo algo que não foi salvo).
 * ---------------------------------------------------------------------
 */
 
