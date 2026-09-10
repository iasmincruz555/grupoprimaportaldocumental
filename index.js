/**
 * Backend que conecta o Portal Grupoprima ao Google Drive.
 *
 * Rotas:
 *  GET /files
 *      Lista os arquivos da pasta configurada (metadados apenas —
 *      não baixa o conteúdo, só o essencial pra montar a listagem
 *      no portal: id, nome, mimeType, tamanho, data de modificação).
 *
 *  GET /api/documents/:id/file
 *      Devolve o arquivo original (binário) de um arquivo específico,
 *      IDENTIFICADO PELO driveFileId — é a rota que o portal já chama
 *      hoje em fetchDocumentFile().
 *
 * Segurança:
 *  - Ambas as rotas só servem arquivos que estão DENTRO da pasta
 *    configurada em DRIVE_FOLDER_ID (verificado via drive.files.get
 *    checando o campo "parents"). Isso evita que alguém troque o
 *    fileId na URL e acesse outro arquivo qualquer que a conta de
 *    serviço enxergue no Drive.
 *  - Este serviço é somente leitura (scope drive.readonly) — não
 *    envia nada para o Drive, só lê.
 *  - NOVO: chave de acesso (BACKEND_ACCESS_KEY) + CORS restrito
 *    (ALLOWED_ORIGIN). Antes, as duas rotas ficavam abertas para
 *    QUALQUER pessoa na internet que descobrisse a URL — mesmo sem
 *    saber a senha do portal, dava para listar e baixar todos os
 *    documentos reais. Ver notas de deploy no final do arquivo.
 */

const express = require("express");
const { google } = require("googleapis");

const app = express();

// ---------------------------------------------------------------------
// CORS: por padrão, restrito à origem configurada em ALLOWED_ORIGIN.
// Sem essa variável definida, cai em "*" (aberto) só para não travar
// testes locais — isso é inseguro e deve ser corrigido antes de ir
// para produção (ver notas no final do arquivo).
// ---------------------------------------------------------------------
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
if (ALLOWED_ORIGIN === "*") {
  console.warn(
    "[aviso] ALLOWED_ORIGIN não definida — CORS está aberto para qualquer origem. " +
      "Defina ALLOWED_ORIGIN com o domínio real do portal antes de ir para produção."
  );
}

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Portal-Key");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ---------------------------------------------------------------------
// Chave de acesso simples (defesa mínima): sem ela, qualquer pessoa que
// descubra a URL do backend consegue listar/baixar os documentos reais.
// Isso NÃO é autenticação de usuário (não sabe quem é Iasmin ou não) —
// é só um segredo compartilhado entre o backend e o portal, para parar
// acesso casual/varreduras automáticas. Continua visível para quem abrir
// o código-fonte do portal, então não é segurança forte — é a barreira
// mínima enquanto não há login real no backend.
// ---------------------------------------------------------------------
const BACKEND_ACCESS_KEY = process.env.BACKEND_ACCESS_KEY || null;
if (!BACKEND_ACCESS_KEY) {
  console.warn(
    "[aviso] BACKEND_ACCESS_KEY não definida — as rotas estão SEM nenhuma chave de acesso. " +
      "Qualquer pessoa com a URL consegue listar e baixar os documentos. " +
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
// Pegue esse ID na URL da pasta: https://drive.google.com/drive/folders/ESTE_TRECHO_AQUI
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

const auth = new google.auth.GoogleAuth({
  credentials,
  scopes: ["https://www.googleapis.com/auth/drive.readonly"],
});

const drive = google.drive({ version: "v3", auth });

/** Confere se o arquivo pertence à pasta autorizada antes de servir. */
async function pertenceAPastaAutorizada(fileId) {
  const meta = await drive.files.get({
    fileId,
    fields: "id, parents",
  });
  return (meta.data.parents || []).includes(DRIVE_FOLDER_ID);
}

/**
 * GET /files
 * Lista os documentos da pasta (só metadados — sem baixar o binário).
 */
app.get("/files", exigirChaveDeAcesso, async (req, res) => {
  try {
    const result = await drive.files.list({
      q: `'${DRIVE_FOLDER_ID}' in parents and trashed = false`,
      fields:
        "files(id, name, mimeType, size, modifiedTime, md5Checksum)",
      pageSize: 200,
      orderBy: "name",
    });

    const arquivos = (result.data.files || []).map((f) => ({
      driveFileId: f.id,
      nomeOriginal: f.name,
      mimeType: f.mimeType,
      tamanho: f.size ? Number(f.size) : null,
      modificadoEm: f.modifiedTime,
    }));

    res.json({ pasta: DRIVE_FOLDER_ID, total: arquivos.length, arquivos });
  } catch (err) {
    console.error("Erro ao listar arquivos da pasta:", err.message);
    res.status(500).json({ erro: "Não foi possível listar os documentos da pasta." });
  }
});

/**
 * GET /api/documents/:id/file
 * Devolve o arquivo original. ":id" é o driveFileId.
 */
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
 * Variáveis de ambiente a configurar no serviço de hospedagem (nunca no
 * código nem em nenhum arquivo commitado):
 *
 *   GOOGLE_SERVICE_ACCOUNT_KEY_B64  conteúdo do JSON da conta de serviço,
 *                                   em base64 (uma linha só). No Windows
 *                                   (PowerShell):
 *       [Convert]::ToBase64String([IO.File]::ReadAllBytes("caminho\para\o-arquivo.json"))
 *   BACKEND_ACCESS_KEY              uma senha longa qualquer, só sua —
 *                                   é o que o portal vai enviar no header
 *                                   "X-Portal-Key" em toda chamada.
 *   ALLOWED_ORIGIN                  a origem exata de onde o portal é
 *                                   servido (ex.: https://claude.site ou
 *                                   o domínio que aparecer na barra de
 *                                   endereço quando você abrir o link
 *                                   público do Artifact).
 *   DRIVE_FOLDER_ID                 só precisa definir se um dia mudar
 *                                   de pasta oficial — o padrão já é o
 *                                   ID correto da pasta atual.
 *
 * Passo que só você consegue fazer (fora deste código): compartilhar a
 * pasta "PORTAL DOCUMENTAL | GRUPOPRIMA" no Google Drive com o e-mail da
 * conta de serviço (algo como
 * grupoprima-portal-iasmin-conta@grupoprima-portal-iasmin.iam.gserviceaccount.com),
 * como Leitor. Sem isso, mesmo com tudo certo aqui, toda chamada volta
 * "arquivo não encontrado" — a conta de serviço não enxerga a pasta.
 *
 * Este backend é SÓ LEITURA hoje (Ver/Baixar). Ele não resolve, sozinho,
 * o pedido de deixar qualquer funcionário ENVIAR documento novo pelo
 * "Adicionar documentação" — isso exigiria uma rota de upload nova, com
 * escopo de escrita no Drive e a pasta compartilhada como Editor (não só
 * Leitor) com a conta de serviço, além de reforçar a autenticação antes
 * de liberar escrita para qualquer chamada.
 * ---------------------------------------------------------------------
 */
