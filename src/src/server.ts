
import express from "express";
import cors from "cors";
import helmet from "helmet";
import { createServer } from "node:http";
import { randomBytes, randomInt } from "node:crypto";
import { WebSocketServer, WebSocket } from "ws";

const app = express();
const server = createServer(app);

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "16kb" }));

const PORT = Number(process.env.PORT) || 3000;
const SESSION_DURATION = 15 * 60 * 1000;

type Session = {
  code: string;
  adminToken: string;
  guestToken?: string;
  approved: boolean;
  expiresAt: number;
  clients: Set<WebSocket>;
};

const sessions = new Map<string, Session>();

function createToken(): string {
  return randomBytes(32).toString("hex");
}

function findSession(code: string): Session | undefined {
  const session = sessions.get(code);

  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(code);
    return undefined;
  }

  return session;
}

function send(socket: WebSocket, data: unknown): void {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(data));
  }
}

// Verifica che il server sia attivo
app.get("/health", (_req, res) => {
  res.json({
    status: "online",
    service: "Remote Simple"
  });
});

// Crea una nuova sessione di assistenza
app.post("/api/sessions", (_req, res) => {
  let code = "";

  do {
    code = String(randomInt(100000, 1000000));
  } while (sessions.has(code));

  const session: Session = {
    code,
    adminToken: createToken(),
    approved: false,
    expiresAt: Date.now() + SESSION_DURATION,
    clients: new Set()
  };

  sessions.set(code, session);

  res.status(201).json({
    code: session.code,
    adminToken: session.adminToken,
    expiresAt: session.expiresAt
  });
});

// Il destinatario richiede di entrare nella sessione
app.post("/api/sessions/:code/join", (req, res) => {
  const session = findSession(req.params.code);

  if (!session) {
    res.status(404).json({ error: "Sessione non trovata o scaduta" });
    return;
  }

  if (session.guestToken) {
    res.status(409).json({ error: "Sessione già occupata" });
    return;
  }

  session.guestToken = createToken();

  res.json({
    message: "Richiesta di assistenza creata",
    guestToken: session.guestToken,
    consentRequired: true
  });
});

// Registra il consenso esplicito del destinatario
app.post("/api/sessions/:code/consent", (req, res) => {
  const session = findSession(req.params.code);
  const { guestToken, consent } = req.body;

  if (!session || !session.guestToken) {
    res.status(404).json({ error: "Sessione non trovata" });
    return;
  }

  if (guestToken !== session.guestToken) {
    res.status(403).json({ error: "Autorizzazione non valida" });
    return;
  }

  if (consent !== true) {
    res.status(403).json({ error: "Consenso non concesso" });
    return;
  }

  session.approved = true;

  for (const client of session.clients) {
    send(client, { type: "consent-approved" });
  }

  res.json({ approved: true });
});

// Server WebSocket per la segnalazione tra dispositivi
const wss = new WebSocketServer({
  server,
  path: "/ws"
});

wss.on("connection", (socket, request) => {
  const url = new URL(
    request.url ?? "/",
    `http://${request.headers.host ?? "localhost"}`
  );

  const code = url.searchParams.get("code");
  const token = url.searchParams.get("token");

  if (!code || !token) {
    socket.close(1008, "Credenziali mancanti");
    return;
  }

  const session = findSession(code);

  if (!session) {
    socket.close(1008, "Sessione non valida");
    return;
  }

  const isAdmin = token === session.adminToken;
  const isGuest = token === session.guestToken;

  if (!isAdmin && !isGuest) {
    socket.close(1008, "Accesso non autorizzato");
    return;
  }

  if (isGuest && !session.approved) {
    socket.close(1008, "Consenso non ancora concesso");
    return;
  }

  session.clients.add(socket);

  send(socket, {
    type: "connected",
    approved: session.approved
  });

  socket.on("message", (rawData) => {
    if (!session.approved || !session.clients.has(socket)) {
      return;
    }

    if (rawData.toString().length > 16000) {
      socket.close(1009, "Messaggio troppo grande");
      return;
    }

    try {
      const message = JSON.parse(rawData.toString());

      const allowedTypes = ["offer", "answer", "candidate"];

      if (!allowedTypes.includes(message.type)) {
        return;
      }

      for (const client of session.clients) {
        if (client !== socket) {
          send(client, message);
        }
      }
    } catch {
      send(socket, { error: "Messaggio non valido" });
    }
  });

  socket.on("close", () => {
    session.clients.delete(socket);
  });
});

// Elimina periodicamente le sessioni scadute
setInterval(() => {
  for (const [code, session] of sessions) {
    if (session.expiresAt < Date.now()) {
      for (const client of session.clients) {
        client.close(1000, "Sessione scaduta");
      }

      sessions.delete(code);
    }
  }
}, 60 * 1000);

server.listen(PORT, () => {
  console.log(`Remote Simple server attivo sulla porta ${PORT}`);
});
