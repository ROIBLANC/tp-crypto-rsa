import { useState, useMemo, useRef } from "react";
import forge from "node-forge";
import "./App.css";

/* ------------------------------------------------------------------ */
/*  Configuration                                                      */
/* ------------------------------------------------------------------ */
const AUTHORS = " YEO IVAN & YOUL FULGENCE"; // ← à remplacer par vos noms
const KEY_BITS = 2048;
const CHUNK_SIZE = 190; // marge de sécurité sous la limite OAEP (214 octets)

/* ------------------------------------------------------------------ */
/*  Utilitaires                                                        */
/* ------------------------------------------------------------------ */
const formatSize = (bytes) => {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / 1024 / 1024).toFixed(2)} Mo`;
};

// Empreinte SHA-256 de la clé : permet de vérifier avec le binôme (par téléphone,
// par exemple) que la clé reçue n'a pas été modifiée en route.
const fingerprintOf = (pem) => {
  const md = forge.md.sha256.create();
  md.update(pem.replace(/\s+/g, ""));
  return md
    .digest()
    .toHex()
    .match(/.{2}/g)
    .slice(0, 12)
    .join(":")
    .toUpperCase();
};

const readFile = (file, mode = "binary") =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    if (mode === "text") reader.readAsText(file);
    else reader.readAsBinaryString(file);
  });

// Laisse le navigateur respirer pour mettre à jour la barre de progression
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

const downloadBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

const inspectPem = (pem, type) => {
  if (!pem.trim()) return { status: "empty" };
  try {
    const key =
      type === "public"
        ? forge.pki.publicKeyFromPem(pem.trim())
        : forge.pki.privateKeyFromPem(pem.trim());
    return {
      status: "valid",
      bits: key.n.bitLength(),
      fingerprint: fingerprintOf(pem),
    };
  } catch {
    return { status: "invalid" };
  }
};

/* ------------------------------------------------------------------ */
/*  Petits composants                                                  */
/* ------------------------------------------------------------------ */
function DropZone({ file, onFile, accept, label }) {
  const inputRef = useRef(null);
  const [over, setOver] = useState(false);

  const open = () => inputRef.current?.click();

  return (
    <div
      className={`dropzone ${over ? "over" : ""} ${file ? "filled" : ""}`}
      role="button"
      tabIndex={0}
      onClick={open}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          open();
        }
      }}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setOver(false);
        const f = e.dataTransfer.files?.[0];
        if (f) onFile(f);
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        hidden
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFile(f);
          e.target.value = "";
        }}
      />
      {file ? (
        <>
          <div className="dz-icon">📄</div>
          <div className="dz-name">{file.name}</div>
          <div className="dz-meta">
            {formatSize(file.size)} · cliquer pour changer
          </div>
        </>
      ) : (
        <>
          <div className="dz-icon">⬆️</div>
          <div className="dz-name">{label}</div>
          <div className="dz-meta">
            Glissez-déposez ou cliquez pour parcourir
          </div>
        </>
      )}
    </div>
  );
}

function PemImport({ onText, children }) {
  const inputRef = useRef(null);
  return (
    <>
      <input
        ref={inputRef}
        type="file"
        accept=".pem,.txt,.key,.pub"
        hidden
        onChange={async (e) => {
          const f = e.target.files?.[0];
          if (f) onText(await readFile(f, "text"));
          e.target.value = "";
        }}
      />
      <button
        type="button"
        className="btn btn-ghost btn-sm"
        onClick={() => inputRef.current?.click()}
      >
        {children}
      </button>
    </>
  );
}

function KeyStatus({ info }) {
  if (info.status === "empty")
    return <span className="badge badge-idle">En attente d'une clé</span>;
  if (info.status === "invalid")
    return <span className="badge badge-err">✕ Format PEM invalide</span>;
  return (
    <span className="badge badge-ok">✓ Clé RSA {info.bits} bits valide</span>
  );
}

function Progress({ value }) {
  return (
    <div className="progress" aria-label="Progression">
      <div className="progress-bar" style={{ width: `${value}%` }} />
      <span className="progress-label">{value}%</span>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Application                                                        */
/* ------------------------------------------------------------------ */
export default function App() {
  // Étape 1 : clés
  const [keys, setKeys] = useState({ publicKey: "", privateKey: "" });
  const [isGenerating, setIsGenerating] = useState(false);
  const [genTime, setGenTime] = useState(null);
  const [showPrivate, setShowPrivate] = useState(false);

  // Étape 2 : chiffrement
  const [fileToEncrypt, setFileToEncrypt] = useState(null);
  const [recipientPublicKeyPem, setRecipientPublicKeyPem] = useState("");
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [encProgress, setEncProgress] = useState(0);
  const [encResult, setEncResult] = useState(null);

  // Étape 3 : déchiffrement
  const [fileToDecrypt, setFileToDecrypt] = useState(null);
  const [myPrivateKeyPem, setMyPrivateKeyPem] = useState("");
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decProgress, setDecProgress] = useState(0);
  const [decResult, setDecResult] = useState(null);

  // Interface
  const [toasts, setToasts] = useState([]);
  const [logs, setLogs] = useState([
    {
      id: 0,
      time: new Date().toLocaleTimeString("fr-FR"),
      type: "info",
      msg: "Application prête. Aucune donnée ne quitte votre navigateur.",
    },
  ]);

  const recipientInfo = useMemo(
    () => inspectPem(recipientPublicKeyPem, "public"),
    [recipientPublicKeyPem],
  );
  const privateInfo = useMemo(
    () => inspectPem(myPrivateKeyPem, "private"),
    [myPrivateKeyPem],
  );
  const myFingerprint = useMemo(
    () => (keys.publicKey ? fingerprintOf(keys.publicKey) : ""),
    [keys.publicKey],
  );

  /* ---------- notifications & journal ---------- */
  const log = (type, msg) =>
    setLogs((prev) =>
      [
        {
          id: Date.now() + Math.random(),
          time: new Date().toLocaleTimeString("fr-FR"),
          type,
          msg,
        },
        ...prev,
      ].slice(0, 40),
    );

  const notify = (type, msg) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, type, msg }]);
    setTimeout(
      () => setToasts((prev) => prev.filter((t) => t.id !== id)),
      4200,
    );
    log(type, msg);
  };

  const copy = async (text, what) => {
    try {
      await navigator.clipboard.writeText(text);
      notify("success", `${what} copiée dans le presse-papiers.`);
    } catch {
      notify("error", "Copie impossible : sélectionnez le texte manuellement.");
    }
  };

  const scrollTo = (id) =>
    document
      .getElementById(id)
      ?.scrollIntoView({ behavior: "smooth", block: "start" });

  /* ---------- Partie 1 : génération des clés ---------- */
  const generateRSAKeys = () => {
    setIsGenerating(true);
    log("info", `Génération d'une paire RSA ${KEY_BITS} bits…`);
    // Petit délai pour que le spinner s'affiche avant le calcul
    setTimeout(() => {
      const t0 = performance.now();
      forge.pki.rsa.generateKeyPair(
        { bits: KEY_BITS, workers: -1 },
        (err, keypair) => {
          if (err) {
            console.error("Erreur génération :", err);
            notify("error", "Échec de la génération des clés.");
            setIsGenerating(false);
            return;
          }
          const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
          const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
          setKeys({ publicKey: publicKeyPem, privateKey: privateKeyPem });
          setMyPrivateKeyPem(privateKeyPem); // remplissage auto pour l'étape 3
          setGenTime(((performance.now() - t0) / 1000).toFixed(2));
          setShowPrivate(false);
          setIsGenerating(false);
          notify("success", "Paire de clés RSA générée avec succès.");
        },
      );
    }, 60);
  };

  /* ---------- Partie 2 : chiffrement par blocs ---------- */
  const handleEncryptFile = async () => {
    let publicKey;
    try {
      publicKey = forge.pki.publicKeyFromPem(recipientPublicKeyPem.trim());
    } catch {
      notify("error", "La clé publique du binôme est invalide.");
      return;
    }

    setIsEncrypting(true);
    setEncProgress(0);
    setEncResult(null);
    try {
      const fileBytes = await readFile(fileToEncrypt);
      if (fileBytes.length === 0) throw new Error("Le fichier est vide.");

      const t0 = performance.now();
      const total = Math.ceil(fileBytes.length / CHUNK_SIZE);
      const encryptedChunks = [];
      log(
        "info",
        `Chiffrement de « ${fileToEncrypt.name} » en ${total} blocs…`,
      );

      for (let i = 0, n = 0; i < fileBytes.length; i += CHUNK_SIZE, n++) {
        const chunk = fileBytes.slice(i, i + CHUNK_SIZE);
        const encryptedChunk = publicKey.encrypt(chunk, "RSA-OAEP");
        encryptedChunks.push(forge.util.encode64(encryptedChunk));
        if (n % 20 === 0) {
          setEncProgress(Math.round((n / total) * 100));
          await tick();
        }
      }
      setEncProgress(100);

      const payload = JSON.stringify({
        originalName: fileToEncrypt.name,
        chunks: encryptedChunks,
      });
      const blob = new Blob([payload], { type: "application/json" });
      downloadBlob(blob, `${fileToEncrypt.name}.rsa.enc`);

      setEncResult({
        name: `${fileToEncrypt.name}.rsa.enc`,
        originalSize: fileToEncrypt.size,
        encryptedSize: blob.size,
        chunks: total,
        ms: Math.round(performance.now() - t0),
      });
      notify("success", "Fichier chiffré et téléchargé (.rsa.enc).");
    } catch (err) {
      console.error("Erreur chiffrement :", err);
      notify("error", `Erreur de chiffrement : ${err.message}`);
    } finally {
      setIsEncrypting(false);
    }
  };

  /* ---------- Partie 3 : déchiffrement par blocs ---------- */
  const handleDecryptFile = async () => {
    let privateKey;
    try {
      privateKey = forge.pki.privateKeyFromPem(myPrivateKeyPem.trim());
    } catch {
      notify("error", "Votre clé privée est invalide.");
      return;
    }

    setIsDecrypting(true);
    setDecProgress(0);
    setDecResult(null);
    try {
      const text = await readFile(fileToDecrypt, "text");
      let payload;
      try {
        payload = JSON.parse(text);
      } catch {
        throw new Error("ce fichier n'est pas un .rsa.enc valide.");
      }
      if (!Array.isArray(payload.chunks) || !payload.originalName) {
        throw new Error("structure du fichier chiffré incorrecte.");
      }

      const t0 = performance.now();
      const total = payload.chunks.length;
      const parts = [];
      log("info", `Déchiffrement de ${total} blocs…`);

      for (let n = 0; n < total; n++) {
        const encryptedChunk = forge.util.decode64(payload.chunks[n]);
        parts.push(privateKey.decrypt(encryptedChunk, "RSA-OAEP"));
        if (n % 20 === 0) {
          setDecProgress(Math.round((n / total) * 100));
          await tick();
        }
      }
      setDecProgress(100);

      const decryptedBytes = parts.join("");
      const buffer = new Uint8Array(decryptedBytes.length);
      for (let i = 0; i < decryptedBytes.length; i++) {
        buffer[i] = decryptedBytes.charCodeAt(i) & 0xff;
      }

      downloadBlob(new Blob([buffer]), `dechiffre_${payload.originalName}`);
      setDecResult({
        name: `dechiffre_${payload.originalName}`,
        size: buffer.length,
        chunks: total,
        ms: Math.round(performance.now() - t0),
      });
      notify("success", "Fichier déchiffré et téléchargé.");
    } catch (err) {
      console.error("Erreur déchiffrement :", err);
      const wrongKey = /Encryption block is invalid|OAEP|decrypt/i.test(
        err.message,
      );
      notify(
        "error",
        wrongKey
          ? "Déchiffrement impossible : mauvaise clé privée ou fichier corrompu."
          : `Erreur de déchiffrement : ${err.message}`,
      );
    } finally {
      setIsDecrypting(false);
    }
  };

  /* ---------- Étapes (tracker) ---------- */
  const steps = [
    { id: "step-1", n: 1, label: "Générer les clés", done: !!keys.publicKey },
    { id: "step-2", n: 2, label: "Chiffrer", done: !!encResult },
    { id: "step-3", n: 3, label: "Déchiffrer", done: !!decResult },
  ];
  const currentStep = steps.find((s) => !s.done)?.n ?? 4;

  const canEncrypt =
    fileToEncrypt && recipientInfo.status === "valid" && !isEncrypting;
  const canDecrypt =
    fileToDecrypt && privateInfo.status === "valid" && !isDecrypting;

  return (
    <div className="app">
      <div className="bg-blob blob-1" />
      <div className="bg-blob blob-2" />
      <div className="bg-blob blob-3" />

      {/* ---------- En-tête ---------- */}
      <header className="topbar">
        <div className="brand">
          <span className="brand-logo">🔐</span>
          <span className="brand-name">
            RSA<span>Vault</span>
          </span>
        </div>
        <div className="topbar-badges">
          <span className="pill">RSA-{KEY_BITS}</span>
          <span className="pill">OAEP</span>
          <span className="pill pill-green">● 100 % côté client</span>
        </div>
      </header>

      <section className="hero">
        <p className="eyebrow">TP Cryptographie · Chiffrement asymétrique</p>
        <h1>
          Échangez des fichiers{" "}
          <span className="gradient-text">chiffrés en RSA</span>
        </h1>
        <p className="hero-sub">
          Générez votre paire de clés, chiffrez un fichier avec la clé publique
          de votre binôme, et laissez-le le déchiffrer avec sa clé privée. Tout
          se passe dans votre navigateur.
        </p>
      </section>

      {/* ---------- Tracker d'étapes ---------- */}
      <nav className="stepper" aria-label="Progression">
        {steps.map((s, i) => (
          <div key={s.id} className="stepper-item">
            <button
              className={`step-dot ${s.done ? "done" : ""} ${currentStep === s.n ? "active" : ""}`}
              onClick={() => scrollTo(s.id)}
            >
              {s.done ? "✓" : s.n}
            </button>
            <span
              className={`step-label ${currentStep === s.n ? "active" : ""}`}
            >
              {s.label}
            </span>
            {i < steps.length - 1 && (
              <span className={`step-line ${s.done ? "done" : ""}`} />
            )}
          </div>
        ))}
      </nav>

      <main className="content">
        {/* ============ ÉTAPE 1 ============ */}
        <section id="step-1" className="card card-indigo">
          <div className="card-head">
            <span className="card-num">1</span>
            <div>
              <h2>Génération de mes clés RSA</h2>
              <p>
                La clé publique se partage. La clé privée ne quitte jamais votre
                machine.
              </p>
            </div>
          </div>

          <div className="row-actions">
            <button
              className="btn btn-primary"
              onClick={generateRSAKeys}
              disabled={isGenerating}
            >
              {isGenerating ? (
                <>
                  <span className="spinner" /> Génération en cours…
                </>
              ) : keys.publicKey ? (
                "🔄 Régénérer mes clés"
              ) : (
                "⚡ Générer mes clés RSA"
              )}
            </button>
            {genTime && !isGenerating && (
              <span className="muted">Générées en {genTime} s</span>
            )}
          </div>

          <div className="keys">
            <div className="field">
              <div className="field-head">
                <label>
                  🔓 Ma clé publique <em>(à envoyer au binôme)</em>
                </label>
                {keys.publicKey && (
                  <span className="badge badge-ok">Partageable</span>
                )}
              </div>
              <textarea
                readOnly
                rows={7}
                value={keys.publicKey}
                placeholder="Cliquez sur « Générer mes clés RSA »…"
                spellCheck={false}
              />
              {myFingerprint && (
                <div
                  className="fingerprint"
                  title="Empreinte SHA-256 (à comparer avec votre binôme)"
                >
                  <span>Empreinte</span>
                  <code>{myFingerprint}</code>
                </div>
              )}
              <div className="field-actions">
                <button
                  className="btn btn-ghost btn-sm"
                  disabled={!keys.publicKey}
                  onClick={() => copy(keys.publicKey, "Clé publique")}
                >
                  📋 Copier
                </button>
                <button
                  className="btn btn-ghost btn-sm"
                  disabled={!keys.publicKey}
                  onClick={() =>
                    downloadBlob(new Blob([keys.publicKey]), "cle_publique.pem")
                  }
                >
                  ⬇️ .pem
                </button>
              </div>
            </div>

            <div className="field">
              <div className="field-head">
                <label>
                  🔒 Ma clé privée <em>(à garder secrète)</em>
                </label>
                {keys.privateKey && (
                  <span className="badge badge-warn">Confidentielle</span>
                )}
              </div>
              <textarea
                readOnly
                rows={7}
                className={keys.privateKey && !showPrivate ? "blurred" : ""}
                value={keys.privateKey}
                placeholder="Votre clé privée apparaîtra ici…"
                spellCheck={false}
              />
              <div className="field-actions">
                <button
                  className="btn btn-ghost btn-sm"
                  disabled={!keys.privateKey}
                  onClick={() => setShowPrivate((v) => !v)}
                >
                  {showPrivate ? "🙈 Masquer" : "👁️ Afficher"}
                </button>
                <button
                  className="btn btn-ghost btn-sm"
                  disabled={!keys.privateKey}
                  onClick={() => copy(keys.privateKey, "Clé privée")}
                >
                  📋 Copier
                </button>
                <button
                  className="btn btn-ghost btn-sm"
                  disabled={!keys.privateKey}
                  onClick={() =>
                    downloadBlob(new Blob([keys.privateKey]), "cle_privee.pem")
                  }
                >
                  ⬇️ .pem
                </button>
              </div>
            </div>
          </div>
        </section>

        <div className="grid-2">
          {/* ============ ÉTAPE 2 ============ */}
          <section id="step-2" className="card card-green">
            <div className="card-head">
              <span className="card-num">2</span>
              <div>
                <h2>Chiffrer un fichier</h2>
                <p>Avec la clé publique de votre binôme.</p>
              </div>
            </div>

            <div className="field">
              <label>Fichier à chiffrer</label>
              <DropZone
                file={fileToEncrypt}
                onFile={setFileToEncrypt}
                label="Choisissez le fichier à protéger"
              />
            </div>

            <div className="field">
              <div className="field-head">
                <label>Clé publique du binôme</label>
                <KeyStatus info={recipientInfo} />
              </div>
              <textarea
                rows={6}
                value={recipientPublicKeyPem}
                onChange={(e) => setRecipientPublicKeyPem(e.target.value)}
                placeholder="Collez la clé publique transmise par votre binôme…"
                spellCheck={false}
              />
              <div className="field-actions">
                <PemImport onText={setRecipientPublicKeyPem}>
                  📂 Importer un .pem
                </PemImport>
                {recipientInfo.status === "valid" && (
                  <div className="fingerprint inline">
                    <span>Empreinte</span>
                    <code>{recipientInfo.fingerprint}</code>
                  </div>
                )}
              </div>
            </div>

            {isEncrypting && <Progress value={encProgress} />}

            <button
              className="btn btn-green btn-block"
              onClick={handleEncryptFile}
              disabled={!canEncrypt}
            >
              {isEncrypting ? (
                <>
                  <span className="spinner" /> Chiffrement…
                </>
              ) : (
                "🔐 Chiffrer et télécharger (.rsa.enc)"
              )}
            </button>
            {!canEncrypt && !isEncrypting && (
              <p className="hint">
                {!fileToEncrypt
                  ? "Sélectionnez un fichier."
                  : "Collez une clé publique valide."}
              </p>
            )}

            {encResult && (
              <div className="result result-green">
                <div className="result-title">
                  ✓ Chiffrement terminé — {encResult.name}
                </div>
                <div className="stats">
                  <div>
                    <strong>{formatSize(encResult.originalSize)}</strong>
                    <span>Taille d'origine</span>
                  </div>
                  <div>
                    <strong>{formatSize(encResult.encryptedSize)}</strong>
                    <span>Taille chiffrée</span>
                  </div>
                  <div>
                    <strong>{encResult.chunks}</strong>
                    <span>Blocs RSA</span>
                  </div>
                  <div>
                    <strong>{encResult.ms} ms</strong>
                    <span>Durée</span>
                  </div>
                </div>
              </div>
            )}
          </section>

          {/* ============ ÉTAPE 3 ============ */}
          <section id="step-3" className="card card-amber">
            <div className="card-head">
              <span className="card-num">3</span>
              <div>
                <h2>Déchiffrer un fichier reçu</h2>
                <p>Avec votre clé privée.</p>
              </div>
            </div>

            <div className="field">
              <label>Fichier chiffré (.rsa.enc)</label>
              <DropZone
                file={fileToDecrypt}
                onFile={setFileToDecrypt}
                accept=".enc,.json"
                label="Déposez le fichier .rsa.enc reçu"
              />
            </div>

            <div className="field">
              <div className="field-head">
                <label>Ma clé privée</label>
                <KeyStatus info={privateInfo} />
              </div>
              <textarea
                rows={6}
                value={myPrivateKeyPem}
                onChange={(e) => setMyPrivateKeyPem(e.target.value)}
                placeholder="Collez votre clé privée pour déchiffrer le fichier…"
                spellCheck={false}
              />
              <div className="field-actions">
                <PemImport onText={setMyPrivateKeyPem}>
                  📂 Importer un .pem
                </PemImport>
              </div>
            </div>

            {isDecrypting && <Progress value={decProgress} />}

            <button
              className="btn btn-amber btn-block"
              onClick={handleDecryptFile}
              disabled={!canDecrypt}
            >
              {isDecrypting ? (
                <>
                  <span className="spinner" /> Déchiffrement…
                </>
              ) : (
                "🔓 Déchiffrer et récupérer le fichier d'origine"
              )}
            </button>
            {!canDecrypt && !isDecrypting && (
              <p className="hint">
                {!fileToDecrypt
                  ? "Sélectionnez un fichier .rsa.enc."
                  : "Renseignez une clé privée valide."}
              </p>
            )}

            {decResult && (
              <div className="result result-amber">
                <div className="result-title">
                  ✓ Déchiffrement terminé — {decResult.name}
                </div>
                <div className="stats">
                  <div>
                    <strong>{formatSize(decResult.size)}</strong>
                    <span>Taille restaurée</span>
                  </div>
                  <div>
                    <strong>{decResult.chunks}</strong>
                    <span>Blocs RSA</span>
                  </div>
                  <div>
                    <strong>{decResult.ms} ms</strong>
                    <span>Durée</span>
                  </div>
                </div>
              </div>
            )}
          </section>
        </div>

        {/* ============ Infos techniques + journal ============ */}
        <div className="grid-2">
          <section className="card card-plain">
            <div className="card-head">
              <span className="card-num alt">ℹ</span>
              <div>
                <h2>Fonctionnement technique</h2>
                <p>Ce que fait l'application en coulisses.</p>
              </div>
            </div>
            <ul className="tech-list">
              <li>
                <strong>Algorithme</strong>
                <span>RSA {KEY_BITS} bits, padding OAEP</span>
              </li>
              <li>
                <strong>Découpage</strong>
                <span>Blocs de {CHUNK_SIZE} octets (limite OAEP : 214 o)</span>
              </li>
              <li>
                <strong>Format de sortie</strong>
                <span>JSON · blocs chiffrés encodés en Base64</span>
              </li>
              <li>
                <strong>Clés</strong>
                <span>Format PEM (PKCS#1 / SPKI)</span>
              </li>
              <li>
                <strong>Bibliothèque</strong>
                <span>node-forge</span>
              </li>
              <li>
                <strong>Confidentialité</strong>
                <span>Aucun serveur : les clés restent dans le navigateur</span>
              </li>
            </ul>
          </section>

          <section className="card card-plain">
            <div className="card-head">
              <span className="card-num alt">›_</span>
              <div>
                <h2>Journal d'activité</h2>
                <p>Historique des opérations de la session.</p>
              </div>
            </div>
            <div className="terminal">
              <div className="terminal-bar">
                <i />
                <i />
                <i />
                <span>session.log</span>
              </div>
              <div className="terminal-body">
                {logs.map((l) => (
                  <div key={l.id} className={`log log-${l.type}`}>
                    <time>{l.time}</time>
                    <span>{l.msg}</span>
                  </div>
                ))}
              </div>
            </div>
          </section>
        </div>
      </main>

      <footer className="footer">
        <span>TP Cryptographie · {AUTHORS}</span>
        <span>React · Vite · node-forge</span>
      </footer>

      {/* ---------- Toasts ---------- */}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast toast-${t.type}`}>
            <span>
              {t.type === "success" ? "✓" : t.type === "error" ? "✕" : "ℹ"}
            </span>
            {t.msg}
          </div>
        ))}
      </div>
    </div>
  );
}
