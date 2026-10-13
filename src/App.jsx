import { useState } from "react";
import forge from "node-forge";

export default function App() {
  // --- ÉTATS CLÉS ---
  const [keys, setKeys] = useState({ publicKey: "", privateKey: "" });
  const [isGenerating, setIsGenerating] = useState(false);

  // --- ÉTATS CHIFFREMENT ---
  const [fileToEncrypt, setFileToEncrypt] = useState(null);
  const [recipientPublicKeyPem, setRecipientPublicKeyPem] = useState("");
  const [isEncrypting, setIsEncrypting] = useState(false);

  // --- ÉTATS DÉCHIFFREMENT ---
  const [fileToDecrypt, setFileToDecrypt] = useState(null);
  const [myPrivateKeyPem, setMyPrivateKeyPem] = useState("");
  const [isDecrypting, setIsDecrypting] = useState(false);

  // 1. Génération des clés RSA (2048 bits)
  const generateRSAKeys = () => {
    setIsGenerating(true);
    forge.pki.rsa.generateKeyPair(
      { bits: 2048, workers: -1 },
      (err, keypair) => {
        if (err) {
          console.error("Erreur génération :", err);
          setIsGenerating(false);
          return;
        }
        const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
        const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);

        setKeys({ publicKey: publicKeyPem, privateKey: privateKeyPem });
        setMyPrivateKeyPem(privateKeyPem); // Remplit automatiquement le champ déchiffrement pour tester
        setIsGenerating(false);
      },
    );
  };

  // 2. Chiffrement RSA PUR par blocs
  const handleEncryptFile = () => {
    if (!fileToEncrypt || !recipientPublicKeyPem.trim()) {
      alert(
        "Sélectionnez un fichier et collez la clé publique de votre binôme.",
      );
      return;
    }

    setIsEncrypting(true);

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const fileBytes = e.target.result;
        const recipientPublicKey = forge.pki.publicKeyFromPem(
          recipientPublicKeyPem,
        );

        // RSA 2048 bits avec OAEP limite les blocs à ~214 octets (on prend 190 octets par sécurité)
        const CHUNK_SIZE = 190;
        const encryptedChunks = [];

        for (let i = 0; i < fileBytes.length; i += CHUNK_SIZE) {
          const chunk = fileBytes.slice(i, i + CHUNK_SIZE);
          const encryptedChunk = recipientPublicKey.encrypt(chunk, "RSA-OAEP");
          encryptedChunks.push(forge.util.encode64(encryptedChunk));
        }

        const payload = JSON.stringify({
          originalName: fileToEncrypt.name,
          chunks: encryptedChunks,
        });

        const blob = new Blob([payload], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `${fileToEncrypt.name}.rsa.enc`;
        link.click();
        URL.revokeObjectURL(url);

        alert("Fichier chiffré en RSA pur avec succès !");
      } catch (err) {
        console.error("Erreur chiffrement :", err);
        alert("Erreur de chiffrement. Vérifiez le format de la clé publique.");
      } finally {
        setIsEncrypting(false);
      }
    };

    reader.readAsBinaryString(fileToEncrypt);
  };

  // 3. Déchiffrement RSA PUR par blocs
  const handleDecryptFile = () => {
    if (!fileToDecrypt || !myPrivateKeyPem.trim()) {
      alert("Sélectionnez le fichier .rsa.enc et insérez votre clé privée.");
      return;
    }

    setIsDecrypting(true);

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const payload = JSON.parse(e.target.result);
        const privateKey = forge.pki.privateKeyFromPem(myPrivateKeyPem);

        let decryptedBytes = "";

        // Déchiffrement de chaque bloc un par un
        for (const encryptedChunkBase64 of payload.chunks) {
          const encryptedChunk = forge.util.decode64(encryptedChunkBase64);
          const decryptedChunk = privateKey.decrypt(encryptedChunk, "RSA-OAEP");
          decryptedBytes += decryptedChunk;
        }

        // Reconstitution des données binaires d'origine
        const buffer = new Uint8Array(decryptedBytes.length);
        for (let i = 0; i < decryptedBytes.length; i++) {
          buffer[i] = decryptedBytes.charCodeAt(i) & 0xff;
        }

        const blob = new Blob([buffer]);
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = `dechiffre_${payload.originalName}`;
        link.click();
        URL.revokeObjectURL(url);

        alert("Fichier déchiffré avec succès !");
      } catch (err) {
        console.error("Erreur déchiffrement :", err);
        alert(
          "Erreur lors du déchiffrement. Clé privée invalide ou fichier corrompu.",
        );
      } finally {
        setIsDecrypting(false);
      }
    };

    reader.readAsText(fileToDecrypt);
  };

  return (
    <div
      style={{
        maxWidth: "900px",
        margin: "0 auto",
        padding: "20px",
        fontFamily: "system-ui",
      }}
    >
      <h1
        style={{ textAlign: "center", lineHeight: "1.3", marginBottom: "30px" }}
      >
        TP Cryptographie <br /> Chiffrement / Déchiffrement RSA Pur
      </h1>

      {/* 1. GÉNÉRATION DES CLÉS */}
      <section
        style={{
          backgroundColor: "#f8fafc",
          padding: "20px",
          borderRadius: "8px",
          marginBottom: "20px",
          border: "1px solid #e2e8f0",
        }}
      >
        <h2>1. Génération de mes clés RSA</h2>
        <button
          onClick={generateRSAKeys}
          disabled={isGenerating}
          style={{
            padding: "10px 20px",
            cursor: "pointer",
            marginBottom: "15px",
          }}
        >
          {isGenerating ? "Génération en cours..." : "Générer mes clés RSA"}
        </button>

        <div style={{ display: "flex", gap: "20px" }}>
          <div style={{ flex: 1 }}>
            <label style={{ fontWeight: "bold" }}>
              Ma Clé Publique (À envoyer au binôme) :
            </label>
            <textarea
              readOnly
              value={keys.publicKey}
              rows={7}
              style={{
                width: "100%",
                marginTop: "5px",
                fontSize: "11px",
                fontFamily: "monospace",
              }}
              placeholder="La clé publique s'affichera ici..."
            />
          </div>
          <div style={{ flex: 1 }}>
            <label style={{ fontWeight: "bold" }}>
              Ma Clé Privée (À garder secrète) :
            </label>
            <textarea
              readOnly
              value={keys.privateKey}
              rows={7}
              style={{
                width: "100%",
                marginTop: "5px",
                fontSize: "11px",
                fontFamily: "monospace",
              }}
              placeholder="La clé privée s'affichera ici..."
            />
          </div>
        </div>
      </section>

      {/* 2. CHIFFREMENT */}
      <section
        style={{
          backgroundColor: "#f0fdf4",
          padding: "20px",
          borderRadius: "8px",
          marginBottom: "20px",
          border: "1px solid #bbf7d0",
        }}
      >
        <h2>2. Chiffrer un fichier avec la Clé Publique du binôme</h2>

        <div style={{ marginBottom: "15px" }}>
          <label
            style={{
              display: "block",
              fontWeight: "bold",
              marginBottom: "5px",
            }}
          >
            Fichier à chiffrer :
          </label>
          <input
            type="file"
            onChange={(e) => setFileToEncrypt(e.target.files[0])}
          />
        </div>

        <div style={{ marginBottom: "15px" }}>
          <label
            style={{
              display: "block",
              fontWeight: "bold",
              marginBottom: "5px",
            }}
          >
            Clé Publique du binôme :
          </label>
          <textarea
            value={recipientPublicKeyPem}
            onChange={(e) => setRecipientPublicKeyPem(e.target.value)}
            rows={5}
            style={{ width: "100%", fontSize: "11px", fontFamily: "monospace" }}
            placeholder="Collez la clé publique transmise par votre binôme..."
          />
        </div>

        <button
          onClick={handleEncryptFile}
          disabled={isEncrypting}
          style={{
            padding: "10px 20px",
            backgroundColor: "#16a34a",
            color: "white",
            border: "none",
            borderRadius: "4px",
            cursor: "pointer",
          }}
        >
          {isEncrypting
            ? "Chiffrement en cours..."
            : "Chiffrer et Télécharger (.rsa.enc)"}
        </button>
      </section>

      {/* 3. DÉCHIFFREMENT */}
      <section
        style={{
          backgroundColor: "#fefce8",
          padding: "20px",
          borderRadius: "8px",
          border: "1px solid #fef08a",
        }}
      >
        <h2>3. Déchiffrer un fichier reçu avec Ma Clé Privée</h2>

        <div style={{ marginBottom: "15px" }}>
          <label
            style={{
              display: "block",
              fontWeight: "bold",
              marginBottom: "5px",
            }}
          >
            Fichier chiffré (.rsa.enc) :
          </label>
          <input
            type="file"
            onChange={(e) => setFileToDecrypt(e.target.files[0])}
          />
        </div>

        <div style={{ marginBottom: "15px" }}>
          <label
            style={{
              display: "block",
              fontWeight: "bold",
              marginBottom: "5px",
            }}
          >
            Ma Clé Privée :
          </label>
          <textarea
            value={myPrivateKeyPem}
            onChange={(e) => setMyPrivateKeyPem(e.target.value)}
            rows={5}
            style={{ width: "100%", fontSize: "11px", fontFamily: "monospace" }}
            placeholder="Collez votre clé privée pour déchiffrer le fichier..."
          />
        </div>

        <button
          onClick={handleDecryptFile}
          disabled={isDecrypting}
          style={{
            padding: "10px 20px",
            backgroundColor: "#ca8a04",
            color: "white",
            border: "none",
            borderRadius: "4px",
            cursor: "pointer",
          }}
        >
          {isDecrypting
            ? "Déchiffrement en cours..."
            : "Déchiffrer et Récupérer le fichier d'origine"}
        </button>
      </section>
    </div>
  );
}
