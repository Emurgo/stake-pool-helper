import { useState, useEffect } from "react";
import { Ada, HARDENED } from "@cardano-foundation/ledgerjs-hw-app-cardano";
import TransportWebUSB from "@ledgerhq/hw-transport-webusb";
import { blake2b } from "@noble/hashes/blake2.js";
import bech32 from "bech32";

type Status =
  | { kind: "idle" }
  | { kind: "connecting" }
  | { kind: "loading" }
  | { kind: "success"; publicKeyHex: string; chainCodeHex: string; poolId: string }
  | { kind: "error"; message: string };

function derivePoolId(publicKeyHex: string): string {
  const bytes = Uint8Array.from(Buffer.from(publicKeyHex, "hex"));
  const hash = blake2b(bytes, { dkLen: 28 });
  return bech32.encode("pool", bech32.toWords(hash));
}

const PATH = [
  1853 + HARDENED,
  1815 + HARDENED,
  0 + HARDENED,
  0 + HARDENED,
];

async function fetchExtendedPublicKey() {
  const transport = await TransportWebUSB.create();
  try {
    const ada = new Ada(transport);
    return await ada.getExtendedPublicKey({ path: PATH });
  } finally {
    await transport.close();
  }
}

export default function App() {
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  useEffect(() => {
    setStatus({ kind: "connecting" });
  }, []);

  async function connect() {
    setStatus({ kind: "connecting" });
    try {
      setStatus({ kind: "loading" });
      const result = await fetchExtendedPublicKey();
      setStatus({
        kind: "success",
        publicKeyHex: result.publicKeyHex,
        chainCodeHex: result.chainCodeHex,
        poolId: derivePoolId(result.publicKeyHex),
      });
    } catch (err) {
      setStatus({
        kind: "error",
        message: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
  }

  return (
    <div style={styles.container}>
      <h1 style={styles.title}>Pool KES Utils</h1>
      <h2 style={styles.subtitle}>Extended Public Key</h2>
      <p style={styles.path}>Path: 1853H / 1815H / 0H / 0H</p>

      {(status.kind === "idle" || status.kind === "connecting") && (
        <div style={styles.card}>
          <p style={styles.hint}>
            Connect your Ledger device, open the Cardano app, then click below.
          </p>
          <button style={styles.button} onClick={connect}>
            Connect Ledger &amp; Get Key
          </button>
        </div>
      )}

      {status.kind === "loading" && (
        <div style={styles.card}>
          <p style={styles.loading}>Waiting for Ledger confirmation…</p>
        </div>
      )}

      {status.kind === "success" && (
        <div style={styles.card}>
          <div style={styles.field}>
            <span style={styles.label}>Pool ID</span>
            <code style={styles.value}>{status.poolId}</code>
          </div>
          <div style={styles.field}>
            <span style={styles.label}>Public Key</span>
            <code style={styles.value}>{status.publicKeyHex}</code>
          </div>
          <div style={styles.field}>
            <span style={styles.label}>Chain Code</span>
            <code style={styles.value}>{status.chainCodeHex}</code>
          </div>
          <button style={{ ...styles.button, ...styles.secondary }} onClick={connect}>
            Refresh
          </button>
        </div>
      )}

      {status.kind === "error" && (
        <div style={{ ...styles.card, ...styles.errorCard }}>
          <p style={styles.errorText}>{status.message}</p>
          <button style={styles.button} onClick={connect}>
            Retry
          </button>
        </div>
      )}
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    fontFamily: "system-ui, sans-serif",
    maxWidth: 600,
    margin: "60px auto",
    padding: "0 24px",
  },
  title: {
    fontSize: 28,
    fontWeight: 700,
    margin: 0,
  },
  subtitle: {
    fontSize: 18,
    fontWeight: 500,
    marginTop: 8,
    color: "#555",
  },
  path: {
    fontFamily: "monospace",
    fontSize: 14,
    color: "#888",
    marginBottom: 32,
  },
  card: {
    background: "#f9f9f9",
    border: "1px solid #e0e0e0",
    borderRadius: 10,
    padding: 24,
  },
  errorCard: {
    background: "#fff5f5",
    border: "1px solid #fca5a5",
  },
  hint: {
    color: "#555",
    marginTop: 0,
    marginBottom: 20,
    lineHeight: 1.5,
  },
  loading: {
    color: "#555",
    margin: 0,
  },
  button: {
    background: "#1d4ed8",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    padding: "10px 20px",
    fontSize: 15,
    cursor: "pointer",
  },
  secondary: {
    background: "#6b7280",
    marginTop: 20,
  },
  field: {
    marginBottom: 16,
  },
  label: {
    display: "block",
    fontSize: 12,
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.05em",
    color: "#888",
    marginBottom: 4,
  },
  value: {
    display: "block",
    fontSize: 13,
    wordBreak: "break-all",
    background: "#efefef",
    padding: "8px 10px",
    borderRadius: 4,
  },
  errorText: {
    color: "#b91c1c",
    marginTop: 0,
    marginBottom: 16,
    fontFamily: "monospace",
    fontSize: 13,
  },
};
