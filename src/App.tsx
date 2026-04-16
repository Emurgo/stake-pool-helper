import { useState, useEffect } from "react";
import { Ada, HARDENED } from "@cardano-foundation/ledgerjs-hw-app-cardano";
import TransportWebUSB from "@ledgerhq/hw-transport-webusb";
import { blake2b } from "@noble/hashes/blake2.js";
import { bech32 } from "bech32";
import { genKeyKES } from "./kes";
import { encode } from 'cbor2';

type Status =
  | { kind: "idle" }
  | { kind: "connecting" }
  | { kind: "loading" }
  | { kind: "success"; poolId: string; ticker: string | null; downloadedFilename: string }
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

async function fetchOpCertSignature(kesPublicKeyHex, kesPeriod, issueCounter) {
  const transport = await TransportWebUSB.create();
  try {
    const ada = new Ada(transport);
    return await ada.signOperationalCertificate({
      kesPublicKeyHex,
      kesPeriod,
      issueCounter,
      coldKeyPath: PATH,
    });
  } finally {
    await transport.close();
  }
}

const BLOCKFROST_PROJECT_ID = 'mainnettssNeYQtpuod4KVg8F7SDr5kW27mb7hJ'; //fixme
const BLOCKFROST_BASE_URL = 'https://cardano-mainnet.blockfrost.io/api/v0';

async function blockfrostFetch(path: string) {
  const resp = await fetch(`${BLOCKFROST_BASE_URL}${path}`, {
    headers: { project_id: BLOCKFROST_PROJECT_ID },
  });
  if (!resp.ok) {
    throw new Error(`Blockfrost ${path} returned ${resp.status}`);
  }
  return resp.json();
}

async function retry(func, errorHandler) {
  if (!errorHandler) {
    errorHandler = async () => {
      console.error('just failed, retry');
      await pause();
    };
  };
  for (;;) {
    try {
      return await func();
    } catch (error) {
      await errorHandler(error);
    }
  }
}

async function getPoolTicker(poolId: string): Promise<string | null> {
  try {
    const resp = await blockfrostFetch(`/pools/${poolId}/metadata`);
    return resp.ticker ?? null;
  } catch {
    return null;
  }
}

async function getLastBlockHashOfPool(poolId) {
  const resp = await retry(
    async () => await blockfrostFetch(`/pools/${poolId}/blocks?page=1&count=1&order=desc`),
    (error) => console.log(`error getting latest block hash: ${error.message}`)
  );
  return resp[0];
}

async function getOpCertCounter(poolId) {
  const blockHash = await getLastBlockHashOfPool(poolId);
  if (blockHash === undefined) {
    return -1;
  }
  const resp = await retry(
    async () => await blockfrostFetch(`/blocks/${blockHash}`),
    (error) => console.log(`error getting block: ${error.message}`)
  );
  return Number(resp.op_cert_counter);
}

function getCurrentKesPeriod() {
  const T = new Date('2023/06/19 11:32:22 UTC');
  const S = 95608051;
  const K = 129600;
  const currentSlot = Math.floor((Date.now() - T.valueOf()) / 1000 + S);
  return Math.floor(currentSlot / K);
}

function createNodeOpCertFileContent(kesVKey, coldVKey, kesPeriod, counter, signature) {
  const cborHex = encode(
    [
      [
        Uint8Array.fromHex(kesVKey),
        counter,
        kesPeriod,
        Uint8Array.fromHex(signature),
      ],
      Uint8Array.fromHex(coldVKey),
    ]
  ).toHex();

  return JSON.stringify({
    "type": "NodeOperationalCertificate",
    "description": "",
    cborHex,
  }, null, 4);
}

function createKesSKeyFileContent(kesSKey) {
  const cborHex = encode(Uint8Array.fromHex(kesSKey)).toHex();

  return JSON.stringify({
   "type": "KesSigningKey_ed25519_kes_2^6",
    "description": "KES Signing Key",
    cborHex,
  }, null, 4);
}

function createTar(files: { name: string; content: string }[]): Uint8Array {
  const enc = new TextEncoder();
  const blocks: Uint8Array[] = [];

  for (const file of files) {
    const contentBytes = enc.encode(file.content);
    const header = new Uint8Array(512);

    // filename (offset 0, 100 bytes)
    header.set(enc.encode(file.name).slice(0, 100), 0);
    // mode (offset 100)
    header.set(enc.encode('0000644\0'), 100);
    // uid (offset 108)
    header.set(enc.encode('0000000\0'), 108);
    // gid (offset 116)
    header.set(enc.encode('0000000\0'), 116);
    // size in octal (offset 124, 12 bytes)
    header.set(enc.encode(contentBytes.length.toString(8).padStart(11, '0') + '\0'), 124);
    // mtime in octal (offset 136, 12 bytes)
    header.set(enc.encode(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0'), 136);
    // checksum placeholder — 8 spaces (offset 148)
    header.set(enc.encode('        '), 148);
    // type flag: regular file (offset 156)
    header[156] = 48; // '0'
    // ustar magic (offset 257)
    header.set(enc.encode('ustar\0'), 257);
    header.set(enc.encode('00'), 263);

    // compute and write checksum
    let checksum = 0;
    for (let i = 0; i < 512; i++) checksum += header[i];
    header.set(enc.encode(checksum.toString(8).padStart(6, '0') + '\0 '), 148);

    blocks.push(header);

    // file content padded to a multiple of 512
    const padded = new Uint8Array(Math.ceil(contentBytes.length / 512) * 512);
    padded.set(contentBytes);
    blocks.push(padded);
  }

  // end-of-archive: two zero blocks
  blocks.push(new Uint8Array(1024));

  const total = blocks.reduce((s, b) => s + b.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const b of blocks) { out.set(b, offset); offset += b.length; }
  return out;
}

function downloadTar(filename: string, files: { name: string; content: string }[]) {
  const data = createTar(files);
  const url = URL.createObjectURL(new Blob([data], { type: 'application/x-tar' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function App() {
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [internalPoolId, setInternalPoolId] = useState("");

  useEffect(() => {
    setStatus({ kind: "connecting" });
  }, []);

  async function connect() {
    setStatus({ kind: "connecting" });
    try {
      setStatus({ kind: "loading" });
      const exportColdPublicKeyResult = await fetchExtendedPublicKey();
      const poolId = derivePoolId(exportColdPublicKeyResult.publicKeyHex);
      console.log('poolId:', poolId);
      const ticker = await getPoolTicker(poolId);
      console.log('ticker:', ticker);
      const oldCounter = await getOpCertCounter(poolId);
      const poolCounter = oldCounter + 1;
      console.log('poolCounter:', poolCounter);

      const depth = 6; // 64 periods (Cardano mainnet)
      const seed = crypto.getRandomValues(new Uint8Array(32));
      const kes = genKeyKES(seed, depth);
      const kesVKey = Buffer.from(kes.verKey).toString('hex')
      const kesSKey = Buffer.from(kes.signKey).toString('hex')
      console.log('KES vkey', kesVKey);
      console.log('KES skey', kesSKey);
      
      const kesPeriod = getCurrentKesPeriod();

      const { signatureHex } = await fetchOpCertSignature(kesVKey, kesPeriod, poolCounter);
      console.log('operational certificate signature:', signatureHex);

      const nodeOpCertFileContent = createNodeOpCertFileContent(
        kesVKey,
        exportColdPublicKeyResult.publicKeyHex,
        kesPeriod,
        poolCounter,
        signatureHex
      );

      const kesSKeyFileContent = createKesSKeyFileContent(kesSKey);

      const downloadedFilename = `${internalPoolId}.tar`;
      downloadTar(downloadedFilename, [
        { name: 'node.cert', content: nodeOpCertFileContent },
        { name: 'kes.skey', content: kesSKeyFileContent },
      ]);

      setStatus({ kind: "success", poolId, ticker, downloadedFilename });
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

      {(status.kind === "idle" || status.kind === "connecting") && (
        <div style={styles.card}>
          <div style={styles.field}>
            <label style={styles.label} htmlFor="internalPoolId">Internal Pool ID</label>
            <input
              id="internalPoolId"
              style={styles.input}
              type="text"
              value={internalPoolId}
              onChange={e => setInternalPoolId(e.target.value)}
            />
          </div>

          <p style={styles.hint}>
            Connect your Ledger device, open the Cardano app, then click below.
          </p>

          <button
            style={{ ...styles.button, ...(internalPoolId.trim() === "" ? styles.buttonDisabled : {}) }}
            onClick={connect}
            disabled={internalPoolId.trim() === ""}
          >
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
          {status.ticker !== null && (
            <div style={styles.field}>
              <span style={styles.label}>Ticker</span>
              <code style={styles.value}>{status.ticker}</code>
            </div>
          )}
          <p style={styles.hint}>
            Please transfer the downloaded file <strong>{status.downloadedFilename}</strong> to the DevOps team.
          </p>
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
  input: {
    display: "block",
    width: "100%",
    boxSizing: "border-box",
    padding: "8px 10px",
    fontSize: 14,
    borderRadius: 4,
    border: "1px solid #d1d5db",
    outline: "none",
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
  buttonDisabled: {
    background: "#93c5fd",
    cursor: "not-allowed",
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
