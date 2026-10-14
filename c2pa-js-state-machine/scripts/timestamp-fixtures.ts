import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { IncomingMessage, ServerResponse } from "node:http";

/** Loopback-only RFC 3161 authority with ephemeral TEST ONLY credentials. */
export function timestampFixtures(origin: string) {
  const directory = mkdtempSync(join(tmpdir(), "c2pa-m3-tsa-"));
  const path = (name: string) => join(directory, name);
  const openssl = (...args: string[]) => execFileSync("openssl", args, { stdio: ["ignore", "pipe", "pipe"] });
  const counts: Record<string, number> = { good: 0, refused: 0, malformed: 0, mismatch: 0 };
  try {
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", path("root.key"));
    openssl("req", "-new", "-x509", "-key", path("root.key"), "-out", path("root.pem"),
      "-days", "30", "-subj", "/CN=M3 TEST ONLY Timestamp Root",
      "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
    for (const name of ["signer", "tsa"]) {
      if (name === "signer")
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", path(`${name}.key`));
      else openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", path(`${name}.key`));
      openssl("req", "-new", "-key", path(`${name}.key`), "-out", path(`${name}.csr`),
        "-subj", `/CN=M3 TEST ONLY ${name}`);
      writeFileSync(path("extensions"), [
        "basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature",
        `extendedKeyUsage=critical,${name === "tsa" ? "timeStamping" : "emailProtection"}`,
        "subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid",
      ].join("\n"));
      openssl("x509", "-req", "-in", path(`${name}.csr`), "-CA", path("root.pem"), "-CAkey", path("root.key"),
        "-set_serial", name === "tsa" ? "2" : "1", "-days", "30", "-extfile", path("extensions"),
        "-out", path(`${name}.pem`));
    }
    writeFileSync(path("serial"), "01\n");
    writeFileSync(path("tsa.cnf"), [
      "[tsa]", "default_tsa=local", "[local]", `serial=${path("serial")}`,
      `signer_cert=${path("tsa.pem")}`, `certs=${path("root.pem")}`, `signer_key=${path("tsa.key")}`,
      "signer_digest=sha256", "default_policy=1.2.3.4.1", "digests=sha256",
      "accuracy=secs:1", "ordering=yes", "tsa_name=yes", "ess_cert_id_chain=no",
      "ess_cert_id_alg=sha256",
    ].join("\n"));
    const fixture = {
      origin, now: Date.now() + 2000, root: readFileSync(path("root.pem"), "utf8"),
      cert: openssl("x509", "-in", path("signer.pem"), "-outform", "DER").toString("base64"),
      rootDer: openssl("x509", "-in", path("root.pem"), "-outform", "DER").toString("base64"),
      key: readFileSync(path("signer.key"), "utf8"),
    };
    return {
      close() { rmSync(directory, { recursive: true }) },
      async handle(request: IncomingMessage, response: ServerResponse): Promise<boolean> {
        const url = new URL(request.url ?? "/", origin);
        if (!url.pathname.startsWith("/__m3/tsa/")) return false;
        const mode = url.pathname.slice("/__m3/tsa/".length);
        if (mode === "fixtures" || mode === "stats") {
          response.setHeader("Content-Type", "application/json");
          response.end(JSON.stringify(mode === "fixtures" ? fixture : counts));
          return true;
        }
        if (!Object.hasOwn(counts, mode)) { response.writeHead(404).end(); return true }
        if (request.method !== "POST" || request.headers["content-type"] !== "application/timestamp-query" ||
            request.headers.accept !== "application/timestamp-reply") {
          response.writeHead(400).end("Expected RFC 3161 POST");
          return true;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        for await (const chunk of request) {
          size += chunk.length;
          if (size > 4096) { response.writeHead(413).end(); return true }
          chunks.push(Buffer.from(chunk));
        }
        const incoming = Buffer.concat(chunks);
        writeFileSync(path("request.der"), incoming);
        const text = openssl("ts", "-query", "-in", path("request.der"), "-text").toString();
        if (!text.includes("Hash Algorithm: sha256") || !text.includes("Certificate required: yes")) {
          response.writeHead(400).end("Expected SHA-256 request with certificates");
          return true;
        }
        counts[mode]++;
        response.setHeader("Content-Type", "application/timestamp-reply");
        if (mode === "refused") {
          // TimeStampResp with PKIStatus rejection and no token.
          response.end(Buffer.from([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02]));
        } else if (mode === "malformed") response.end(Buffer.from("not a timestamp"));
        else {
          if (mode === "mismatch")
            writeFileSync(path("request.der"), openssl("ts", "-query", "-digest", "00".repeat(32), "-sha256", "-cert"));
          openssl("ts", "-reply", "-config", path("tsa.cnf"), "-queryfile", path("request.der"),
            "-out", path("reply.der"));
          openssl("ts", "-verify", "-queryfile", path("request.der"), "-in", path("reply.der"),
            "-CAfile", path("root.pem"), "-untrusted", path("tsa.pem"));
          response.end(readFileSync(path("reply.der")));
        }
        return true;
      },
    };
  } catch (cause) {
    rmSync(directory, { recursive: true });
    throw cause;
  }
}
