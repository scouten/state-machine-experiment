import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { IncomingMessage, ServerResponse } from "node:http";

/** Ephemeral TEST ONLY keys/certificates and genuine signed OCSP responses. */
export function ocspFixtures(origin: string) {
  const directory = mkdtempSync(join(tmpdir(), "c2pa-m3-ocsp-"));
  const path = (name: string) => join(directory, name);
  const openssl = (...args: string[]) => execFileSync("openssl", args, { stdio: ["ignore", "pipe", "pipe"] });
  const modes = ["good", "revoked", "malformed", "unavailable", "slow", "slow-body", "oversize", "redirect", "no-cors"];
  const counts: Record<string, number> = {};
  try {
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", path("key.pem"));
    openssl("req", "-new", "-x509", "-key", path("key.pem"), "-out", path("root.pem"),
      "-days", "30", "-subj", "/CN=M3 TEST ONLY OCSP Root",
      "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
    openssl("req", "-new", "-key", path("key.pem"), "-out", path("leaf.csr"), "-subj", "/CN=M3 TEST ONLY OCSP Signer");
    const certs: Record<string, string> = {};
    for (const [index, mode] of modes.entries()) {
      writeFileSync(path("extensions"), [
        "basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature,nonRepudiation",
        "extendedKeyUsage=critical,emailProtection", "subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid",
        `authorityInfoAccess=OCSP;URI:${origin}/__m3/ocsp/${mode}${mode === "no-cors" ? "" : "?cors=1"}`,
      ].join("\n"));
      openssl("x509", "-req", "-in", path("leaf.csr"), "-CA", path("root.pem"), "-CAkey", path("key.pem"),
        "-set_serial", String(index + 1), "-days", "30", "-extfile", path("extensions"), "-out", path(`${mode}.pem`));
      certs[mode] = openssl("x509", "-in", path(`${mode}.pem`), "-outform", "DER").toString("base64");
      // The responder database is independent of certificate signature validation.
      writeFileSync(path(`${mode}.index`), `${mode === "revoked" ? "R" : "V"}\t271231235959Z\t${mode === "revoked" ? "260101000000Z" : ""}\t${(index + 1).toString(16).padStart(2, "0").toUpperCase()}\tunknown\t/CN=M3 TEST ONLY OCSP Signer\n`);
      openssl("ocsp", "-issuer", path("root.pem"), "-sha256", "-cert", path(`${mode}.pem`),
        "-no_nonce", "-reqout", path(`${mode}.request.der`));
      openssl("ocsp", "-index", path(`${mode}.index`), "-rsigner", path("root.pem"), "-rkey", path("key.pem"),
        "-CA", path("root.pem"), "-issuer", path("root.pem"), "-reqin", path(`${mode}.request.der`),
        "-respout", path(`${mode}.response.der`), "-ndays", "7", "-resp_no_certs");
      counts[mode] = 0;
    }
    const fixture = {
      origin, certs, now: Date.now() + 2000, root: readFileSync(path("root.pem"), "utf8"),
      rootDer: openssl("x509", "-in", path("root.pem"), "-outform", "DER").toString("base64"),
      key: readFileSync(path("key.pem"), "utf8"),
    };
    return {
      close() { rmSync(directory, { recursive: true }) },
      async handle(request: IncomingMessage, response: ServerResponse): Promise<boolean> {
        const url = new URL(request.url ?? "/", origin);
        if (!url.pathname.startsWith("/__m3/ocsp/")) return false;
        if (url.pathname.endsWith("/fixtures") || url.pathname.endsWith("/stats")) {
          response.setHeader("Content-Type", "application/json");
          response.end(JSON.stringify(url.pathname.endsWith("/fixtures") ? fixture : counts));
          return true;
        }
        const mode = url.pathname.slice("/__m3/ocsp/".length);
        if (!modes.includes(mode)) { response.writeHead(404).end(); return true }
        if (request.method === "OPTIONS") {
          if (url.searchParams.has("cors")) {
            response.setHeader("Access-Control-Allow-Origin", request.headers.origin ?? "");
            response.setHeader("Access-Control-Allow-Methods", "POST");
            response.setHeader("Access-Control-Allow-Headers", "content-type");
          }
          response.writeHead(204).end();
          return true;
        }
        if (url.searchParams.has("cors"))
          response.setHeader("Access-Control-Allow-Origin", request.headers.origin ?? "");
        if (request.method !== "POST" || request.headers["content-type"] !== "application/ocsp-request" ||
            request.headers.accept !== "application/ocsp-response") {
          response.writeHead(400).end("Expected OCSP POST");
          return true;
        }
        counts[mode]++;
        const chunks: Buffer[] = [];
        let size = 0;
        for await (const chunk of request) {
          size += chunk.length;
          if (size > 4096) { response.writeHead(413).end(); return true }
          chunks.push(Buffer.from(chunk));
        }
        writeFileSync(path("incoming.der"), Buffer.concat(chunks));
        const incoming = openssl("ocsp", "-reqin", path("incoming.der"), "-req_text", "-noverify").toString();
        const expected = openssl("ocsp", "-reqin", path(`${mode}.request.der`), "-req_text", "-noverify").toString();
        if (incoming !== expected) { response.writeHead(400).end("Wrong OCSP CertID"); return true }
        if (mode === "unavailable") { response.writeHead(503).end(); return true }
        if (mode === "redirect") { response.writeHead(302, { Location: "/__m3/ocsp/good" }).end(); return true }
        const bytes = mode === "malformed" ? Buffer.from("not DER") :
          mode === "oversize" ? Buffer.alloc(65537) : readFileSync(path(`${mode}.response.der`));
        response.setHeader("Content-Type", "application/ocsp-response");
        response.writeHead(200);
        if (mode === "slow-body") response.write(bytes.subarray(0, 1));
        const timer = setTimeout(() => response.end(mode === "slow-body" ? bytes.subarray(1) : bytes),
          mode.startsWith("slow") ? 250 : 0);
        response.on("close", () => clearTimeout(timer));
        return true;
      },
    };
  } catch (cause) {
    rmSync(directory, { recursive: true });
    throw cause;
  }
}
