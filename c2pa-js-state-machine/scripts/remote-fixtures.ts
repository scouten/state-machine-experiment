import type { Plugin } from "vite";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { ocspFixtures } from "./ocsp-fixtures.ts";
import { timestampFixtures } from "./timestamp-fixtures.ts";

/** Loopback-only test endpoints; never part of the SDK transport. */
export function remoteFixtures(): Plugin {
  let fixtureServer: ReturnType<typeof createServer> | undefined;
  let ocsp: ReturnType<typeof ocspFixtures> | undefined;
  let tsa: ReturnType<typeof timestampFixtures> | undefined;
  return {
    name: "m3-remote-fixtures",
    async configureServer(server) {
      const stores = new Map<string, Buffer>();
      const requests = new Map<string, number>();
      let origin: string;
      const handle = async (request: IncomingMessage, response: ServerResponse, next: () => void) => {
        const path = request.url?.split("?")[0];
        if (!path?.startsWith("/__m3/")) return next();
        if (ocsp && await ocsp.handle(request, response)) return;
        if (tsa && await tsa.handle(request, response)) return;
        if (path === "/__m3/origin") {
          response.setHeader("Content-Type", "application/json");
          response.end(JSON.stringify({ origin }));
          return;
        }
        if (path === "/__m3/requests") {
          response.setHeader("Content-Type", "application/json");
          response.end(JSON.stringify(Object.fromEntries(requests)));
          return;
        }
        const url = new URL(request.url!, "http://localhost");
        if (url.searchParams.has("cors") && request.headers.origin)
          response.setHeader("Access-Control-Allow-Origin", request.headers.origin);
        if (request.method === "POST") {
          const chunks: Buffer[] = [];
          let size = 0;
          for await (const chunk of request) {
            size += chunk.length;
            if (size > 1024 * 1024) { response.writeHead(413).end(); return }
            chunks.push(Buffer.from(chunk));
          }
          stores.set(path, Buffer.concat(chunks));
          response.writeHead(204).end();
          return;
        }
        requests.set(path, (requests.get(path) ?? 0) + 1);
        if (url.searchParams.has("redirect")) {
          response.writeHead(302, { Location: "/__m3/should-not-fetch" }).end();
          return;
        }
        const bytes = stores.get(path);
        if (!bytes) { response.writeHead(404).end(); return }
        const delay = url.searchParams.has("slow") ? 200 : 0;
        response.setHeader("Content-Type", "application/octet-stream");
        if (!url.searchParams.has("chunked")) response.setHeader("Content-Length", bytes.length);
        response.writeHead(200);
        if (url.searchParams.has("slow-body")) {
          response.write(bytes.subarray(0, 1));
          const timer = setTimeout(() => response.end(bytes.subarray(1)), 200);
          response.on("close", () => clearTimeout(timer));
        } else {
          const timer = setTimeout(() => response.end(bytes), delay);
          response.on("close", () => clearTimeout(timer));
        }
      };
      const crossOrigin = createServer((request, response) => {
        void handle(request, response, () => { response.writeHead(404).end() })
          .catch((cause: unknown) => response.destroy(cause instanceof Error ? cause : new Error(String(cause))));
      });
      fixtureServer = crossOrigin;
      await new Promise<void>((resolve, reject) => {
        crossOrigin.once("error", reject);
        crossOrigin.listen(0, "127.0.0.1", resolve);
      });
      const address = crossOrigin.address();
      if (!address || typeof address === "string") throw new Error("Missing remote fixture server address");
      origin = `http://127.0.0.1:${address.port}`;
      try {
        ocsp = ocspFixtures(origin);
        tsa = timestampFixtures(origin);
      } catch (cause) {
        ocsp?.close();
        ocsp = undefined;
        crossOrigin.closeAllConnections();
        crossOrigin.close();
        throw cause;
      }
      server.middlewares.use((request, response, next) => {
        void handle(request, response, next).catch(next);
      });
    },
    async closeBundle() {
      if (!fixtureServer) return;
      const closing = fixtureServer;
      fixtureServer = undefined;
      closing.closeAllConnections();
      await new Promise<void>((resolve, reject) => {
        closing.close((error) => { if (error) reject(error); else resolve() });
      });
      ocsp?.close();
      ocsp = undefined;
      tsa?.close();
      tsa = undefined;
    },
  };
}
