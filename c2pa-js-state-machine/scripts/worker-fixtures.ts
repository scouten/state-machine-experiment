import type { Plugin } from "vite";

export function workerFixtures(): Plugin {
  return {
    name: "m3-worker-csp-fixtures",
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        const url = new URL(request.url ?? "/", "http://localhost");
        if (url.pathname !== "/__m3-worker-csp") return next();
        const allowed = url.searchParams.get("mode") === "allow";
        response.setHeader("Content-Type", "text/html");
        response.setHeader("Content-Security-Policy",
          `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; worker-src ${allowed ? "'self'" : "'none'"};`);
        response.end('<!doctype html><script type="module" src="/browser/csp-worker-page.ts"></script>');
      });
    },
  };
}
