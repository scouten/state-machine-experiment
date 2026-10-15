import { mkdirSync, readFileSync, rmSync, writeFileSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";
import { root, stateArtifacts } from "./contract.ts";

// The source harness stays unchanged; this private staging directory is the pack input.
stateArtifacts();
const directory = join(root, ".cache/package");
rmSync(directory, { recursive: true, force: true });
mkdirSync(join(directory, "dist"), { recursive: true });
const config = ts.readConfigFile(join(root, "tsconfig.json"), ts.sys.readFile);
if (config.error) throw new Error(ts.flattenDiagnosticMessageText(config.error.messageText, "\n"));
const parsed = ts.parseJsonConfigFileContent({
  ...config.config, include: ["src/**/*.ts"],
  compilerOptions: { ...config.config.compilerOptions, noEmit: false, declaration: true,
    rootDir: "src", outDir: ".cache/package/dist", rewriteRelativeImportExtensions: true },
}, ts.sys, root);
const program = ts.createProgram(parsed.fileNames, parsed.options);
const diagnostics = [...parsed.errors, ...ts.getPreEmitDiagnostics(program)];
if (diagnostics.length) throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
  getCurrentDirectory: () => root, getCanonicalFileName: (file) => file, getNewLine: () => "\n",
}));
const emitted = program.emit();
if (emitted.emitSkipped || emitted.diagnostics.length)
  throw new Error("Package TypeScript emission failed");
const entry = join(directory, "dist/index.js");
const source = readFileSync(entry, "utf8");
const generatedImport = '"../.cache/generated/state_machine.js"';
if (source.split(generatedImport).length !== 2) throw new Error("Expected exactly one generated bindings import");
writeFileSync(entry, source.replace(generatedImport, '"./state_machine.js"'));
for (const name of ["state_machine.js", "state_machine.d.ts", "state_machine_bg.wasm", "state_machine_bg.wasm.d.ts"])
  copyFileSync(join(root, ".cache/generated", name), join(directory, "dist", name));
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  name: string; version: string; devDependencies: Record<string, string>; engines: Record<string, string>;
};
const exported = (name: string) => ({ types: `./dist/${name}.d.ts`, import: `./dist/${name}.js` });
writeFileSync(join(directory, "package.json"), JSON.stringify({
  name: manifest.name, version: manifest.version, private: true, type: "module",
  description: "Private experimental sans-I/O C2PA browser migration prototype",
  engines: manifest.engines, files: ["dist"],
  exports: { "./inline": exported("index"), "./worker": exported("worker"),
    "./worker-entry": exported("worker-entry"), "./resources/state-machine.wasm": "./dist/state_machine_bg.wasm" },
  dependencies: { "@contentauth/c2pa-utilities": manifest.devDependencies["@contentauth/c2pa-utilities"] },
}, null, 2) + "\n");
console.log(`Built private package staging directory: ${directory}`);
