import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

export const root = dirname(dirname(fileURLToPath(import.meta.url)));
export const upstreamRoot = join(root, ".cache/upstream");
export const pin = JSON.parse(readFileSync(join(root, "upstream.json"), "utf8")) as {
  repository: string;
  commit: string;
  archiveSha256: string;
  legacyPackage: string;
  legacyVersion: string;
  legacyIntegrity: string;
  packages: string[];
  oracleTests: string[];
};

export function hash(bytes: string | Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function files(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name, "en"))
    .flatMap((entry) => {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`Unexpected source symlink: ${path}`);
      return entry.isDirectory() ? files(path) : [path];
    });
}

export interface TestCase {
  id: string;
  file: string;
  line: number;
  title: string;
  fullName: string;
  platform: "browser" | "node";
  parameterized: boolean;
  sourceMode: string;
}

function callName(expression: ts.Expression): { base: string; modifiers: string[] } {
  if (ts.isIdentifier(expression)) return { base: expression.text, modifiers: [] };
  if (ts.isPropertyAccessExpression(expression)) {
    const inner = callName(expression.expression);
    return { base: inner.base, modifiers: [...inner.modifiers, expression.name.text] };
  }
  if (ts.isCallExpression(expression)) return callName(expression.expression);
  return { base: "", modifiers: [] };
}

export function extractTests(text: string, file: string): TestCase[] {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const cases: TestCase[] = [];
  function visit(node: ts.Node, suites: string[], parameterized: boolean, suiteModes: string[]): void {
    if (ts.isCallExpression(node)) {
      const { base, modifiers } = callName(node.expression);
      const titleNode = node.arguments[0];
      const callback = node.arguments.find((argument) =>
        ts.isArrowFunction(argument) || ts.isFunctionExpression(argument));
      const isSuite = base === "describe" || base === "suite";
      const isTest = base === "test" || base === "it";
      const builder = ts.isPropertyAccessExpression(node.expression) &&
        ["each", "skipIf", "runIf"].includes(node.expression.name.text);
      const inlineCallback = callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback));
      if (!builder && titleNode && (isTest || isSuite && inlineCallback)) {
        const literal = ts.isStringLiteralLike(titleNode);
        const title = literal ? titleNode.text : titleNode.getText(source);
        const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
        const dynamic = parameterized || modifiers.includes("each") || !literal;
        if (isTest) {
          cases.push({
            id: `${file}:${line}`,
            file, line, title, fullName: [...suites, title].join(" "),
            platform: file.includes("/c2pa-web/") ? "browser" : "node",
            parameterized: dynamic,
            sourceMode: [...new Set([...suiteModes, ...modifiers.filter((m) => m !== "each"),
              ...(!inlineCallback && node.arguments.length === 1 ? ["todo"] : [])])].join(".") || "normal",
          });
          return;
        }
        if (callback) visit(callback, [...suites, title], dynamic,
          [...suiteModes, ...modifiers.filter((m) => m !== "each")]);
        return;
      }
    }
    const loop = ts.isForStatement(node) || ts.isForOfStatement(node) || ts.isForInStatement(node);
    ts.forEachChild(node, (child) => visit(child, suites, parameterized || loop, suiteModes));
  }
  visit(source, [], false, []);
  return cases;
}

function declarations(text: string, file: string) {
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  return source.statements.flatMap((node) => {
    if (ts.isExportDeclaration(node)) return [{ declaration: node.getText(source), members: [] as string[] }];
    if (!ts.canHaveModifiers(node) || !ts.getModifiers(node)?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) return [];
    const named = ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node) ||
      ts.isFunctionDeclaration(node) || ts.isEnumDeclaration(node) ||
      ts.isTypeAliasDeclaration(node) || ts.isModuleDeclaration(node);
    const name = named ? node.name?.getText(source) : undefined;
    const declaration = name ?? (ts.isVariableStatement(node)
      ? node.declarationList.declarations.map((d) => d.name.getText(source)).join(", ")
      : ts.SyntaxKind[node.kind]);
    const members = ts.isClassDeclaration(node) || ts.isInterfaceDeclaration(node)
      ? node.members.filter((member) =>
        !(member.name && ts.isPrivateIdentifier(member.name)) &&
        !(ts.canHaveModifiers(member) && ts.getModifiers(member)?.some((m) =>
          m.kind === ts.SyntaxKind.PrivateKeyword || m.kind === ts.SyntaxKind.ProtectedKeyword)))
        .map((member) => member.name?.getText(source) ?? "constructor")
      : [];
    return [{ declaration, members }];
  });
}

export function buildInventory(directory = upstreamRoot) {
  const sourceFiles = pin.packages.flatMap((name) => files(join(directory, "packages", name)));
  const tests = sourceFiles.filter((file) => /\.(spec|test)\.[cm]?[jt]sx?$/.test(file))
    .flatMap((file) => extractTests(readFileSync(file, "utf8"), relative(directory, file)));
  if (tests.length === 0 || new Set(tests.map((t) => t.id)).size !== tests.length)
    throw new Error("Empty or duplicate contract inventory");
  const snapshots = sourceFiles.map((file) => ({
    file: relative(directory, file), sha256: hash(readFileSync(file)),
  }));
  const surfaces = sourceFiles.filter((file) =>
    /\.[cm]?[jt]sx?$/.test(file) && !/\.(spec|test)\./.test(file))
    .map((file) => ({
      file: relative(directory, file),
      exports: declarations(readFileSync(file, "utf8"), file),
    })).filter((surface) => surface.exports.length > 0);
  const packages = pin.packages.map((name) => ({
    name,
    manifest: JSON.parse(readFileSync(join(directory, "packages", name, "package.json"), "utf8")) as unknown,
  }));
  const provenance = ["LICENSE", "pnpm-lock.yaml"].map((file) => ({
    file, sha256: hash(readFileSync(join(directory, file))),
  }));
  for (const title of pin.oracleTests) {
    const matches = tests.filter((t) => t.file === "packages/c2pa-web/src/lib/reader.spec.ts" && t.title === title);
    if (matches.length !== 1 || matches[0].parameterized || matches[0].sourceMode !== "normal")
      throw new Error(`Oracle selection must identify exactly one ordinary test: ${title}`);
  }
  const publishedTypes = legacyArtifacts().filter((file) => file.file.endsWith(".d.ts"));
  return { schemaVersion: 1, upstream: pin, packages, provenance, surfaces, publishedTypes, snapshots, tests };
}

export type Inventory = ReturnType<typeof buildInventory>;

export function loadInventory(): Inventory {
  return JSON.parse(readFileSync(join(root, "contracts/inventory.json"), "utf8")) as Inventory;
}

export interface Observation {
  id: string;
  status: "passed" | "failed";
}

export function parityReport(inventory: Inventory, observations: Observation[] = [], stateObservations: Observation[] = []) {
  if (inventory.tests.length === 0) throw new Error("Cannot report parity for an empty inventory");
  const valid = new Set(inventory.tests.map((test) => test.id));
  const seen = new Set<string>();
  for (const results of [observations, stateObservations]) {
    seen.clear();
    for (const result of results) {
    if (!valid.has(result.id) || seen.has(result.id) || !["passed", "failed"].includes(result.status))
      throw new Error(`Invalid or duplicate observation: ${result.id}`);
    seen.add(result.id);
    if (inventory.tests.find((test) => test.id === result.id)?.parameterized)
      throw new Error("Parameterized contracts need instance-level expansion before accepting observations");
    }
  }
  const tests = inventory.tests.map((test) => ({
    ...test,
    legacy: observations.find((o) => o.id === test.id)?.status ?? "not_run",
    stateMachine: stateObservations.find((o) => o.id === test.id)?.status ?? "unported",
    blocker: stateObservations.some((o) => o.id === test.id) ? undefined : "Outside the implemented M1 compatibility slice",
  }));
  return {
    upstreamCommit: inventory.upstream.commit,
    inventorySha256: hash(JSON.stringify(inventory)),
    denominator: tests.length,
    legacy: {
      passed: observations.filter((o) => o.status === "passed").length,
      failed: observations.filter((o) => o.status === "failed").length,
      notRun: tests.length - observations.length,
    },
    stateMachine: {
      passed: stateObservations.filter((o) => o.status === "passed").length,
      failed: stateObservations.filter((o) => o.status === "failed").length,
      unported: tests.length - stateObservations.length,
    },
    fullParity: tests.every((test) => test.stateMachine === "passed"),
    tests,
  };
}

export function legacyArtifacts() {
  return [pin.legacyPackage, "@contentauth/c2pa-wasm", "@contentauth/c2pa-utilities", "@contentauth/c2pa-types"]
    .flatMap((name) => files(join(root, "node_modules", name)))
    .filter((file) => /\.(js|wasm|d\.ts)$/.test(file) || file.endsWith("/package.json"))
    .map((file) => ({ file: relative(join(root, "node_modules"), file), sha256: hash(readFileSync(file)) }));
}

export function harnessFingerprint(): string {
  const inputs = ["scripts", "browser", "test", "src"]
    .filter((name) => existsSync(join(root, name)))
    .flatMap((name) => files(join(root, name)));
  inputs.push(...["package.json", "tsconfig.json", "vitest.config.ts", "upstream.json"].map((name) => join(root, name)));
  return hash(JSON.stringify(inputs.sort().map((file) => ({
    file: relative(root, file), sha256: hash(readFileSync(file)),
  }))));
}

export function stateSources() {
  const repository = dirname(root);
  const inputs = readdirSync(repository, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("contentauth-"))
    .flatMap((entry) => {
      const directory = join(repository, entry.name);
      return [join(directory, "Cargo.toml"), ...files(join(directory, "src")).filter((file) => file.endsWith(".rs"))];
    });
  inputs.push(join(repository, "Cargo.toml"), join(repository, "Cargo.lock"));
  inputs.push(
    join(repository, "contentauth-c2pa-reader/tests/fixtures/C.jpg"),
    join(repository, "contentauth-c2pa-builder/tests/fixtures/test-signer.der"),
    join(repository, "contentauth-c2pa-builder/tests/fixtures/test-signer.key.pem"),
  );
  return inputs.sort().map((file) => ({ file: relative(repository, file), sha256: hash(readFileSync(file)) }));
}

export function stateArtifacts() {
  const directory = join(root, ".cache/generated");
  const build = JSON.parse(readFileSync(join(directory, "build.json"), "utf8")) as { sources: ReturnType<typeof stateSources> };
  if (JSON.stringify(build.sources) !== JSON.stringify(stateSources()))
    throw new Error("State-machine build is stale; rerun build:wasm");
  return files(directory).map((file) => ({ file: relative(root, file), sha256: hash(readFileSync(file)) }));
}

export interface EvidenceFingerprint {
  inventorySha256: string;
  lockSha256: string;
  harnessSha256: string;
  artifactsSha256: string;
}
export function assertFreshEvidence(actual: EvidenceFingerprint, expected: EvidenceFingerprint): void {
  for (const key of ["inventorySha256", "lockSha256", "harnessSha256", "artifactsSha256"] as const)
    if (actual[key] !== expected[key]) throw new Error(`Stale oracle evidence (${key}); rerun the browser proof`);
}
