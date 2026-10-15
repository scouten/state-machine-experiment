import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { hash, pin, root, upstreamRoot } from "./contract.ts";

const cache = join(root, ".cache");
mkdirSync(cache, { recursive: true });
const archive = join(cache, "upstream.tar.gz");
if (!existsSync(archive)) {
  execFileSync("curl", [
    "--fail", "--location", "--silent", "--show-error", "--connect-timeout", "10", "--max-time", "120",
    `https://codeload.github.com/${pin.repository}/tar.gz/${pin.commit}`,
    "--output", archive,
  ], { stdio: "inherit" });
}
if (hash(readFileSync(archive)) !== pin.archiveSha256)
  throw new Error("Upstream archive checksum mismatch; refusing to extract");
const marker = join(upstreamRoot, ".contract-commit");
if (existsSync(upstreamRoot)) {
  if (!existsSync(marker) || readFileSync(marker, "utf8") !== pin.commit)
    throw new Error("Unexpected/partial upstream checkout; remove only .cache/upstream and retry");
} else {
  const entries = execFileSync("tar", ["-tzf", archive], { encoding: "utf8" }).trim().split("\n");
  if (entries.some((entry) => entry.startsWith("/") || entry.split("/").includes("..")))
    throw new Error("Unsafe upstream archive path");
  const staging = mkdtempSync(join(cache, "upstream-"));
  try {
    execFileSync("tar", ["-xzf", archive, "--strip-components=1", "-C", staging]);
    writeFileSync(join(staging, ".contract-commit"), pin.commit);
    renameSync(staging, upstreamRoot);
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}
console.log(`Prepared upstream ${pin.commit}; archive verified.`);
