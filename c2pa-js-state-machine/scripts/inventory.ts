import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { buildInventory, root } from "./contract.ts";

const inventory = buildInventory();
const output = JSON.stringify(inventory, null, 2) + "\n";
const path = join(root, "contracts/inventory.json");
if (process.argv.includes("--check")) {
  if (readFileSync(path, "utf8") !== output) throw new Error("Committed inventory differs from pinned source");
} else {
  mkdirSync(join(root, "contracts"), { recursive: true });
  writeFileSync(path, output);
}
console.log(`${inventory.tests.length} test declarations; ${inventory.surfaces.length} export surfaces; ${inventory.snapshots.length} source/fixture hashes.`);
