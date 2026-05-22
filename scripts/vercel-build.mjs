import { spawnSync } from "node:child_process";
import { cp, rm } from "node:fs/promises";
import { join } from "node:path";

const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const shell = process.platform === "win32";
const apps = [
  { name: "Loginqldoanhoi", output: "login" },
  { name: "Quanlyhoatdong", output: "hoat-dong" },
];

function run(command, args, cwd) {
  const label = [command, ...args].join(" ");
  console.log(`Running ${label} in ${cwd}...`);
  const result = spawnSync(command, args, {
    cwd,
    stdio: "inherit",
    shell,
  });

  if (result.error) console.error(result.error);
  if (result.status !== 0) process.exit(result.status ?? 1);
}

for (const app of apps) {
  run(npmCommand, ["install", "--no-audit", "--no-fund"], app.name);
  run(npmCommand, ["run", "build"], app.name);
}

const root = process.cwd();
const outputDir = join(root, "dist");

await rm(outputDir, { recursive: true, force: true });
for (const app of apps) {
  await cp(join(root, app.name, "dist"), join(outputDir, app.output), {
    recursive: true,
  });
}

console.log("Prepared Vercel static output in dist/.");
