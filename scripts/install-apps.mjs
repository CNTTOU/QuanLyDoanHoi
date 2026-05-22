import { spawnSync } from "node:child_process";

const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const apps = ["Loginqldoanhoi", "Quanlyhoatdong"];

for (const app of apps) {
  console.log(`Installing dependencies in ${app}...`);
  const result = spawnSync(npmCommand, ["install", "--no-audit", "--no-fund"], {
    cwd: app,
    stdio: "inherit",
    shell: process.platform === "win32",
  });

  if (result.error) {
    console.error(result.error);
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
