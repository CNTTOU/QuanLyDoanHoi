import { spawnSync } from "node:child_process";
import { cp, readFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";

const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const shell = process.platform === "win32";
const apps = [
  {
    name: "Loginqldoanhoi",
    output: "login",
    env: {
      VITE_APP_BASE_PATH: "/login/",
      VITE_ADMIN_APP_URL: "/hoat-dong",
    },
  },
  {
    name: "Quanlyhoatdong",
    output: "hoat-dong",
    env: {
      VITE_APP_BASE_PATH: "/hoat-dong/",
      VITE_LOGIN_APP_URL: "/login/",
      VITE_GATEWAY_API_BASE: "",
    },
  },
];

function run(command, args, cwd, env = {}) {
  const label = [command, ...args].join(" ");
  console.log(`Running ${label} in ${cwd}...`);
  const result = spawnSync(command, args, {
    cwd,
    env: { ...process.env, ...env },
    stdio: "inherit",
    shell,
  });

  if (result.error) console.error(result.error);
  if (result.status !== 0) process.exit(result.status ?? 1);
}

for (const app of apps) {
  run(npmCommand, ["install", "--no-audit", "--no-fund"], app.name);
  run(npmCommand, ["run", "build"], app.name, app.env);
}

const root = process.cwd();
const outputDir = join(root, "dist");

await rm(outputDir, { recursive: true, force: true });
for (const app of apps) {
  await cp(join(root, app.name, "dist"), join(outputDir, app.output), {
    recursive: true,
  });
}

async function assertReferencedAssets(appOutput) {
  const indexPath = join(outputDir, appOutput, "index.html");
  const html = await readFile(indexPath, "utf8");
  const references = Array.from(
    html.matchAll(/(?:src|href)="\/([^"]+\.(?:js|css))"/g),
    (match) => match[1],
  );

  for (const reference of references) {
    const assetPath = join(outputDir, ...reference.split("/"));
    try {
      await stat(assetPath);
    } catch {
      throw new Error(
        `Missing asset referenced by ${appOutput}/index.html: /${reference}`,
      );
    }
  }
}

for (const app of apps) {
  await assertReferencedAssets(app.output);
}

console.log("Prepared Vercel static output in dist/.");
