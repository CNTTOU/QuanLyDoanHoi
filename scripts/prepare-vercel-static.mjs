import { cp, rm } from "node:fs/promises";
import { join } from "node:path";

const root = process.cwd();
const outputDir = join(root, "dist");

await rm(outputDir, { recursive: true, force: true });
await cp(join(root, "Loginqldoanhoi", "dist"), join(outputDir, "login"), {
  recursive: true,
});
await cp(join(root, "Quanlyhoatdong", "dist"), join(outputDir, "hoat-dong"), {
  recursive: true,
});

console.log("Prepared Vercel static output in dist/.");
