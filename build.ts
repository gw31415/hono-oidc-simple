import { readFileSync } from "node:fs";
import { type BuildOptions, build } from "esbuild";

const dependencies =
  JSON.parse(readFileSync("package.json", "utf-8")).dependencies || {};
const peerDependencies =
  JSON.parse(readFileSync("package.json", "utf-8")).peerDependencies || {};
const entryFile = "src/index.ts";

const config: BuildOptions = {
  bundle: true,
  entryPoints: [entryFile],
  external: [...Object.keys(dependencies), ...Object.keys(peerDependencies)],
  logLevel: "info",
  minify: true,
  sourcemap: false,
};

build({
  ...config,
  format: "esm",
  outfile: "./dist/index.mjs",
  target: ["ES6"],
});

build({
  ...config,
  format: "cjs",
  outfile: "./dist/index.cjs",
  target: ["ES6"],
});
