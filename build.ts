import { type BuildOptions, build } from "esbuild";
import { dependencies } from "./package.json";

const entryFile = "src/index.ts";
const config: BuildOptions = {
  bundle: true,
  entryPoints: [entryFile],
  external: Object.keys(dependencies),
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
