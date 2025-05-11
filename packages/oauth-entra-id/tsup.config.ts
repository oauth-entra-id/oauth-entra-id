import { type Options, defineConfig } from 'tsup';

export default defineConfig((options: Options) => ({
  name: 'oauth-entra-id',
  entry: {
    index: 'src/exports/index.ts',
    express: 'src/exports/express.ts',
    nestjs: 'src/exports/nestjs.ts',
  },
  outDir: 'dist',
  format: ['cjs', 'esm'],
  clean: true,
  dts: true,
  sourcemap: true,
  treeshake: true,
  splitting: true,
  minify: false,
  cjsInterop: true,
  tsconfig: 'tsconfig.json',
  skipNodeModulesBundle: true,
  external: ['express', 'cookie-parser'],
  ...options,
}));
