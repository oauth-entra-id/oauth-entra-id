import { defineConfig, type Options } from 'tsup';

export default defineConfig((options: Options) => ({
  name: 'oauth-azure-ad',
  entry: {
    index: 'src/index.ts',
    express: 'src/express.ts',
    nestjs: 'src/nestjs.ts',
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
