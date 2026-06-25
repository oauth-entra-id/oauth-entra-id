import { defineConfig } from 'tsdown';

export default defineConfig({
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
  minify: false,
  cjsDefault: true,
  tsconfig: 'tsconfig.json',
  outExtensions: ({ format }) => ({ js: format === 'cjs' ? '.cjs' : '.js' }),
});
