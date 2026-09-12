import { build as viteBuild } from 'vite';
import esbuild from 'esbuild';

async function main() {
  console.log('Building client with Vite...');
  await viteBuild();

  console.log('Building server with esbuild...');
  await esbuild.build({
    entryPoints: ['server.ts'],
    bundle: true,
    platform: 'node',
    format: 'cjs',
    packages: 'external',
    sourcemap: true,
    outfile: 'dist/server.cjs',
  });

  console.log('✓ Complete build successful.');
}

main().catch((err) => {
  console.error('Build failed:', err);
  process.exit(1);
});
