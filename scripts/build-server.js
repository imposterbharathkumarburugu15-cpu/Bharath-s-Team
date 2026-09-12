import esbuild from 'esbuild';

async function buildServer() {
  try {
    await esbuild.build({
      entryPoints: ['server.ts'],
      bundle: true,
      platform: 'node',
      format: 'cjs',
      packages: 'external',
      sourcemap: true,
      outfile: 'dist/server.cjs',
    });
    console.log('✓ Server bundled to dist/server.cjs');
  } catch (err) {
    console.error('Server build error:', err);
    process.exit(1);
  }
}

buildServer();
