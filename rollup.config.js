import typescript from '@rollup/plugin-typescript';
import dts from 'rollup-plugin-dts';

const config = [
  {
    input : '.build/transpiled/index.js',
    output: {
      file: 'dist/thetyster-utils.js',
      format: 'es',
      sourcemap: true,
    },
    plugins: [typescript()]
  },
  {
    input: '.build/transpiled/index.d.ts',
    output: {
      file: 'dist/thetyster-utils.ts',
      format: 'es'
    },
    plugins: [dts()]
  }
];

export default config;
