module.exports = {
  bracketSpacing: true,
  bracketSameLine: true,
  singleQuote: true,
  jsxSingleQuote: true,
  trailingComma: 'es5',
  semi: true,
  printWidth: 110,
  arrowParens: 'always',
  overrides: [
    {
      files: ['tsconfig.json', 'tsconfig.test.json', 'jsconfig.json'],
      options: {
        parser: 'jsonc',
      },
    },
  ],
};
