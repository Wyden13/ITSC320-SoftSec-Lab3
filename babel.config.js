module.exports = {
  presets: ['module:@react-native/babel-preset'],
  /* ============================================================
   * SECURITY FIX (Insecure Code Practices): register the
   * react-native-dotenv plugin so secrets can be imported from a
   * git-ignored `.env` via `import { ... } from '@env'` instead of
   * being hardcoded in source. See REPORT.md II-E.
   * ============================================================ */
  plugins: [
    [
      'module:react-native-dotenv',
      {
        moduleName: '@env',
        path: '.env',
        safe: false,
        allowUndefined: false,
      },
    ],
  ],
};
