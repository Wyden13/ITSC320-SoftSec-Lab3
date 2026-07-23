/* ============================================================
 * SECURITY FIX (Insecure Code Practices): TypeScript module
 * declaration for the `@env` virtual module provided by the
 * react-native-dotenv babel plugin. Lets us import secrets in a
 * type-safe way instead of hardcoding them. See REPORT.md II-E.
 * ============================================================ */
declare module '@env' {
  export const NOTES_ENC_KEY: string;
  export const API_KEY: string;
  export const API_SECRET: string;
}
