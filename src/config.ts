import 'dotenv/config';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

export const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: Number(process.env.PORT || 3000),
  clientOrigins: Array.from(new Set([
    ...(process.env.CLIENT_ORIGINS || 'http://localhost:8100,http://localhost:8101,http://localhost:8102,http://localhost:4200,http://127.0.0.1:8100,http://127.0.0.1:8101,http://127.0.0.1:8102,http://127.0.0.1:4200,http://0.0.0.0:8101,http://0.0.0.0:8102').split(',').map(origin => origin.trim()).filter(Boolean),
    // Capacitor's bundled Android app origin; keep the explicit web origins above.
    'http://localhost',
    'https://localhost'
  ])),
  appJwtSecret: required('APP_JWT_SECRET'),
  xcodeBaseUrl: (process.env.XCODE_API_BASE_URL || 'https://xcodeappapi.xcode.com.my/api').replace(/\/$/, ''),
  xcodeAuthPath: process.env.XCODE_AUTH_PATH || 'JWTToken/Post',
  xcodeAuthPayload: process.env.XCODE_AUTH_PAYLOAD || ''
};
