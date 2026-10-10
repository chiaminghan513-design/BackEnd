import axios, { AxiosInstance } from 'axios';
import { config } from './config.js';

type TokenCache = { value: string; expiresAt: number } | undefined;
let tokenCache: TokenCache;

function tokenFrom(response: unknown): string | undefined {
  if (typeof response === 'string') return response;
  if (!response || typeof response !== 'object') return undefined;
  const data = response as Record<string, unknown>;
  for (const [key, value] of Object.entries(data)) {
    if (['successtoken', 'access_token', 'accesstoken', 'token', 'jwt'].includes(key.toLowerCase()) && typeof value === 'string') {
      return value;
    }
  }
  if (data.data) return tokenFrom(data.data);
  return undefined;
}

export class XcodeClient {
  private readonly http: AxiosInstance;

  constructor() {
    this.http = axios.create({ baseURL: config.xcodeBaseUrl, timeout: 15_000 });
  }

  private async getToken(): Promise<string> {
    if (tokenCache && tokenCache.expiresAt > Date.now()) return tokenCache.value;
    if (!config.xcodeAuthPayload) throw new Error('XCODE_AUTH_PAYLOAD has not been configured.');

    const params = JSON.parse(config.xcodeAuthPayload) as Record<string, string>;
    // Swagger documents JWTToken/Post with UserName and Password as query parameters.
    const response = await this.http.post(config.xcodeAuthPath, '', { params });
    const token = tokenFrom(response.data);
    if (!token) {
      const keys = response.data && typeof response.data === 'object' ? Object.keys(response.data as object).join(', ') : typeof response.data;
      throw new Error(`The Xcode token response did not contain a recognised token field (received: ${keys || 'empty response'}).`);
    }

    // The API does not document the token expiry. Refresh conservatively every 50 minutes.
    tokenCache = { value: token, expiresAt: Date.now() + 50 * 60 * 1000 };
    return token;
  }

  async get<T>(path: string): Promise<T> {
    const token = await this.getToken();
    const response = await this.http.get<T>(path, { headers: { Authorization: `Bearer ${token}` } });
    return response.data;
  }

  async post<T>(path: string, body: unknown): Promise<T> {
    const token = await this.getToken();
    const response = await this.http.post<T>(path, body, { headers: { Authorization: `Bearer ${token}` } });
    return response.data;
  }

  async postPublic<T>(path: string, body: unknown): Promise<T> {
    const response = await this.http.post<T>(path, body);
    return response.data;
  }
}

export const xcode = new XcodeClient();
