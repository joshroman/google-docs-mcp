import { google } from 'googleapis';
import { OAuth2Client, Credentials } from 'google-auth-library';
import * as fs from 'fs/promises';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { createServer, IncomingMessage, ServerResponse } from 'http';
import { parse as parseUrl } from 'url';
import { parse as parseQueryString } from 'querystring';
import { spawn } from 'child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const REDIRECT_URI = 'http://localhost:4100/code';
const SCOPES = [
  'openid',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/documents',
  'https://www.googleapis.com/auth/spreadsheets',
  'https://www.googleapis.com/auth/drive'
];

export interface AccountInfo {
  email: string;
  accountType: string;
  extraInfo?: string;
  gauthFile?: string;

  toDescription(): string;
}

interface ServerConfig {
  gauthFile: string;
  accountsFile: string;
  credentialsDir: string;
}

class AccountInfoImpl implements AccountInfo {
  constructor(
    public email: string,
    public accountType: string,
    public extraInfo: string = '',
    public gauthFile?: string
  ) {}

  toDescription(): string {
    return `Account for email: ${this.email} of type: ${this.accountType}. Extra info: ${this.extraInfo}`;
  }
}

export class GetCredentialsError extends Error {
  constructor(public authorizationUrl: string) {
    super('Error getting credentials');
  }
}

export class CodeExchangeError extends GetCredentialsError {}
export class NoRefreshTokenError extends GetCredentialsError {}
export class NoUserIdError extends Error {}
export class AuthInProgressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthInProgressError';
  }
}

class OAuthCallbackServer {
  private server: ReturnType<typeof createServer>;
  private resolveAuth!: (code: string) => void;
  private rejectAuth!: (error: Error) => void;
  private authPromise: Promise<string>;

  constructor() {
    this.authPromise = new Promise((resolve, reject) => {
      this.resolveAuth = resolve;
      this.rejectAuth = reject;
    });
    this.server = createServer(this.handleRequest.bind(this));
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse) {
    const url = parseUrl(req.url || '');
    if (url.pathname !== '/code') {
      res.writeHead(404);
      res.end();
      return;
    }

    const query = parseQueryString(url.query || '');
    if (!query.code) {
      res.writeHead(400);
      res.end('Missing authorization code');
      this.rejectAuth(new Error('Missing authorization code'));
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.write('<html><body><h1>Authorization successful!</h1><p>You can close this tab.</p></body></html>');
    res.end();

    this.resolveAuth(query.code as string);
    this.server.close();
  }

  async listen(port: number = 4100): Promise<string> {
    return new Promise((resolve, reject) => {
      this.server.listen(port, () => {
        console.error(`OAuth callback server listening on port ${port}`);
        this.authPromise.then(resolve).catch(reject);
      });
      this.server.on('error', reject);
    });
  }
}

export class GAuthService {
  private oauth2Clients: Map<string, OAuth2Client> = new Map();
  private config: ServerConfig;
  private accountsInfo: AccountInfo[] = [];

  constructor(config: ServerConfig) {
    this.config = config;
  }

  getConfig(): ServerConfig {
    return this.config;
  }

  async initialize(): Promise<void> {
    // Load accounts first to get OAuth configs
    this.accountsInfo = await this.getAccountInfo();

    if (this.accountsInfo.length === 0) {
      throw new Error('No accounts configured. Please create .accounts.json with at least one account.');
    }

    // Initialize OAuth clients for each account
    for (const account of this.accountsInfo) {
      try {
        // Use account-specific gauth file if provided, otherwise fall back to default
        const gauthFile = account.gauthFile || this.config.gauthFile;
        // Use the path directly if absolute, otherwise resolve relative to cwd
        const gauthPath = path.isAbsolute(gauthFile)
          ? gauthFile
          : path.resolve(process.cwd(), gauthFile);
        const gauthData = await fs.readFile(gauthPath, 'utf8');
        const credentials = JSON.parse(gauthData);

        if (!credentials.installed && !credentials.web) {
          throw new Error(`Invalid OAuth2 credentials format in gauth file for ${account.email}`);
        }

        const key = credentials.installed || credentials.web;
        const oauth2Client = new google.auth.OAuth2(
          key.client_id,
          key.client_secret,
          REDIRECT_URI
        );

        this.oauth2Clients.set(account.email, oauth2Client);
        console.error(`Initialized OAuth2 client for ${account.email}`);
      } catch (error) {
        console.error(`Failed to initialize OAuth2 client for ${account.email}: ${(error as Error).message}`);
      }
    }

    if (this.oauth2Clients.size === 0) {
      throw new Error('Failed to initialize any OAuth2 clients. Check your gauth files.');
    }
  }

  getClient(userId: string): OAuth2Client {
    const client = this.oauth2Clients.get(userId);
    if (!client) {
      const available = Array.from(this.oauth2Clients.keys()).join(', ');
      throw new Error(`OAuth2 client not found for user: ${userId}. Available: ${available || 'none'}`);
    }
    return client;
  }

  getAccountList(): AccountInfo[] {
    return this.accountsInfo;
  }

  private getCredentialFilename(userId: string): string {
    return path.join(this.config.credentialsDir, `.oauth2.${userId}.json`);
  }

  async getAccountInfo(): Promise<AccountInfo[]> {
    try {
      // Use the path directly if absolute, otherwise resolve relative to cwd
      const accountsPath = path.isAbsolute(this.config.accountsFile)
        ? this.config.accountsFile
        : path.resolve(process.cwd(), this.config.accountsFile);
      const data = await fs.readFile(accountsPath, 'utf8');
      const { accounts } = JSON.parse(data);

      if (!Array.isArray(accounts)) {
        throw new Error('Invalid accounts format in accounts file');
      }

      return accounts.map((acc: any) => new AccountInfoImpl(
        acc.email,
        acc.account_type,
        acc.extra_info,
        acc.gauth_file
      ));
    } catch (error) {
      console.error('Error reading accounts file:', error);
      return [];
    }
  }

  async getStoredCredentials(userId: string): Promise<OAuth2Client | null> {
    const oauth2Client = this.getClient(userId);
    if (!oauth2Client) {
      return null;
    }

    try {
      const credFilePath = this.getCredentialFilename(userId);
      const data = await fs.readFile(credFilePath, 'utf8');
      const credentials = JSON.parse(data);
      oauth2Client.setCredentials(credentials);
      return oauth2Client;
    } catch (error) {
      console.warn(`No stored OAuth2 credentials yet for user: ${userId}`);
      return null;
    }
  }

  async storeCredentials(client: OAuth2Client, userId: string): Promise<void> {
    const credFilePath = this.getCredentialFilename(userId);
    await fs.mkdir(path.dirname(credFilePath), { recursive: true });
    await fs.writeFile(credFilePath, JSON.stringify(client.credentials, null, 2));
    console.error(`Stored credentials for ${userId} at ${credFilePath}`);
  }

  async exchangeCode(authorizationCode: string, userId: string): Promise<OAuth2Client> {
    const oauth2Client = this.getClient(userId);
    if (!oauth2Client) {
      throw new Error('OAuth2 client not initialized. Call initialize() first.');
    }

    try {
      const { tokens } = await oauth2Client.getToken(authorizationCode);
      oauth2Client.setCredentials(tokens);
      return oauth2Client;
    } catch (error) {
      console.error('Error exchanging code:', error);
      throw new CodeExchangeError('');
    }
  }

  async getUserInfo(client: OAuth2Client): Promise<any> {
    const oauth2 = google.oauth2({ version: 'v2', auth: client });
    try {
      const { data } = await oauth2.userinfo.get();
      if (data && data.id) {
        return data;
      }
      throw new NoUserIdError();
    } catch (error) {
      console.error('Error getting user info:', error);
      throw error;
    }
  }

  async getAuthorizationUrl(emailAddress: string): Promise<string> {
    const oauth2Client = this.getClient(emailAddress);
    if (!oauth2Client) {
      throw new Error(`OAuth2 client not initialized for user: ${emailAddress}`);
    }

    return oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: SCOPES,
      prompt: 'consent',
      login_hint: emailAddress
    });
  }

  async startAuthFlow(userId: string): Promise<void> {
    const authUrl = await this.getAuthorizationUrl(userId);
    console.error(`\n=== Authorization required for ${userId} ===`);
    console.error(`Opening browser for authorization...`);

    // Start OAuth callback server
    const callbackServer = new OAuthCallbackServer();

    // Open browser
    spawn('open', [authUrl], { stdio: 'ignore' });

    try {
      // Wait for callback
      const code = await callbackServer.listen(4100);

      // Exchange code for tokens
      const client = await this.exchangeCode(code, userId);
      const userInfo = await this.getUserInfo(client);

      if (userInfo.email !== userId) {
        console.warn(`Warning: Authorized email ${userInfo.email} differs from expected ${userId}`);
      }

      if (client.credentials.refresh_token) {
        await this.storeCredentials(client, userId);
        console.error(`Authorization complete for ${userId}`);
      } else {
        throw new Error('No refresh token received. Try revoking app access and re-authorizing.');
      }
    } catch (error) {
      console.error(`Authorization failed for ${userId}:`, error);
      throw error;
    }
  }

  async ensureAuthorized(userId: string): Promise<OAuth2Client> {
    // Check if account exists
    const account = this.accountsInfo.find(a => a.email === userId);
    if (!account) {
      const available = this.accountsInfo.map(a => a.email).join(', ');
      throw new Error(`Account ${userId} not configured. Available accounts: ${available || 'none'}`);
    }

    // Try to load stored credentials
    let client = await this.getStoredCredentials(userId);

    if (client) {
      // Check if token needs refresh
      const tokens = client.credentials;
      if (tokens.expiry_date && tokens.expiry_date < Date.now() + 60000) {
        console.error(`Token for ${userId} is expired or expiring soon, refreshing...`);
        try {
          const { credentials } = await client.refreshAccessToken();
          client.setCredentials(credentials);
          await this.storeCredentials(client, userId);
        } catch (error) {
          console.error(`Failed to refresh token for ${userId}, re-authorizing...`);
          await this.startAuthFlow(userId);
          client = await this.getStoredCredentials(userId);
        }
      }
      return client!;
    }

    // No stored credentials, start auth flow
    await this.startAuthFlow(userId);
    client = await this.getStoredCredentials(userId);

    if (!client) {
      throw new Error(`Failed to authorize ${userId}`);
    }

    return client;
  }
}
