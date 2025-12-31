# Google Docs MCP Server

MCP server for Google Docs, Sheets, and Drive operations with multi-account support.

## Development

```bash
npm install
npm run build
npm start
```

## Architecture

- `src/server.ts` - Main MCP server with tool definitions
- `src/googleDocsApiHelpers.ts` - Google Docs API helper functions
- `src/googleSheetsApiHelpers.ts` - Google Sheets API helper functions
- `src/services/auth.ts` - Multi-account OAuth authentication
- `src/types/` - TypeScript type definitions

## Key Features

- Multi-account Google OAuth support
- Document read/write/format operations
- Spreadsheet operations
- Drive file management
- Comment management via Drive API
