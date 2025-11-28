# Endpoint Web UI

A modern, reactive web interface for Endpoint AI-powered penetration testing.

## Features

- Real-time scan monitoring via WebSocket
- Beautiful, dark-themed UI with smooth animations
- Live vulnerability discovery feed
- Activity log with filtering and search
- Multi-target scan support
- Scan history

## Quick Start

### 1. Install Dependencies

```bash
cd web
make install
```

Or manually:
```bash
# Backend
cd backend && go mod tidy

# Frontend
cd frontend && npm install
```

### 2. Set Environment Variables

Make sure your Endpoint environment is configured:
```bash
export ENDPOINT_LLM="anthropic/claude-sonnet-4-5"
export LLM_API_KEY="your-api-key"
```

### 3. Start the Servers

In one terminal, start the backend:
```bash
make backend
# or: cd backend && go run main.go
```

In another terminal, start the frontend:
```bash
make frontend
# or: cd frontend && npm run dev
```

### 4. Open the UI

Visit **http://localhost:4321** in your browser.

## Architecture

```
web/
├── backend/           # Go API server
│   ├── main.go       # WebSocket + REST API
│   └── go.mod
├── frontend/          # Astro + React frontend
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── hooks/        # Custom React hooks
│   │   ├── lib/          # Utilities
│   │   ├── layouts/      # Astro layouts
│   │   ├── pages/        # Astro pages
│   │   └── styles/       # Global CSS
│   └── package.json
└── Makefile
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scans` | Create a new scan |
| GET | `/api/scans` | List all scans |
| GET | `/api/scans/:id` | Get scan details |
| DELETE | `/api/scans/:id` | Stop a scan |
| WS | `/api/scans/:id/ws` | WebSocket for real-time updates |

## WebSocket Messages

```typescript
// Status update
{ type: "status", data: "running" | "completed" | "error" }

// Output line
{ type: "output", data: { stream: "stdout" | "stderr", line: string } }

// Vulnerability found
{ type: "vulnerability", data: Vulnerability }

// Initial state
{ type: "init", data: { id, status, targets, vulnerabilities, events } }
```

## Development

### Frontend

Built with:
- **Astro** - Static site generation
- **React** - UI components
- **Tailwind CSS** - Styling
- **Framer Motion** - Animations
- **Lucide** - Icons

### Backend

Built with:
- **Go** - API server
- **Gorilla Mux** - HTTP routing
- **Gorilla WebSocket** - Real-time communication
- **CORS** - Cross-origin support

## Production Build

```bash
make build
```

This creates:
- `dist/endpoint-web` - Go binary
- `frontend/dist/` - Static frontend files

Serve the frontend with any static file server, and run the Go binary for the API.
