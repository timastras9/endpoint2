.PHONY: all backend frontend dev install clean

# Install all dependencies
install:
	@echo "Installing backend dependencies..."
	cd backend && go mod tidy
	@echo "Installing frontend dependencies..."
	cd frontend && npm install

# Run backend only
backend:
	@echo "Starting Go backend on :8080..."
	cd backend && go run main.go

# Run frontend only
frontend:
	@echo "Starting Astro frontend on :4321..."
	cd frontend && npm run dev

# Run both in development mode (requires two terminals or use &)
dev:
	@echo "Starting development servers..."
	@echo "Backend: http://localhost:8080"
	@echo "Frontend: http://localhost:4321"
	@echo ""
	@echo "Run 'make backend' in one terminal and 'make frontend' in another"

# Build for production
build:
	@echo "Building backend..."
	cd backend && go build -o ../dist/endpoint-web main.go
	@echo "Building frontend..."
	cd frontend && npm run build
	@echo "Build complete! Output in dist/"

# Clean build artifacts
clean:
	rm -rf dist/
	rm -rf frontend/node_modules/
	rm -rf frontend/dist/

# Run everything (background mode)
run:
	@echo "Starting Endpoint Web UI..."
	@cd backend && go run main.go &
	@cd frontend && npm run dev
