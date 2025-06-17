# Vulnerability Server

A FastAPI-based web service for tracking and managing Python application dependencies and their security vulnerabilities. This service integrates with the OSV.dev vulnerability database to identify security issues in Python packages.

## Features

- **Application Management**: Create and manage Python applications with their dependency requirements
- **Vulnerability Scanning**: Automatic vulnerability detection for Python packages using OSV.dev API
- **Dependency Tracking**: Track dependencies across multiple applications and identify vulnerable packages
- **RESTful API**: Clean REST API for programmatic access to vulnerability data
- **Background Processing**: Asynchronous vulnerability scanning to avoid blocking operations
- **Pagination Support**: Efficient handling of large datasets with pagination

## API Endpoints

### Applications
- `GET /api/v1/applications` - List all applications with vulnerability status
- `POST /api/v1/applications` - Create a new application by uploading requirements.txt
- `GET /api/v1/applications/{id}/dependencies` - Get dependencies for a specific application

### Dependencies
- `GET /api/v1/dependencies` - List all tracked dependencies across applications
- `GET /api/v1/dependencies/{id}` - Get detailed information about a specific dependency

## Technology Stack

- **FastAPI**: Modern, fast web framework for building APIs with Python
- **Uvicorn**: ASGI server for running the FastAPI application
- **HTTPX**: Async HTTP client for external API calls (OSV.dev)
- **Pydantic**: Data validation and settings management using Python type annotations
- **Pytest**: Testing framework with async support

## Architecture

The application follows a clean architecture pattern with:

- **Controllers**: Handle HTTP requests and responses
- **Services**: Business logic layer for applications and dependencies
- **Models**: Pydantic data models for type safety and validation
- **I/O Layer**: External integrations (OSV.dev API, caching, repositories)
- **Middlewares**: Cross-cutting concerns (error handling, dependency injection)

## Setup and Installation

### Prerequisites

Ensure you have Python 3.12.10 or later installed.

### Installation Steps

1. **Create a virtual environment**
   ```bash
   python -m venv .venv
   ```

2. **Activate the virtual environment**
   ```bash
   source .venv/bin/activate  # On Linux/macOS
   # or
   .venv\Scripts\activate     # On Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements-test.txt
   ```

### Running the Application

#### Development Mode
Start the server in development mode with auto-reload:
```bash
make dev
```

#### Production Mode
Start the server in production mode with multiple workers:
```bash
make start
```

The API will be available at `http://localhost:8000`

### API Documentation

Once the server is running, you can access:
- Interactive API documentation (Swagger UI): `http://localhost:8000/docs`
- Alternative API documentation (ReDoc): `http://localhost:8000/redoc`

## Usage Example

### Creating an Application

```bash
curl -X POST "http://localhost:8000/api/v1/applications" \
  -H "Content-Type: multipart/form-data" \
  -F "new_application={\"name\":\"MyApp\",\"version\":\"1.0.0\",\"description\":\"My Python application\"}" \
  -F "requirements_file=@requirements.txt"
```

### Listing Applications

```bash
curl -X GET "http://localhost:8000/api/v1/applications?limit=10"
```

### Getting Application Dependencies

```bash
curl -X GET "http://localhost:8000/api/v1/applications/1/dependencies"
```

## Development

### Running Tests

```bash
pytest
```

### Code Formatting

The project uses Ruff for code formatting and linting:

```bash
ruff check .
ruff format .
```

### Project Structure

```
vulnerabilitieserver/
├── controllers/        # API route handlers
├── services/          # Business logic
├── models/           # Pydantic data models
├── io/               # External integrations (OSV.dev, cache, repository)
├── middlewares/      # Request/response middlewares
├── utils/            # Utility functions
└── fixtures/         # Test fixtures and data
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is developed for Morgan Stanley and follows internal licensing policies.

## External Dependencies

- **OSV.dev**: The project integrates with the OSV (Open Source Vulnerabilities) database for vulnerability information


