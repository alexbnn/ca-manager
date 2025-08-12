# SCEP Server Dockerfile Options

## Available Dockerfiles

### 1. `Dockerfile` (Original - Multi-stage)
- **Build Time:** ~4-5 minutes
- **Image Size:** ~150MB
- **Features:** Multi-stage build, optimized for production
- **Use Case:** Production deployment with minimal image size

### 2. `Dockerfile.simple` (Recommended for Development)
- **Build Time:** ~2-3 minutes  
- **Image Size:** ~200MB
- **Features:** Single-stage build, faster development iteration
- **Use Case:** Development and testing

### 3. `Dockerfile.alpine` (Small but slow to build)
- **Build Time:** ~5-6 minutes (needs to compile packages)
- **Image Size:** ~100MB
- **Features:** Alpine Linux base, very small final image
- **Use Case:** Resource-constrained production environments

### 4. `Dockerfile.fast` (Fastest build)
- **Build Time:** ~1-2 minutes
- **Image Size:** ~120MB
- **Features:** Minimal dependencies, Flask dev server
- **Use Case:** Rapid development iteration only

## How to Switch

Edit `docker-compose.yml` and change the dockerfile:

```yaml
scep-server:
  build:
    context: ./scep-server
    dockerfile: Dockerfile.simple  # Change this line
```

## Current Setting

Currently using: `Dockerfile.simple` (best balance of speed and features)