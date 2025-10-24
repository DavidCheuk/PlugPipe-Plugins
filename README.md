# PlugPipe Plugins Registry

**Official plugin repository for PlugPipe Universal Integration Hub**

🔌 **251+ plugins** | 🎯 **Production-ready** | 🆓 **Forever free**

## What is PlugPipe?

PlugPipe is the Universal System Integration Hub that makes ANY infrastructure component pluggable, interchangeable, and future-proof. This repository contains the official plugin registry.

## Plugin Categories

- **A2A Protocol**: Agent-to-agent communication
- **Authentication**: JWT, OAuth2, RBAC, API keys (12+ plugins)
- **Security**: MCP security, secret scanning, input sanitization (25+ plugins)
- **Integration**: API adapters, webhooks, message queues (40+ plugins)
- **Data**: Databases, caching, transformation (30+ plugins)
- **Cloud**: AWS, Azure, GCP, Kubernetes (20+ plugins)
- **Orchestration**: Workflows, pipelines, DAGs (15+ plugins)
- **Monitoring**: Logging, metrics, tracing (10+ plugins)

## Quick Start

### Using PlugPipe GitHub Backend

```yaml
# config.yaml
registries:
  - backend: github
    type: github
    repos: DavidCheuk/PlugPipe-Plugins
    branch: main
    directory: plugs
    github_token_env: GITHUB_TOKEN
```

### Using PlugPipe CLI

```bash
# List available plugins
./pp list

# Install and run a plugin
./pp run agent_card_generator --version 1.0.0

# Search plugins
./pp search "security"
```

## Repository Statistics

- **Total Plugins**: 251 plugins
- **Categories**: 20+ categories
- **License**: MIT License (100% free forever)
- **Copyright Compliance**: 100% (all files have SPDX headers)

## Contributing

We welcome plugin contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Path B Business Model

**ALL 251 PLUGINS ARE FREE FOREVER** - No feature gating, no premium versions

PlugPipe monetizes through Enterprise Support Contracts:
- Managed cloud deployment
- 24/7 support with SLA guarantees
- Custom plugin development
- Training and consulting

## License

MIT License - See [LICENSE](LICENSE) for details

All plugins are copyrighted by PlugPipe Team (2025) and licensed under MIT.

## Security

Report security vulnerabilities: security@plugpipe.com

See [SECURITY.md](SECURITY.md) for our security policy.
