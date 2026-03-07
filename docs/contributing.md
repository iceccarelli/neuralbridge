# Contributing

NeuralBridge is an open-source project, and we welcome contributions from the community. Whether you are a developer, a security researcher, or a technical writer, there are many ways to get involved.

## Ways to Contribute

- **Build a New Adapter**: The most impactful way to contribute is to build a new adapter for a system that isn't yet supported. See the [Custom Adapters](adapters/custom.md) guide to get started.
- **Improve Documentation**: Help us make our documentation clearer, more comprehensive, and more accessible.
- **Report a Bug**: If you find a bug, please open an issue on our GitHub repository with a detailed description and steps to reproduce it.
- **Suggest a Feature**: Have an idea for a new feature? We'd love to hear it. Open an issue to start the discussion.
- **Submit a Pull Request**: If you've fixed a bug or implemented a new feature, please submit a pull request. We review all PRs and provide feedback.

## Development Setup

To get started with local development:

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```bash
    git clone https://github.com/your-username/neuralbridge.git
    cd neuralbridge
    ```
3.  **Install development dependencies**:
    ```bash
    pip install -r requirements/dev.txt
    ```
4.  **Run the tests** to ensure everything is set up correctly:
    ```bash
    pytest
    ```
5.  **Create a new branch** for your changes:
    ```bash
    git checkout -b my-new-feature
    ```
6.  **Make your changes**, and then **submit a pull request** to the `main` branch of the upstream repository.

## Code Style

We use `ruff` for linting and `black` for code formatting. Please run these tools before submitting a pull request:

```bash
ruff check .
black .
```

Thank you for considering contributing to NeuralBridge. Together, we can build the future of agentic AI infrastructure.
