# Dashboard

The NeuralBridge Dashboard is a user-friendly, web-based interface for managing and monitoring your entire NeuralBridge environment. It is a React single-page application (SPA) that communicates with the NeuralBridge backend via its REST API.

![NeuralBridge Dashboard](assets/dashboard_screenshot.png)
*The main connections view in the NeuralBridge Dashboard.*

## Key Features

- **Connection Management**: Visually create, configure, and delete adapter connections. The dashboard dynamically renders configuration forms based on the JSON schema provided by each adapter.
- **Security and RBAC**: Manage users, assign roles, and control permissions for different agents and teams.
- **Live Audit Trail**: View the immutable audit log in real-time. Search, filter, and inspect every request and response that flows through the system.
- **Compliance Center**: Access and generate compliance artifacts, including EU CRA vulnerability reports and GDPR processing records.
- **Health Monitoring**: A real-time dashboard showing the health, performance, and error rates of all connected adapters.

## Accessing the Dashboard

When you run NeuralBridge using the recommended Docker Compose setup, the dashboard is automatically available at:

[http://localhost:3000](http://localhost:3000)

## Technology Stack

The dashboard is built with a modern, robust frontend stack:

- **React**: A declarative, component-based library for building user interfaces.
- **Vite**: A next-generation frontend tooling that provides a faster and leaner development experience.
- **TypeScript**: A statically typed superset of JavaScript that enhances code quality and maintainability.
- **Tailwind CSS**: A utility-first CSS framework for rapidly building custom designs.
- **Recharts**: A composable charting library for building beautiful data visualizations.
