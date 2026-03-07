# Custom Adapters

While NeuralBridge offers a rich library of pre-built adapters, its true power lies in its extensibility. You can easily create your own custom adapters to connect to any system that is not covered out of the box, from proprietary internal APIs to specialized hardware.

## The Adapter Development Kit (ADK)

Developing a custom adapter is a straightforward process, thanks to the NeuralBridge Adapter Development Kit (ADK). The ADK consists of a `BaseAdapter` class, a CLI tool for scaffolding, and detailed documentation.

## Implementing a Custom Adapter

To create a custom adapter, you simply need to create a Python class that inherits from `BaseAdapter` and implements the following five methods:

```python
from neuralbridge.adapters import BaseAdapter

class MyCustomAdapter(BaseAdapter):
    async def _do_connect(self) -> None:
        # Logic to establish a connection to your system
        pass

    async def _do_disconnect(self) -> None:
        # Logic to gracefully close the connection
        pass

    async def _do_execute(self, operation: str, params: dict) -> any:
        # The core logic of your adapter.
        if operation == "get_status":
            return await self.client.get_status()
        else:
            raise NotImplementedError(f"Operation '{operation}' not supported.")

    async def _do_validate_credentials(self) -> dict:
        # Logic to test the provided credentials.
        pass

    def _get_config_schema(self) -> dict:
        # A JSON schema that defines the configuration parameters.
        return {
            "type": "object",
            "properties": {
                "api_endpoint": {"type": "string"},
                "api_key": {"type": "string"},
            },
            "required": ["api_endpoint", "api_key"],
        }
```

## Getting Started with a New Adapter

### 1. Scaffold the Adapter

Use the `neuralbridge` CLI to generate a new adapter template.

```bash
neuralbridge adk new --name my-iot-adapter
```

### 2. Implement the Logic

Fill in the five required methods with the logic specific to your target system.

### 3. Test Your Adapter

The ADK includes a testing suite to ensure your adapter behaves as expected.

```bash
cd my-iot-adapter
pytest
```

### 4. Package and Install

Once your tests are passing, you can package your adapter and install it into your NeuralBridge environment.

```bash
pip install .
```

Your adapter will now be available to be configured and used just like any of the pre-built adapters, empowering you to connect your AI agents to any system imaginable.
