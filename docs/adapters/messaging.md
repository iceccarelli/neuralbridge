# Messaging Adapters

Effective communication is a critical capability for any advanced AI agent. NeuralBridge's messaging adapters enable agents to interact with users and systems through the most common collaboration and notification platforms, from sending alerts to participating in group discussions.

## Supported Messaging Platforms

| Adapter | Module Path | Key Operations | Use Cases |
|---|---|---|---|
| **Slack** | `adapters.messaging.slack` | `send_message`, `send_rich_message`, `list_channels`, `get_user_info` | Sending automated alerts to engineering channels, posting daily summaries to a management channel, responding to user queries in a support channel. |
| **Microsoft Teams** | `adapters.messaging.teams` | `send_message`, `send_adaptive_card`, `list_teams`, `list_channels` | Integrating with corporate workflows, sending notifications to Teams channels, creating interactive cards for user feedback. |
| **Email (SMTP)** | `adapters.messaging.email_smtp` | `send_email` | Sending formal notifications, delivering reports to stakeholders, integrating with legacy systems that rely on email. |
| **Discord** | `adapters.messaging.discord` | `send_message`, `send_embed` | Community engagement, automated server moderation, sending updates to a Discord server. |
| **Telegram** | `adapters.messaging.telegram` | `send_message`, `send_photo`, `send_document` | Building interactive bots, sending personal notifications, broadcasting messages to a channel. |

## Key Features

- **Rich Formatting**: Adapters for platforms like Slack and Microsoft Teams support rich message formatting, including interactive cards and buttons, allowing for more engaging and functional agent interactions.
- **User and Channel Discovery**: Agents can use operations like `list_channels` or `get_user_info` to discover the context of their environment and direct messages to the appropriate person or place.
- **Attachment Support**: Send files, images, and documents through platforms that support them, such as Telegram and Email.

## Example: Sending a Slack Alert

This example configures a Slack adapter to allow an `operations` agent to send critical alerts to the `#devops-alerts` channel.

### YAML Configuration (`slack.yaml`)

```yaml
adapters:
  slack_prod:
    type: slack
    description: "Primary Slack workspace for internal communication."
    auth:
      bot_token: ${SLACK_BOT_TOKEN}
    permissions:
      - role: operations_agent
        allowed_operations:
          - send_message
        allowed_channels:
          # Only allow sending messages to this specific channel
          - "#devops-alerts"
```

### Agent Tool Call

An agent with the `operations_agent` role can then send a message:

```json
{
  "adapter": "slack_prod",
  "operation": "send_message",
  "params": {
    "channel": "#devops-alerts",
    "text": "Critical Alert: Database CPU utilization has exceeded 95% for the last 10 minutes."
  }
}
```

NeuralBridge validates that the agent is only sending a message to the authorized channel, preventing it from spamming other channels or sending direct messages. This granular control is essential for maintaining order and security in a collaborative environment.
