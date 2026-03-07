# Cloud Service Adapters

Modern enterprises are built on the cloud. NeuralBridge's cloud service adapters provide a secure and standardized way for AI agents to interact with the fundamental building blocks of public cloud platforms, such as object storage and serverless functions.

## Supported Cloud Services

| Adapter | Module Path | Key Operations | Use Cases |
|---|---|---|---|
| **AWS S3** | `adapters.cloud.aws_s3` | `upload_file`, `download_file`, `list_buckets`, `list_objects` | Storing and retrieving large files, processing data lakes, archiving documents. |
| **Azure Blob Storage** | `adapters.cloud.azure_blob` | `upload_blob`, `download_blob`, `list_containers`, `list_blobs` | Integrating with Microsoft Azure workflows, storing application data. |
| **Google Cloud Storage** | `adapters.cloud.gcs` | `upload_file`, `download_file`, `list_buckets`, `list_objects` | Powering Google Cloud applications, storing data for BigQuery. |

## Key Features

- **Fine-Grained Permissions**: Control access not just to specific buckets or containers, but also to objects with specific prefixes, allowing for highly granular security policies.
- **Streaming Support**: For large files, the adapters support streaming uploads and downloads, minimizing the memory footprint on the NeuralBridge server.
- **Pre-signed URL Generation**: Agents can generate temporary, pre-signed URLs to grant time-limited access to specific files, a secure way to share data without exposing credentials.

## Example: Uploading a File to AWS S3

This example configures an S3 adapter to allow a `data_processing` agent to upload processed reports to a specific folder within a bucket.

### YAML Configuration (`s3.yaml`)

```yaml
adapters:
  s3_reports:
    type: aws_s3
    description: "S3 bucket for storing daily processed reports."
    auth:
      aws_access_key_id: ${AWS_ACCESS_KEY_ID}
      aws_secret_access_key: ${AWS_SECRET_ACCESS_KEY}
      region_name: "us-east-1"
    permissions:
      - role: data_processing_agent
        allowed_operations:
          - upload_file
        allowed_buckets:
          - "company-reports"
        allowed_key_prefixes:
          - "daily_processed/*"
```

### Agent Tool Call

```json
{
  "adapter": "s3_reports",
  "operation": "upload_file",
  "params": {
    "bucket": "company-reports",
    "local_path": "/path/to/processed_report.csv",
    "s3_key": "daily_processed/2026-03-06_report.csv"
  }
}
```

NeuralBridge ensures that the agent can only upload to the `company-reports` bucket and that the S3 key starts with `daily_processed/`. This prevents the agent from overwriting files in other directories or accessing other buckets, providing a critical layer of security for your cloud storage.
