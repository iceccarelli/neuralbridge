/**
 * ConnectionWizard — No-code connection builder.
 *
 * A step-by-step wizard that guides business users through creating
 * adapter connections using YAML configuration.  Designed to be
 * intuitive for non-technical users.
 */

import React, { useState } from "react";

interface Connection {
  id: string;
  name: string;
  adapter: string;
  status: "active" | "inactive" | "error";
  created: string;
  lastUsed: string;
}

const SAMPLE_CONNECTIONS: Connection[] = [
  { id: "c1", name: "Production CRM", adapter: "salesforce", status: "active", created: "2026-02-15", lastUsed: "2 min ago" },
  { id: "c2", name: "Analytics DB", adapter: "bigquery", status: "active", created: "2026-02-20", lastUsed: "5 min ago" },
  { id: "c3", name: "Team Notifications", adapter: "slack", status: "active", created: "2026-03-01", lastUsed: "12 min ago" },
  { id: "c4", name: "SAP ERP (Staging)", adapter: "sap", status: "inactive", created: "2026-03-03", lastUsed: "2 days ago" },
  { id: "c5", name: "Document Store", adapter: "aws_s3", status: "active", created: "2026-01-10", lastUsed: "1 hour ago" },
];

const YAML_EXAMPLE = `# NeuralBridge Connection Configuration
# This YAML file defines a connection to Salesforce CRM.

adapters:
  salesforce:
    type: salesforce
    auth:
      type: oauth2
      client_id: \${SALESFORCE_CLIENT_ID}
      client_secret: \${SALESFORCE_CLIENT_SECRET}
      instance_url: https://yourorg.my.salesforce.com
    permissions:
      - query: "SELECT Id, Name FROM Account"
      - rate_limit: 500/hour
    security:
      encryption: aes-256-gcm
      audit_logging: true
      data_classification: confidential`;

export default function ConnectionWizard() {
  const [showWizard, setShowWizard] = useState(false);
  const [wizardStep, setWizardStep] = useState(1);
  const [selectedAdapter, setSelectedAdapter] = useState("");

  const adapterOptions = [
    { value: "postgres", label: "PostgreSQL", icon: "🗄️" },
    { value: "mysql", label: "MySQL", icon: "🗄️" },
    { value: "mongodb", label: "MongoDB", icon: "🗄️" },
    { value: "salesforce", label: "Salesforce", icon: "🏢" },
    { value: "slack", label: "Slack", icon: "💬" },
    { value: "rest", label: "REST API", icon: "🔌" },
    { value: "aws_s3", label: "AWS S3", icon: "☁️" },
    { value: "gmail", label: "Gmail", icon: "📧" },
  ];

  return (
    <div className="space-y-6">
      {/* Action Bar */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-500 dark:text-gray-400">
          {SAMPLE_CONNECTIONS.length} connections configured
        </p>
        <button onClick={() => { setShowWizard(true); setWizardStep(1); }} className="nb-btn-primary">
          + New Connection
        </button>
      </div>

      {/* Connection Wizard Modal */}
      {showWizard && (
        <div className="nb-card border-2 border-indigo-500/50">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              New Connection — Step {wizardStep} of 3
            </h3>
            <button onClick={() => setShowWizard(false)} className="text-gray-400 hover:text-gray-600">
              Close
            </button>
          </div>

          {/* Progress Bar */}
          <div className="flex gap-2 mb-6">
            {[1, 2, 3].map((s) => (
              <div
                key={s}
                className={`h-1.5 flex-1 rounded-full ${
                  s <= wizardStep ? "bg-indigo-600" : "bg-gray-200 dark:bg-gray-700"
                }`}
              />
            ))}
          </div>

          {wizardStep === 1 && (
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                Select the system you want to connect your AI agents to:
              </p>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {adapterOptions.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => setSelectedAdapter(opt.value)}
                    className={`p-4 rounded-lg border text-center transition-colors ${
                      selectedAdapter === opt.value
                        ? "border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20"
                        : "border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600"
                    }`}
                  >
                    <span className="text-2xl">{opt.icon}</span>
                    <p className="mt-1 text-sm font-medium text-gray-700 dark:text-gray-300">{opt.label}</p>
                  </button>
                ))}
              </div>
              <button
                onClick={() => wizardStep < 3 && setWizardStep(2)}
                disabled={!selectedAdapter}
                className="mt-4 nb-btn-primary disabled:opacity-50"
              >
                Next: Configure
              </button>
            </div>
          )}

          {wizardStep === 2 && (
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                Configure your connection using YAML (or paste your existing config):
              </p>
              <pre className="p-4 bg-gray-900 dark:bg-gray-950 rounded-lg text-sm text-green-400 font-mono overflow-x-auto whitespace-pre">
                {YAML_EXAMPLE}
              </pre>
              <div className="flex gap-3 mt-4">
                <button onClick={() => setWizardStep(1)} className="nb-btn-secondary">Back</button>
                <button onClick={() => setWizardStep(3)} className="nb-btn-primary">Next: Review</button>
              </div>
            </div>
          )}

          {wizardStep === 3 && (
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                Review your connection settings:
              </p>
              <div className="space-y-2 mb-4">
                <div className="flex justify-between py-2 border-b border-gray-100 dark:border-gray-800">
                  <span className="text-sm text-gray-500">Adapter</span>
                  <span className="text-sm font-medium text-gray-900 dark:text-white">{selectedAdapter}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-gray-100 dark:border-gray-800">
                  <span className="text-sm text-gray-500">Auth Type</span>
                  <span className="text-sm font-medium text-gray-900 dark:text-white">OAuth 2.0</span>
                </div>
                <div className="flex justify-between py-2 border-b border-gray-100 dark:border-gray-800">
                  <span className="text-sm text-gray-500">Encryption</span>
                  <span className="text-sm font-medium text-gray-900 dark:text-white">AES-256-GCM</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-sm text-gray-500">Audit Logging</span>
                  <span className="nb-badge-success">Enabled</span>
                </div>
              </div>
              <div className="flex gap-3">
                <button onClick={() => setWizardStep(2)} className="nb-btn-secondary">Back</button>
                <button onClick={() => setShowWizard(false)} className="nb-btn-primary">
                  Create Connection
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Existing Connections */}
      <div className="nb-card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Active Connections</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700">
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Name</th>
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Adapter</th>
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Status</th>
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Created</th>
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Last Used</th>
              </tr>
            </thead>
            <tbody>
              {SAMPLE_CONNECTIONS.map((conn) => (
                <tr key={conn.id} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                  <td className="py-3 px-2 font-medium text-gray-900 dark:text-white">{conn.name}</td>
                  <td className="py-3 px-2 text-gray-600 dark:text-gray-400">{conn.adapter}</td>
                  <td className="py-3 px-2">
                    <span className={conn.status === "active" ? "nb-badge-success" : conn.status === "error" ? "nb-badge-danger" : "nb-badge bg-gray-100 dark:bg-gray-800 text-gray-500"}>
                      {conn.status}
                    </span>
                  </td>
                  <td className="py-3 px-2 text-gray-500 dark:text-gray-400">{conn.created}</td>
                  <td className="py-3 px-2 text-gray-500 dark:text-gray-400">{conn.lastUsed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
