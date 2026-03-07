/**
 * AdapterConfig — Adapter management panel.
 *
 * Displays all registered adapters with their status, category, and
 * supported operations.  Allows enabling/disabling and viewing details.
 */

import React, { useState } from "react";

interface Adapter {
  type: string;
  name: string;
  category: string;
  status: "connected" | "disconnected" | "error";
  operations: string[];
  callsToday: number;
  avgLatency: string;
}

const ADAPTERS: Adapter[] = [
  { type: "postgres", name: "PostgreSQL", category: "Databases", status: "connected", operations: ["query", "execute", "list_tables", "describe_table"], callsToday: 2340, avgLatency: "12ms" },
  { type: "mysql", name: "MySQL", category: "Databases", status: "connected", operations: ["query", "execute", "list_tables", "describe_table"], callsToday: 1890, avgLatency: "14ms" },
  { type: "mongodb", name: "MongoDB", category: "Databases", status: "connected", operations: ["find", "insert", "update", "delete", "aggregate"], callsToday: 980, avgLatency: "18ms" },
  { type: "snowflake", name: "Snowflake", category: "Databases", status: "disconnected", operations: ["query", "list_schemas", "describe_table"], callsToday: 0, avgLatency: "—" },
  { type: "bigquery", name: "BigQuery", category: "Databases", status: "connected", operations: ["query", "list_datasets", "list_tables"], callsToday: 450, avgLatency: "340ms" },
  { type: "rest", name: "REST API", category: "APIs", status: "connected", operations: ["get", "post", "put", "patch", "delete"], callsToday: 3200, avgLatency: "85ms" },
  { type: "graphql", name: "GraphQL", category: "APIs", status: "connected", operations: ["query", "mutation", "introspect"], callsToday: 1100, avgLatency: "92ms" },
  { type: "soap", name: "SOAP/XML", category: "APIs", status: "connected", operations: ["call", "discover_wsdl"], callsToday: 120, avgLatency: "210ms" },
  { type: "slack", name: "Slack", category: "Messaging", status: "connected", operations: ["send_message", "list_channels", "upload_file", "add_reaction"], callsToday: 560, avgLatency: "45ms" },
  { type: "teams", name: "Microsoft Teams", category: "Messaging", status: "connected", operations: ["send_message", "list_channels", "create_channel"], callsToday: 340, avgLatency: "78ms" },
  { type: "salesforce", name: "Salesforce", category: "ERP / CRM", status: "connected", operations: ["query", "create_record", "update_record", "delete_record"], callsToday: 890, avgLatency: "120ms" },
  { type: "sap", name: "SAP ERP", category: "ERP / CRM", status: "connected", operations: ["read_entity", "create_entity", "call_function"], callsToday: 230, avgLatency: "180ms" },
  { type: "aws_s3", name: "AWS S3", category: "Cloud", status: "connected", operations: ["list_objects", "get_object", "put_object", "delete_object"], callsToday: 1560, avgLatency: "35ms" },
  { type: "gmail", name: "Gmail", category: "Productivity", status: "connected", operations: ["send_email", "search_emails", "read_email", "list_labels"], callsToday: 420, avgLatency: "95ms" },
  { type: "notion", name: "Notion", category: "Productivity", status: "connected", operations: ["search", "get_page", "create_page", "update_page"], callsToday: 180, avgLatency: "110ms" },
];

export default function AdapterConfig() {
  const [filter, setFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const categories = ["all", ...new Set(ADAPTERS.map((a) => a.category))];
  const filtered = ADAPTERS.filter(
    (a) =>
      (filter === "all" || a.category === filter) &&
      (search === "" || a.name.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <input
          type="text"
          placeholder="Search adapters..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <div className="flex gap-2">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                filter === cat
                  ? "bg-indigo-600 text-white"
                  : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700"
              }`}
            >
              {cat === "all" ? "All" : cat}
            </button>
          ))}
        </div>
      </div>

      {/* Adapter Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered.map((adapter) => (
          <div key={adapter.type} className="nb-card hover:border-indigo-300 dark:hover:border-indigo-700 transition-colors">
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">{adapter.name}</h3>
                <p className="text-xs text-gray-500 dark:text-gray-400">{adapter.category}</p>
              </div>
              <span
                className={`nb-badge ${
                  adapter.status === "connected"
                    ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400"
                    : adapter.status === "error"
                    ? "bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400"
                    : "bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400"
                }`}
              >
                {adapter.status}
              </span>
            </div>

            <div className="flex gap-4 text-xs text-gray-500 dark:text-gray-400 mb-3">
              <span>Calls: <strong className="text-gray-700 dark:text-gray-300">{adapter.callsToday.toLocaleString()}</strong></span>
              <span>Latency: <strong className="text-gray-700 dark:text-gray-300">{adapter.avgLatency}</strong></span>
            </div>

            <div className="flex flex-wrap gap-1">
              {adapter.operations.slice(0, 4).map((op) => (
                <span key={op} className="px-2 py-0.5 bg-gray-100 dark:bg-gray-800 rounded text-xs text-gray-600 dark:text-gray-400">
                  {op}
                </span>
              ))}
              {adapter.operations.length > 4 && (
                <span className="px-2 py-0.5 text-xs text-gray-400">+{adapter.operations.length - 4} more</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
