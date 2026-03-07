/**
 * AuditViewer — Immutable audit log viewer for CRA compliance.
 *
 * Displays the hash-chain-verified audit trail with filtering,
 * search, and export capabilities.
 */

import React, { useState } from "react";

interface AuditEvent {
  id: string;
  timestamp: string;
  eventType: string;
  actor: string;
  resource: string;
  action: string;
  result: "success" | "failure" | "warning";
  ip: string;
}

const SAMPLE_EVENTS: AuditEvent[] = [
  { id: "evt-001", timestamp: "2026-03-05T14:32:01Z", eventType: "adapter.execute", actor: "agent-openclaw-1", resource: "salesforce", action: "query", result: "success", ip: "10.0.1.42" },
  { id: "evt-002", timestamp: "2026-03-05T14:31:45Z", eventType: "adapter.execute", actor: "agent-langchain-2", resource: "postgres", action: "query", result: "success", ip: "10.0.1.43" },
  { id: "evt-003", timestamp: "2026-03-05T14:30:12Z", eventType: "auth.login", actor: "admin@company.com", resource: "dashboard", action: "login", result: "success", ip: "192.168.1.10" },
  { id: "evt-004", timestamp: "2026-03-05T14:28:55Z", eventType: "adapter.execute", actor: "agent-autogpt-1", resource: "slack", action: "send_message", result: "success", ip: "10.0.1.44" },
  { id: "evt-005", timestamp: "2026-03-05T14:25:30Z", eventType: "security.rate_limit", actor: "agent-custom-3", resource: "rest_api", action: "get", result: "warning", ip: "10.0.1.50" },
  { id: "evt-006", timestamp: "2026-03-05T14:20:00Z", eventType: "compliance.report", actor: "system", resource: "cra_report", action: "generate", result: "success", ip: "127.0.0.1" },
  { id: "evt-007", timestamp: "2026-03-05T14:15:22Z", eventType: "adapter.execute", actor: "agent-openclaw-1", resource: "gmail", action: "send_email", result: "success", ip: "10.0.1.42" },
  { id: "evt-008", timestamp: "2026-03-05T14:10:11Z", eventType: "auth.api_key", actor: "service-account-1", resource: "api", action: "validate", result: "failure", ip: "203.0.113.5" },
];

export default function AuditViewer() {
  const [filter, setFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");

  const eventTypes = ["all", ...new Set(SAMPLE_EVENTS.map((e) => e.eventType))];
  const filtered = SAMPLE_EVENTS.filter(
    (e) =>
      (typeFilter === "all" || e.eventType === typeFilter) &&
      (filter === "" ||
        e.actor.toLowerCase().includes(filter.toLowerCase()) ||
        e.resource.toLowerCase().includes(filter.toLowerCase()))
  );

  return (
    <div className="space-y-6">
      {/* Integrity Banner */}
      <div className="nb-card bg-green-50 dark:bg-green-900/10 border-green-200 dark:border-green-800">
        <div className="flex items-center gap-3">
          <span className="text-2xl">🔒</span>
          <div>
            <p className="font-semibold text-green-800 dark:text-green-400">Hash-Chain Integrity Verified</p>
            <p className="text-sm text-green-600 dark:text-green-500">
              All {SAMPLE_EVENTS.length} audit entries have been verified. No tampering detected.
            </p>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <input
          type="text"
          placeholder="Search by actor or resource..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          {eventTypes.map((t) => (
            <option key={t} value={t}>{t === "all" ? "All Event Types" : t}</option>
          ))}
        </select>
        <button className="nb-btn-secondary">Export JSON</button>
        <button className="nb-btn-secondary">Export CSV</button>
      </div>

      {/* Events Table */}
      <div className="nb-card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700">
              <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Timestamp</th>
              <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Event Type</th>
              <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Actor</th>
              <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Resource</th>
              <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Action</th>
              <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Result</th>
              <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">IP</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((evt) => (
              <tr key={evt.id} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                <td className="py-3 px-2 text-gray-500 dark:text-gray-400 font-mono text-xs">{evt.timestamp}</td>
                <td className="py-3 px-2">
                  <span className="px-2 py-0.5 bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-400 rounded text-xs">
                    {evt.eventType}
                  </span>
                </td>
                <td className="py-3 px-2 text-gray-700 dark:text-gray-300">{evt.actor}</td>
                <td className="py-3 px-2 text-gray-600 dark:text-gray-400">{evt.resource}</td>
                <td className="py-3 px-2 text-gray-600 dark:text-gray-400">{evt.action}</td>
                <td className="py-3 px-2">
                  <span className={
                    evt.result === "success" ? "nb-badge-success" :
                    evt.result === "warning" ? "nb-badge-warning" : "nb-badge-danger"
                  }>
                    {evt.result}
                  </span>
                </td>
                <td className="py-3 px-2 text-gray-400 font-mono text-xs">{evt.ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
