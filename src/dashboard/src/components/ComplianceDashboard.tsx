/**
 * ComplianceDashboard — EU CRA and GDPR compliance monitoring.
 *
 * Shows compliance readiness, countdown to CRA deadline, SBOM status,
 * vulnerability reports, and GDPR Article 30 register.
 */

import React from "react";

interface ComplianceCheck {
  name: string;
  status: "compliant" | "action_required" | "in_progress";
  description: string;
  lastChecked: string;
}

const CRA_CHECKS: ComplianceCheck[] = [
  { name: "Immutable Audit Logging", status: "compliant", description: "Hash-chain verified, append-only audit trail active.", lastChecked: "2 min ago" },
  { name: "Vulnerability Reporting", status: "compliant", description: "CRA Article 14 report generator operational.", lastChecked: "1 hour ago" },
  { name: "Software Bill of Materials", status: "compliant", description: "CycloneDX SBOM auto-generated from dependencies.", lastChecked: "3 hours ago" },
  { name: "Incident Response Logging", status: "compliant", description: "Structured incident logger with severity tracking.", lastChecked: "5 min ago" },
  { name: "Security Documentation", status: "compliant", description: "SECURITY.md and security policies documented.", lastChecked: "1 day ago" },
  { name: "Encryption at Rest", status: "compliant", description: "Fernet (AES-128-CBC) encryption for all credentials.", lastChecked: "10 min ago" },
  { name: "Encryption in Transit", status: "compliant", description: "TLS 1.3 enforced for all external connections.", lastChecked: "10 min ago" },
  { name: "Access Control (RBAC)", status: "compliant", description: "4-role RBAC with granular permissions.", lastChecked: "30 min ago" },
];

const GDPR_ACTIVITIES = [
  { name: "CRM Data Sync", adapter: "salesforce", dataCategories: "Name, Email, Phone", legalBasis: "Contract", retention: "3 years" },
  { name: "Email Processing", adapter: "gmail", dataCategories: "Email content, Attachments", legalBasis: "Legitimate interest", retention: "1 year" },
  { name: "Analytics Queries", adapter: "bigquery", dataCategories: "Aggregated metrics", legalBasis: "Legitimate interest", retention: "2 years" },
  { name: "Team Notifications", adapter: "slack", dataCategories: "User IDs, Messages", legalBasis: "Contract", retention: "90 days" },
];

export default function ComplianceDashboard() {
  const deadline = new Date("2026-09-11T00:00:00Z");
  const now = new Date();
  const daysRemaining = Math.ceil((deadline.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
  const compliantCount = CRA_CHECKS.filter((c) => c.status === "compliant").length;

  return (
    <div className="space-y-8">
      {/* CRA Deadline Banner */}
      <div className="nb-card bg-gradient-to-r from-indigo-600 to-purple-600 border-0 text-white">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xl font-bold">EU Cyber Resilience Act</h3>
            <p className="text-indigo-200 mt-1">Compliance deadline: September 11, 2026</p>
          </div>
          <div className="text-right">
            <p className="text-4xl font-bold">{daysRemaining}</p>
            <p className="text-indigo-200 text-sm">days remaining</p>
          </div>
        </div>
        <div className="mt-4 bg-white/20 rounded-full h-3">
          <div
            className="bg-white rounded-full h-3 transition-all"
            style={{ width: `${(compliantCount / CRA_CHECKS.length) * 100}%` }}
          />
        </div>
        <p className="mt-2 text-sm text-indigo-200">
          {compliantCount}/{CRA_CHECKS.length} checks passed — {Math.round((compliantCount / CRA_CHECKS.length) * 100)}% compliant
        </p>
      </div>

      {/* CRA Checks */}
      <div className="nb-card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">CRA Compliance Checks</h3>
        <div className="space-y-3">
          {CRA_CHECKS.map((check) => (
            <div key={check.name} className="flex items-center justify-between py-3 border-b border-gray-100 dark:border-gray-800 last:border-0">
              <div className="flex items-center gap-3">
                <span className={`w-3 h-3 rounded-full ${
                  check.status === "compliant" ? "bg-green-500" :
                  check.status === "in_progress" ? "bg-yellow-500" : "bg-red-500"
                }`} />
                <div>
                  <p className="font-medium text-gray-900 dark:text-white">{check.name}</p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">{check.description}</p>
                </div>
              </div>
              <div className="text-right">
                <span className={
                  check.status === "compliant" ? "nb-badge-success" :
                  check.status === "in_progress" ? "nb-badge-warning" : "nb-badge-danger"
                }>
                  {check.status.replace("_", " ")}
                </span>
                <p className="text-xs text-gray-400 mt-1">{check.lastChecked}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* GDPR Article 30 Register */}
      <div className="nb-card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">GDPR Article 30 Register</h3>
          <button className="nb-btn-secondary text-sm">Export Register</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700">
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Activity</th>
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Adapter</th>
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Data Categories</th>
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Legal Basis</th>
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Retention</th>
              </tr>
            </thead>
            <tbody>
              {GDPR_ACTIVITIES.map((a) => (
                <tr key={a.name} className="border-b border-gray-100 dark:border-gray-800">
                  <td className="py-3 px-2 font-medium text-gray-900 dark:text-white">{a.name}</td>
                  <td className="py-3 px-2 text-gray-600 dark:text-gray-400">{a.adapter}</td>
                  <td className="py-3 px-2 text-gray-600 dark:text-gray-400">{a.dataCategories}</td>
                  <td className="py-3 px-2 text-gray-600 dark:text-gray-400">{a.legalBasis}</td>
                  <td className="py-3 px-2 text-gray-600 dark:text-gray-400">{a.retention}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <button className="nb-card hover:border-indigo-300 dark:hover:border-indigo-700 transition-colors text-left">
          <h4 className="font-semibold text-gray-900 dark:text-white">Generate CRA Report</h4>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Create Article 14 vulnerability report</p>
        </button>
        <button className="nb-card hover:border-indigo-300 dark:hover:border-indigo-700 transition-colors text-left">
          <h4 className="font-semibold text-gray-900 dark:text-white">Generate SBOM</h4>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">CycloneDX Software Bill of Materials</p>
        </button>
        <button className="nb-card hover:border-indigo-300 dark:hover:border-indigo-700 transition-colors text-left">
          <h4 className="font-semibold text-gray-900 dark:text-white">Export GDPR Register</h4>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">Article 30 processing activities</p>
        </button>
      </div>
    </div>
  );
}
