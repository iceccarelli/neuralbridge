/**
 * NeuralBridge Admin Dashboard — Main Application Component.
 *
 * A beautiful, dark-mode-enabled admin interface for managing adapters,
 * monitoring compliance, viewing audit logs, and optimising costs.
 * Built with React 18 + TypeScript + Tailwind CSS.
 */

import React, { useState } from "react";
import AdapterConfig from "./components/AdapterConfig";
import ConnectionWizard from "./components/ConnectionWizard";
import AuditViewer from "./components/AuditViewer";
import ComplianceDashboard from "./components/ComplianceDashboard";
import CostOptimizer from "./components/CostOptimizer";

type View = "dashboard" | "adapters" | "connections" | "audit" | "compliance" | "costs";

const NAV_ITEMS: { id: View; label: string; icon: string }[] = [
  { id: "dashboard", label: "Dashboard", icon: "⬡" },
  { id: "adapters", label: "Adapters", icon: "⚡" },
  { id: "connections", label: "Connections", icon: "🔗" },
  { id: "audit", label: "Audit Logs", icon: "📋" },
  { id: "compliance", label: "Compliance", icon: "🛡️" },
  { id: "costs", label: "Cost Optimizer", icon: "💰" },
];

export default function App() {
  const [currentView, setCurrentView] = useState<View>("dashboard");
  const [darkMode, setDarkMode] = useState(true);

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
    document.documentElement.classList.toggle("dark");
  };

  return (
    <div className={`min-h-screen ${darkMode ? "dark" : ""}`}>
      <div className="flex min-h-screen bg-gray-50 dark:bg-gray-950">
        {/* Sidebar */}
        <aside className="w-64 bg-white dark:bg-gray-900 border-r border-gray-200 dark:border-gray-800 flex flex-col">
          {/* Logo */}
          <div className="p-6 border-b border-gray-200 dark:border-gray-800">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center text-white font-bold text-lg">
                NB
              </div>
              <div>
                <h1 className="text-lg font-bold text-gray-900 dark:text-white">NeuralBridge</h1>
                <p className="text-xs text-gray-500 dark:text-gray-400">Enterprise Middleware</p>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 p-4 space-y-1">
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                onClick={() => setCurrentView(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  currentView === item.id
                    ? "bg-indigo-50 dark:bg-indigo-900/20 text-indigo-700 dark:text-indigo-400"
                    : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800"
                }`}
              >
                <span className="text-lg">{item.icon}</span>
                {item.label}
              </button>
            ))}
          </nav>

          {/* Dark mode toggle */}
          <div className="p-4 border-t border-gray-200 dark:border-gray-800">
            <button
              onClick={toggleDarkMode}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            >
              <span className="text-lg">{darkMode ? "☀️" : "🌙"}</span>
              {darkMode ? "Light Mode" : "Dark Mode"}
            </button>
            <p className="mt-3 text-xs text-gray-400 dark:text-gray-600 text-center">
              NeuralBridge v0.1.0
            </p>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 overflow-auto">
          {/* Top Bar */}
          <header className="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 px-8 py-4 flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                {NAV_ITEMS.find((i) => i.id === currentView)?.label}
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {currentView === "dashboard" && "Overview of your NeuralBridge instance"}
                {currentView === "adapters" && "Manage and configure universal adapters"}
                {currentView === "connections" && "Create and manage adapter connections"}
                {currentView === "audit" && "Immutable audit trail for CRA compliance"}
                {currentView === "compliance" && "EU CRA and GDPR compliance status"}
                {currentView === "costs" && "Token cost optimization and analytics"}
              </p>
            </div>
            <div className="flex items-center gap-4">
              <span className="nb-badge-success">CRA Ready</span>
              <span className="nb-badge bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-400">
                MCP Compatible
              </span>
            </div>
          </header>

          {/* Content Area */}
          <div className="p-8">
            {currentView === "dashboard" && <DashboardOverview />}
            {currentView === "adapters" && <AdapterConfig />}
            {currentView === "connections" && <ConnectionWizard />}
            {currentView === "audit" && <AuditViewer />}
            {currentView === "compliance" && <ComplianceDashboard />}
            {currentView === "costs" && <CostOptimizer />}
          </div>
        </main>
      </div>
    </div>
  );
}

/* ── Dashboard Overview ──────────────────────────────────────── */

function DashboardOverview() {
  const stats = [
    { label: "Active Adapters", value: "22", change: "+3 this week", color: "indigo" },
    { label: "Connections", value: "8", change: "All healthy", color: "green" },
    { label: "API Calls (24h)", value: "12,847", change: "+18% vs yesterday", color: "purple" },
    { label: "Cost Savings", value: "68%", change: "$2,340 saved this month", color: "emerald" },
  ];

  const recentActivity = [
    { time: "2 min ago", event: "Salesforce adapter: 3 records created", type: "success" },
    { time: "5 min ago", event: "Gmail adapter: 12 emails processed", type: "success" },
    { time: "12 min ago", event: "Rate limit warning: Slack adapter (450/500)", type: "warning" },
    { time: "1 hour ago", event: "CRA compliance report generated", type: "info" },
    { time: "3 hours ago", event: "New connection: SAP ERP (production)", type: "success" },
  ];

  return (
    <div className="space-y-8">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat) => (
          <div key={stat.label} className="nb-card">
            <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{stat.label}</p>
            <p className="mt-2 text-3xl font-bold text-gray-900 dark:text-white">{stat.value}</p>
            <p className="mt-1 text-sm text-green-600 dark:text-green-400">{stat.change}</p>
          </div>
        ))}
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Recent Activity */}
        <div className="nb-card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Recent Activity</h3>
          <div className="space-y-3">
            {recentActivity.map((item, i) => (
              <div key={i} className="flex items-start gap-3 py-2 border-b border-gray-100 dark:border-gray-800 last:border-0">
                <span className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${
                  item.type === "success" ? "bg-green-500" :
                  item.type === "warning" ? "bg-yellow-500" : "bg-blue-500"
                }`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-gray-700 dark:text-gray-300">{item.event}</p>
                  <p className="text-xs text-gray-400 dark:text-gray-500">{item.time}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* CRA Compliance Status */}
        <div className="nb-card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">CRA Compliance</h3>
          <div className="flex items-center gap-4 mb-6">
            <div className="w-20 h-20 rounded-full border-4 border-green-500 flex items-center justify-center">
              <span className="text-2xl font-bold text-green-600 dark:text-green-400">100%</span>
            </div>
            <div>
              <p className="text-sm font-medium text-green-600 dark:text-green-400">Fully Compliant</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Ready for September 11, 2026 deadline
              </p>
            </div>
          </div>
          <div className="space-y-2">
            {["Audit Logging", "Vulnerability Reports", "SBOM Generation", "Incident Logging", "GDPR Article 30"].map((item) => (
              <div key={item} className="flex items-center justify-between py-1.5">
                <span className="text-sm text-gray-600 dark:text-gray-400">{item}</span>
                <span className="nb-badge-success">Compliant</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Adapter Categories */}
      <div className="nb-card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Adapter Ecosystem</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {[
            { name: "Databases", count: 5, icon: "🗄️" },
            { name: "APIs", count: 4, icon: "🔌" },
            { name: "Messaging", count: 5, icon: "💬" },
            { name: "Productivity", count: 2, icon: "📧" },
            { name: "ERP / CRM", count: 2, icon: "🏢" },
            { name: "Cloud", count: 3, icon: "☁️" },
          ].map((cat) => (
            <div key={cat.name} className="text-center p-4 rounded-lg bg-gray-50 dark:bg-gray-800/50">
              <span className="text-2xl">{cat.icon}</span>
              <p className="mt-2 text-sm font-medium text-gray-700 dark:text-gray-300">{cat.name}</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">{cat.count} adapters</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
