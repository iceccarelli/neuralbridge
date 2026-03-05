/**
 * CostOptimizer — Token cost analytics and optimization panel.
 *
 * Shows estimated costs, caching savings, batching efficiency,
 * and per-adapter cost breakdowns.
 */

import React from "react";

interface CostEntry {
  adapter: string;
  calls: number;
  tokens: number;
  cost: string;
  cached: string;
  savings: string;
}

const COST_DATA: CostEntry[] = [
  { adapter: "Salesforce", calls: 890, tokens: 245000, cost: "$0.61", cached: "42%", savings: "$0.45" },
  { adapter: "PostgreSQL", calls: 2340, tokens: 180000, cost: "$0.45", cached: "68%", savings: "$0.96" },
  { adapter: "Gmail", calls: 420, tokens: 320000, cost: "$0.80", cached: "15%", savings: "$0.14" },
  { adapter: "Slack", calls: 560, tokens: 95000, cost: "$0.24", cached: "55%", savings: "$0.29" },
  { adapter: "REST API", calls: 3200, tokens: 890000, cost: "$2.23", cached: "72%", savings: "$5.72" },
  { adapter: "BigQuery", calls: 450, tokens: 1200000, cost: "$3.00", cached: "38%", savings: "$1.84" },
  { adapter: "AWS S3", calls: 1560, tokens: 45000, cost: "$0.11", cached: "80%", savings: "$0.45" },
  { adapter: "SAP ERP", calls: 230, tokens: 180000, cost: "$0.45", cached: "25%", savings: "$0.15" },
];

export default function CostOptimizer() {
  const totalCost = COST_DATA.reduce((sum, d) => sum + parseFloat(d.cost.replace("$", "")), 0);
  const totalSavings = COST_DATA.reduce((sum, d) => sum + parseFloat(d.savings.replace("$", "")), 0);
  const totalTokens = COST_DATA.reduce((sum, d) => sum + d.tokens, 0);
  const totalCalls = COST_DATA.reduce((sum, d) => sum + d.calls, 0);

  return (
    <div className="space-y-8">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="nb-card">
          <p className="text-sm text-gray-500 dark:text-gray-400">Today's Cost</p>
          <p className="text-3xl font-bold text-gray-900 dark:text-white mt-1">${totalCost.toFixed(2)}</p>
          <p className="text-sm text-green-600 dark:text-green-400 mt-1">-23% vs yesterday</p>
        </div>
        <div className="nb-card">
          <p className="text-sm text-gray-500 dark:text-gray-400">Cache Savings</p>
          <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-1">${totalSavings.toFixed(2)}</p>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">68% cache hit rate</p>
        </div>
        <div className="nb-card">
          <p className="text-sm text-gray-500 dark:text-gray-400">Total Tokens</p>
          <p className="text-3xl font-bold text-gray-900 dark:text-white mt-1">{(totalTokens / 1000000).toFixed(1)}M</p>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{totalCalls.toLocaleString()} API calls</p>
        </div>
        <div className="nb-card">
          <p className="text-sm text-gray-500 dark:text-gray-400">Monthly Projection</p>
          <p className="text-3xl font-bold text-gray-900 dark:text-white mt-1">${(totalCost * 30).toFixed(0)}</p>
          <p className="text-sm text-green-600 dark:text-green-400 mt-1">Under budget by $120</p>
        </div>
      </div>

      {/* Optimization Tips */}
      <div className="nb-card bg-indigo-50 dark:bg-indigo-900/10 border-indigo-200 dark:border-indigo-800">
        <h3 className="font-semibold text-indigo-800 dark:text-indigo-400 mb-3">Optimization Recommendations</h3>
        <div className="space-y-2">
          <div className="flex items-start gap-2">
            <span className="text-indigo-500 mt-0.5">1.</span>
            <p className="text-sm text-indigo-700 dark:text-indigo-300">
              <strong>Enable caching for Gmail adapter</strong> — Currently at 15% hit rate. Enabling response caching could save ~$0.50/day.
            </p>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-indigo-500 mt-0.5">2.</span>
            <p className="text-sm text-indigo-700 dark:text-indigo-300">
              <strong>Batch BigQuery queries</strong> — 450 individual calls could be reduced to ~50 batched calls, saving $1.20/day.
            </p>
          </div>
          <div className="flex items-start gap-2">
            <span className="text-indigo-500 mt-0.5">3.</span>
            <p className="text-sm text-indigo-700 dark:text-indigo-300">
              <strong>Use gpt-4o-mini for simple queries</strong> — 60% of REST API calls use simple prompts that could use a cheaper model.
            </p>
          </div>
        </div>
      </div>

      {/* Cost Breakdown Table */}
      <div className="nb-card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Per-Adapter Cost Breakdown</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700">
                <th className="text-left py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Adapter</th>
                <th className="text-right py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Calls</th>
                <th className="text-right py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Tokens</th>
                <th className="text-right py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Cost</th>
                <th className="text-right py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Cache Hit</th>
                <th className="text-right py-3 px-2 text-gray-500 dark:text-gray-400 font-medium">Savings</th>
              </tr>
            </thead>
            <tbody>
              {COST_DATA.map((row) => (
                <tr key={row.adapter} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                  <td className="py-3 px-2 font-medium text-gray-900 dark:text-white">{row.adapter}</td>
                  <td className="py-3 px-2 text-right text-gray-600 dark:text-gray-400">{row.calls.toLocaleString()}</td>
                  <td className="py-3 px-2 text-right text-gray-600 dark:text-gray-400">{row.tokens.toLocaleString()}</td>
                  <td className="py-3 px-2 text-right font-medium text-gray-900 dark:text-white">{row.cost}</td>
                  <td className="py-3 px-2 text-right text-gray-600 dark:text-gray-400">{row.cached}</td>
                  <td className="py-3 px-2 text-right text-green-600 dark:text-green-400 font-medium">{row.savings}</td>
                </tr>
              ))}
            </tbody>
            <tfoot>
              <tr className="border-t-2 border-gray-300 dark:border-gray-600">
                <td className="py-3 px-2 font-bold text-gray-900 dark:text-white">Total</td>
                <td className="py-3 px-2 text-right font-bold text-gray-900 dark:text-white">{totalCalls.toLocaleString()}</td>
                <td className="py-3 px-2 text-right font-bold text-gray-900 dark:text-white">{totalTokens.toLocaleString()}</td>
                <td className="py-3 px-2 text-right font-bold text-gray-900 dark:text-white">${totalCost.toFixed(2)}</td>
                <td className="py-3 px-2 text-right font-bold text-gray-900 dark:text-white">—</td>
                <td className="py-3 px-2 text-right font-bold text-green-600 dark:text-green-400">${totalSavings.toFixed(2)}</td>
              </tr>
            </tfoot>
          </table>
        </div>
      </div>
    </div>
  );
}
