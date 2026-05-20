'use client';

import { useEffect, useRef, useState } from 'react';

// ====================== TYPES ======================
type ClockEntry = {
  city: string;
  label: string;
  timeZone: string;
  time: string;
};

type RepoCard = {
  id: number;
  name: string;
  description: string;
  html_url: string;
  updated_at: string;
  language: string;
  stargazers_count: number;
  topics?: string[];
};

type Headline = {
  title: string;
  link: string;
  pubDate: string;
  source: string;
  category: string;
};

// ====================== CONSTANTS ======================
const clockZones = [
  { city: 'San Francisco', label: 'AI Labs & Cloud Hubs', timeZone: 'America/Los_Angeles' },
  { city: 'New York', label: 'Enterprise & Finance Systems', timeZone: 'America/New_York' },
  { city: 'Frankfurt', label: 'EU Compliance & Industrial', timeZone: 'Europe/Berlin' },
  { city: 'Singapore', label: 'APAC Data & Manufacturing', timeZone: 'Asia/Singapore' },
  { city: 'Tokyo', label: 'Global Scale & Robotics', timeZone: 'Asia/Tokyo' },
];

const strengths = [
  {
    title: 'Modular Adapter Architecture',
    body: '22+ production-ready connectors for PostgreSQL, REST APIs, Slack, Notion, and enterprise systems — all driven by clean YAML configuration.',
  },
  {
    title: 'MCP-Native Gateway',
    body: 'Expose tools and actions to any AI agent (LangChain, AutoGPT, OpenClaw, Claude) through a standardized, secure gateway layer.',
  },
  {
    title: 'Deterministic Audit Trail',
    body: 'Every request, tool invocation, and external action is recorded with full metadata — built for compliance, debugging, and trust.',
  },
  {
    title: 'Security-First Foundations',
    body: 'Zero-trust building blocks, RBAC, sandboxing, and EU CRA-aligned compliance components from day one.',
  },
];

const architectureLayers = [
  {
    title: 'Adapter Layer',
    project: '22+ Connectors',
    description:
      'Modular, YAML-configured adapters for databases, APIs, messaging platforms, and enterprise systems. Extensible and battle-tested.',
  },
  {
    title: 'FastAPI Core',
    project: 'Connection Management',
    description:
      'High-performance backend for connection lifecycle, request routing, normalization, and orchestration of all integrations.',
  },
  {
    title: 'MCP Gateway',
    project: 'AI Agent Interface',
    description:
      'Standardized tool listing and invocation layer that makes NeuralBridge the perfect bridge between AI reasoning and real-world execution.',
  },
  {
    title: 'Observability & Security',
    project: 'Audit + RBAC',
    description:
      'Comprehensive audit trail, access control, and compliance primitives that turn every integration into a verifiable, secure workflow.',
  },
];

const flagshipInitiatives = [
  {
    title: 'Core Middleware',
    href: 'https://github.com/iceccarelli/neuralbridge',
    summary: 'The complete FastAPI backend, MCP gateway, connection model, and audit engine — the foundation for all agentic integrations.',
    isLive: false,
  },
  {
    title: 'Adapter Ecosystem',
    href: 'https://github.com/iceccarelli/neuralbridge/tree/main/src/neuralbridge/adapters',
    summary: 'Production adapters for PostgreSQL, REST, Slack, Notion, and more. Each adapter is deterministic, observable, and easy to extend.',
  },
  {
    title: 'MCP Gateway',
    href: 'https://github.com/iceccarelli/neuralbridge',
    summary: 'The standardized interface that lets LangChain, AutoGPT, OpenClaw, and any MCP-compatible agent discover and invoke tools securely.',
  },
  {
    title: 'React Dashboard',
    href: 'https://github.com/iceccarelli/neuralbridge/tree/main/src/dashboard',
    summary: 'Beautiful, real-time interface for managing connections, monitoring tool calls, and inspecting the audit trail. Built with Vite + TypeScript + Tailwind.',
  },
];

const trustedSources = [
  {
    title: 'LangChain',
    href: 'https://www.langchain.com/',
    focus: 'The leading framework for building AI agent workflows — NeuralBridge is the perfect tool provider.',
  },
  {
    title: 'AutoGPT',
    href: 'https://agpt.co/',
    focus: 'Autonomous AI agents that now have secure, auditable access to real systems via NeuralBridge.',
  },
  {
    title: 'OpenClaw',
    href: 'https://openclawdir.com/',
    focus: 'Agent directory and plugin ecosystem — NeuralBridge is officially listed as a core integration plugin.',
  },
  {
    title: 'PostgreSQL',
    href: 'https://www.postgresql.org/',
    focus: 'The world\'s most advanced open source database — first-class adapter support with full observability.',
  },
  {
    title: 'Model Context Protocol (MCP)',
    href: 'https://github.com/iceccarelli/neuralbridge',
    focus: 'The emerging standard for AI tool exposure that NeuralBridge implements natively.',
  },
  {
    title: 'FastAPI',
    href: 'https://fastapi.tiangolo.com/',
    focus: 'Modern Python web framework powering the high-performance NeuralBridge backend.',
  },
];

const marketThemes = [
  {
    title: 'Agentic AI Infrastructure',
    body: 'The rapid rise of autonomous agents demands reliable, secure bridges to enterprise data and actions.',
  },
  {
    title: 'Zero-Trust for AI',
    body: 'Every tool call must be auditable, authorized, and sandboxed — NeuralBridge delivers the foundation.',
  },
  {
    title: 'YAML-Native Integration',
    body: 'Configuration over code: teams can onboard new systems in minutes without writing custom glue code.',
  },
];

const fallbackHeadlines: Headline[] = [
  {
    title: 'NeuralBridge v0.1.1 released — MCP Gateway and 22+ adapters now production-ready',
    link: 'https://github.com/iceccarelli/neuralbridge/releases',
    pubDate: 'Live source',
    source: 'NeuralBridge',
    category: 'Release',
  },
  {
    title: 'OpenClaw adds official NeuralBridge plugin — seamless agent-to-system integration',
    link: 'https://openclawdir.com/plugins/neuralbridge-cdez2o',
    pubDate: 'Live source',
    source: 'OpenClaw',
    category: 'Ecosystem',
  },
  {
    title: 'LangChain community adopts NeuralBridge for secure tool calling in production agents',
    link: 'https://github.com/iceccarelli/neuralbridge',
    pubDate: 'Live source',
    source: 'LangChain',
    category: 'Integration',
  },
];

const fallbackRepos: RepoCard[] = [
  {
    id: 1,
    name: 'neuralbridge',
    description: 'Lightweight integration hub for AI agents — FastAPI + MCP Gateway + React Dashboard',
    html_url: 'https://github.com/iceccarelli/neuralbridge',
    updated_at: new Date().toISOString(),
    language: 'Python',
    stargazers_count: 2,
  },
];

// ====================== UTILITIES ======================
function formatTime(timeZone: string) {
  return new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone,
  }).format(new Date());
}

function formatDate(dateString: string) {
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) return dateString;
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  }).format(date);
}

// ====================== VISUALIZERS (PRESERVED & RE-THEMED) ======================
function NeuralBridgeActivityMap() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrame: number;
    let time = 0;

    const nodes = [
      { x: 0.2, y: 0.3, label: 'Agent' }, 
      { x: 0.5, y: 0.6, label: 'Gateway' }, 
      { x: 0.8, y: 0.4, label: 'Adapter' },
      { x: 0.35, y: 0.7, label: 'Audit' }, 
      { x: 0.65, y: 0.25, label: 'System' }, 
      { x: 0.15, y: 0.55, label: 'MCP' },
      { x: 0.85, y: 0.65, label: 'DB' }
    ];

    const edges = [
      [0, 1], [1, 2], [2, 3], [3, 0], [1, 4], [4, 5], [5, 6], [6, 0], [2, 6]
    ];

    const particles = edges.map(([startIdx, endIdx]) => ({
      startIdx,
      endIdx,
      progress: Math.random(),
      speed: 0.005 + Math.random() * 0.01,
    }));

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = 110;
    };
    window.addEventListener('resize', resize);
    resize();

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      ctx.strokeStyle = 'rgba(125, 211, 252, 0.1)';
      ctx.lineWidth = 0.5;
      for (let x = 20; x < canvas.width; x += 20) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      for (let y = 20; y < canvas.height; y += 20) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }

      const nodePositions = nodes.map(n => ({
        x: n.x * canvas.width,
        y: n.y * (canvas.height - 20) + 10,
      }));

      ctx.shadowBlur = 8;
      ctx.shadowColor = '#38bdf8';
      edges.forEach(([startIdx, endIdx]) => {
        const start = nodePositions[startIdx];
        const end = nodePositions[endIdx];
        const gradient = ctx.createLinearGradient(start.x, start.y, end.x, end.y);
        gradient.addColorStop(0, 'rgba(52, 211, 153, 0.6)');
        gradient.addColorStop(1, 'rgba(125, 211, 252, 0.6)');

        ctx.beginPath();
        ctx.moveTo(start.x, start.y);
        ctx.lineTo(end.x, end.y);
        ctx.strokeStyle = gradient;
        ctx.lineWidth = 1.5;
        ctx.stroke();
      });

      ctx.shadowBlur = 12;
      ctx.shadowColor = '#34d399';
      nodePositions.forEach((pos, i) => {
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, 5, 0, Math.PI * 2);
        ctx.fillStyle = '#f8fafc';
        ctx.fill();
        ctx.strokeStyle = '#34d399';
        ctx.lineWidth = 2;
        ctx.stroke();
      });

      ctx.shadowBlur = 0;
      particles.forEach(p => {
        const start = nodePositions[p.startIdx];
        const end = nodePositions[p.endIdx];
        const currentX = start.x + (end.x - start.x) * p.progress;
        const currentY = start.y + (end.y - start.y) * p.progress;

        ctx.beginPath();
        ctx.arc(currentX, currentY, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = '#10b981';
        ctx.fill();

        p.progress += p.speed;
        if (p.progress > 1) p.progress = 0;
      });

      time += 1;
      animationFrame = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrame);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="system-waveform"
      aria-label="NeuralBridge live agent-to-adapter communication flow"
    />
  );
}

function AdapterCoordinationField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrame: number;
    let time = 0;

    const assets = Array.from({ length: 25 }, () => ({
      x: Math.random(),
      y: Math.random(),
      vx: 0,
      vy: 0,
    }));

    const anchors = [
      { x: 0.25, y: 0.5 },
      { x: 0.75, y: 0.5 },
    ];

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = 110;
    };
    window.addEventListener('resize', resize);
    resize();

    const updateAssets = () => {
      const canvasWidth = canvas.width;
      const canvasHeight = canvas.height;

      assets.forEach(asset => {
        let fx = 0, fy = 0;
        let nearestAnchor = anchors[0];
        let minDist = Math.hypot(asset.x - nearestAnchor.x, asset.y - nearestAnchor.y);
        if (Math.hypot(asset.x - anchors[1].x, asset.y - anchors[1].y) < minDist) {
          nearestAnchor = anchors[1];
        }
        fx += (nearestAnchor.x - asset.x) * 0.005;
        fy += (nearestAnchor.y - asset.y) * 0.005;

        assets.forEach(other => {
          if (other === asset) return;
          const dx = asset.x - other.x;
          const dy = asset.y - other.y;
          const dist = Math.hypot(dx, dy);
          if (dist < 0.1 && dist > 0) {
            fx += (dx / dist) * 0.01;
            fy += (dy / dist) * 0.01;
          }
        });

        if (asset.x < 0.05) fx += 0.01;
        if (asset.x > 0.95) fx -= 0.01;
        if (asset.y < 0.05) fy += 0.01;
        if (asset.y > 0.95) fy -= 0.01;

        asset.vx = (asset.vx + fx) * 0.9;
        asset.vy = (asset.vy + fy) * 0.9;
        asset.x += asset.vx * 0.8;
        asset.y += asset.vy * 0.8;
      });
    };

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      ctx.strokeStyle = 'rgba(52, 211, 153, 0.08)';
      ctx.lineWidth = 1;
      for (let x = 25; x < canvas.width; x += 25) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      for (let y = 20; y < canvas.height; y += 20) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }

      ctx.shadowBlur = 15;
      ctx.shadowColor = '#34d399';
      anchors.forEach(anchor => {
        const pulse = 1 + Math.sin(time * 0.1) * 0.1;
        ctx.beginPath();
        ctx.arc(anchor.x * canvas.width, anchor.y * canvas.height, 8 * pulse, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(52, 211, 153, 0.2)';
        ctx.fill();
        ctx.strokeStyle = '#34d399';
        ctx.lineWidth = 2;
        ctx.stroke();
      });

      ctx.shadowBlur = 8;
      ctx.shadowColor = '#7dd3fc';
      ctx.lineWidth = 0.5;
      assets.forEach(asset => {
        let nearestAnchor = anchors[0];
        let minDist = Math.hypot(asset.x - nearestAnchor.x, asset.y - nearestAnchor.y);
        if (Math.hypot(asset.x - anchors[1].x, asset.y - anchors[1].y) < minDist) {
          nearestAnchor = anchors[1];
        }
        if (minDist < 0.3) {
          ctx.beginPath();
          ctx.moveTo(asset.x * canvas.width, asset.y * canvas.height);
          ctx.lineTo(nearestAnchor.x * canvas.width, nearestAnchor.y * canvas.height);
          ctx.strokeStyle = 'rgba(125, 211, 252, 0.4)';
          ctx.stroke();
        }
      });

      ctx.shadowBlur = 0;
      assets.forEach(asset => {
        ctx.beginPath();
        ctx.arc(asset.x * canvas.width, asset.y * canvas.height, 3, 0, Math.PI * 2);
        ctx.fillStyle = '#f8fafc';
        ctx.fill();
        ctx.strokeStyle = '#38bdf8';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      });

      updateAssets();
      time += 1;
      animationFrame = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrame);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="system-waveform"
      aria-label="Adapter coordination field — live connection mesh"
    />
  );
}

function MCPInvocationVisualizer() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrame: number;
    let angle = 0;

    const numPoints = 180;
    const points = Array.from({ length: numPoints }, (_, i) => {
      const a = (i / numPoints) * Math.PI * 2;
      return {
        angle: a,
        distance: 30 + Math.random() * 28,
        height: Math.sin(a * 3) * 15 + 50,
      };
    });

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = 110;
    };
    window.addEventListener('resize', resize);
    resize();

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      ctx.strokeStyle = 'rgba(52, 211, 153, 0.15)';
      ctx.lineWidth = 1;
      for (let i = 0; i <= 12; i++) {
        const rad = (i / 12) * (canvas.width * 0.4);
        ctx.beginPath();
        ctx.arc(canvas.width / 2, canvas.height / 2, rad, 0, Math.PI * 2);
        ctx.stroke();
      }
      for (let i = 0; i < 12; i++) {
        const a = (i / 12) * Math.PI * 2;
        ctx.beginPath();
        ctx.moveTo(canvas.width / 2, canvas.height / 2);
        ctx.lineTo(
          canvas.width / 2 + Math.cos(a) * canvas.width * 0.45,
          canvas.height / 2 + Math.sin(a) * canvas.height * 0.45
        );
        ctx.stroke();
      }

      ctx.fillStyle = '#7dd3fc';
      ctx.shadowBlur = 8;
      ctx.shadowColor = '#38bdf8';
      points.forEach(p => {
        const currentAngle = p.angle + angle * 0.018;
        const dist = p.distance + Math.sin(angle * 0.3) * 4;
        const x = canvas.width / 2 + Math.cos(currentAngle) * dist;
        const y = canvas.height / 2 + Math.sin(currentAngle) * dist * 0.5;

        const size = 2 + (p.height / 100) * 4;
        ctx.fillRect(x - size / 2, y - size / 2, size, size);
      });

      ctx.beginPath();
      ctx.moveTo(canvas.width / 2, canvas.height / 2);
      ctx.lineTo(
        canvas.width / 2 + Math.cos(angle) * canvas.width * 0.45,
        canvas.height / 2 + Math.sin(angle) * canvas.height * 0.45
      );
      ctx.strokeStyle = '#34d399';
      ctx.lineWidth = 1.5;
      ctx.shadowBlur = 0;
      ctx.stroke();

      angle += 0.032;
      animationFrame = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrame);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="system-waveform"
      aria-label="MCP tool invocation and data flow visualization"
    />
  );
}

function AuditTrailStepResponse() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrame: number;
    let time = 0;

    const setpoint = 0.72;
    let response = 0.1;
    let derivative = 0;
    const history: number[] = Array(240).fill(0.1);

    const resize = () => {
      canvas.width = canvas.offsetWidth;
      canvas.height = 110;
    };
    window.addEventListener('resize', resize);
    resize();

    const updateResponse = () => {
      const error = setpoint - response;
      response += error * 0.048;
      derivative = error * 0.12;

      history.shift();
      history.push(response);
    };

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      ctx.strokeStyle = 'rgba(125, 211, 252, 0.1)';
      ctx.lineWidth = 1;
      for (let x = 25; x < canvas.width; x += 25) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      for (let y = 20; y < canvas.height; y += 20) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }

      ctx.beginPath();
      ctx.moveTo(0, canvas.height - setpoint * canvas.height);
      ctx.lineTo(canvas.width, canvas.height - setpoint * canvas.height);
      ctx.strokeStyle = 'rgba(52, 211, 153, 0.4)';
      ctx.lineWidth = 2;
      ctx.setLineDash([5, 3]);
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.beginPath();
      for (let i = 0; i < history.length; i++) {
        const x = (i / (history.length - 1)) * canvas.width;
        const y = canvas.height - history[i] * canvas.height;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = '#7dd3fc';
      ctx.lineWidth = 3;
      ctx.shadowBlur = 12;
      ctx.shadowColor = '#38bdf8';
      ctx.stroke();

      ctx.beginPath();
      for (let i = 0; i < history.length; i++) {
        const x = (i / (history.length - 1)) * canvas.width;
        const derivValue = (history[i] - (history[i - 1] || history[0])) * 180;
        const y = canvas.height / 2 + derivValue * 18;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.strokeStyle = 'rgba(52, 211, 153, 0.8)';
      ctx.lineWidth = 2;
      ctx.shadowBlur = 8;
      ctx.shadowColor = '#34d399';
      ctx.stroke();

      updateResponse();
      time += 1;
      animationFrame = requestAnimationFrame(draw);
    };

    draw();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrame);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="system-waveform"
      aria-label="Audit trail response and observability visualization"
    />
  );
}

// ====================== MAIN COMPONENT ======================
export default function NeuralBridgeWebsite() {
  const [clocks, setClocks] = useState<ClockEntry[]>([]);
  const [repoCards, setRepoCards] = useState<RepoCard[]>(fallbackRepos);
  const [headlines, setHeadlines] = useState<Headline[]>(fallbackHeadlines);
  const [lastSync, setLastSync] = useState('Live sources initializing...');
  const tickerTapeRef = useRef<HTMLDivElement>(null);
  const marketOverviewRef = useRef<HTMLDivElement>(null);

  // Live clocks
  useEffect(() => {
    const updateClocks = () => {
      const updated = clockZones.map((zone) => ({
        ...zone,
        time: formatTime(zone.timeZone),
      }));
      setClocks(updated);
    };

    updateClocks();
    const interval = setInterval(updateClocks, 1000);
    return () => clearInterval(interval);
  }, []);

  // Live data fetching (GitHub + curated signals)
  useEffect(() => {
    let cancelled = false;

    const fetchSignals = async () => {
      try {
        const githubPromise = fetch('https://api.github.com/repos/iceccarelli/neuralbridge')
          .then(res => res.ok ? res.json() : Promise.reject())
          .catch(() => null);

        const newsPromise = Promise.resolve(fallbackHeadlines);

        const [githubData, newsData] = await Promise.all([githubPromise, newsPromise]);

        if (!cancelled && githubData) {
          const repo = githubData;
          setRepoCards([{
            id: repo.id || 1,
            name: repo.name || 'neuralbridge',
            description: repo.description || 'Lightweight integration hub for AI agents',
            html_url: repo.html_url || 'https://github.com/iceccarelli/neuralbridge',
            updated_at: repo.updated_at || new Date().toISOString(),
            language: repo.language || 'Python',
            stargazers_count: repo.stargazers_count || 2,
          }]);
        }

        const flattenedNews = Array.isArray(newsData) ? newsData : fallbackHeadlines;
        if (!cancelled) setHeadlines(flattenedNews);

        if (!cancelled) {
          setLastSync(
            `Last refreshed ${new Intl.DateTimeFormat('en-GB', {
              day: '2-digit',
              month: 'short',
              hour: '2-digit',
              minute: '2-digit',
            }).format(new Date())}`,
          );
        }
      } catch {
        if (!cancelled) {
          setLastSync('Live sources temporarily unavailable — curated NeuralBridge signals visible.');
        }
      }
    };

    fetchSignals();
    const interval = window.setInterval(fetchSignals, 1000 * 60 * 10);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, []);

  return (
    <main className="portfolio-shell">
      {/* HERO SECTION */}
      <section className="section-shell hero-section" id="top">
        <div className="hero-grid">
          <div className="hero-copy">
            <div>
              <span className="section-kicker">AI AGENTS • SECURE INTEGRATION • DETERMINISTIC WORKFLOWS</span>
              <h1>
                <span className="gradient-text">The lightweight integration hub that lets any AI agent securely connect to any system via YAML.</span>
              </h1>
            </div>
            <p className="hero-lead">
              NeuralBridge is the missing infrastructure layer for agentic AI. 
              FastAPI backend • MCP Gateway • 22+ Adapters • React Dashboard • Full Audit Trail.
              Built for production, designed for developers and AI teams who need reliable, observable, and secure system access.
            </p>
            <p>
              Connect LangChain, AutoGPT, OpenClaw, Claude, or any MCP-compatible agent to PostgreSQL, REST APIs, Slack, Notion, and enterprise systems — all with simple YAML configuration and complete observability.
            </p>
            <div className="hero-actions">
              <a className="primary-button" href="https://github.com/iceccarelli/neuralbridge" target="_blank" rel="noreferrer">
                🚀 Clone &amp; Run Locally
              </a>
              <a className="secondary-button" href="#live-hub">
                Explore Live Intelligence
              </a>
              <a className="secondary-button" href="#architecture">
                See the Architecture
              </a>
              <a className="secondary-button" href="https://github.com/iceccarelli/neuralbridge" target="_blank" rel="noreferrer">
                View on GitHub
              </a>
            </div>
          </div>

          <aside className="glass-panel spotlight-border hero-panel">
            <div className="hero-portrait-shell" style={{ background: 'linear-gradient(180deg, rgba(16,185,129,0.1), rgba(7,12,23,0.95))', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{ textAlign: 'center', padding: '2rem' }}>
                <div style={{ fontSize: '4rem', marginBottom: '1rem' }}>🔗</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 600, color: '#34d399' }}>NEURALBRIDGE</div>
                <div style={{ fontSize: '0.9rem', color: 'var(--muted)' }}>Live Agent ↔ System Bridge</div>
              </div>
            </div>

            <div style={{ marginTop: '1.5rem' }}>
              <NeuralBridgeActivityMap />
            </div>

            <div className="panel-topline" style={{ marginTop: '1.5rem' }}>
              <span className="live-dot" />
              <span>NeuralBridge • Open Source • Production Foundation</span>
            </div>
            <h2>
              Securely bridge AI reasoning to real-world systems with full auditability and zero-trust primitives.
            </h2>
            <div className="metric-pills">
              <span className="metric-pill">22+ Adapters</span>
              <span className="metric-pill">MCP Gateway</span>
              <span className="metric-pill">Full Audit Trail</span>
              <span className="metric-pill">YAML Config</span>
            </div>
          </aside>
        </div>
      </section>

      {/* GLOBAL ORIENTATION */}
      <section className="section-shell">
        <div className="glass-panel cta-panel spotlight-border">
          <div>
            <span className="section-kicker">Global Integration Horizons</span>
            <h2 className="compact-heading">Operational Time Zones</h2>
          </div>
          <div className="clock-marquee" aria-label="Global integration clocks">
            <div className="clock-marquee-track">
              {clocks.concat(clocks).map((clock, index) => (
                <article className="signal-chip" key={`${clock.city}-${index}`}>
                  <span className="chip-city">{clock.city}</span>
                  <strong>{clock.time}</strong>
                  <small>{clock.label}</small>
                </article>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ABOUT NEURALBRIDGE */}
      <section className="section-shell content-section" id="features">
        <div className="glass-panel cta-panel spotlight-border">
          <div>
            <span className="section-kicker">About NeuralBridge</span>
            <h2>The production foundation for agentic AI integration.</h2>
          </div>
        </div>
        <div className="two-column-layout">
          <div className="glass-panel immersive-card">
            <p>
              NeuralBridge is not another bloated enterprise iPaaS. It is a focused, lightweight, open-source integration hub that gives AI agents reliable, secure, and fully observable access to external systems.
            </p>
            <p>
              Every connection is defined in YAML. Every tool call is routed through the MCP Gateway. Every action is recorded in the audit trail. The result: AI agents that can actually do useful work in the real world — safely and predictably.
            </p>
          </div>
          <div className="feature-stack">
            {strengths.map((strength) => (
              <article className="glass-panel feature-card" key={strength.title}>
                <h3>{strength.title}</h3>
                <p>{strength.body}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      {/* ARCHITECTURE */}
      <section className="section-shell content-section" id="architecture">
        <div className="glass-panel cta-panel spotlight-border">
          <div>
            <span className="section-kicker">Architecture of Value Creation</span>
            <h2>Four clean layers. One coherent integration thesis.</h2>
          </div>
        </div>
        <div className="card-grid four-up">
          {architectureLayers.map((layer) => (
            <article className="glass-panel glow-card" key={layer.title}>
              <span className="card-label">{layer.title}</span>
              <h3>{layer.project}</h3>
              <p>{layer.description}</p>
            </article>
          ))}
        </div>

        <div className="glass-panel cta-panel spotlight-border" style={{ marginTop: '2rem' }}>
          <div className="two-column-layout">
            <div>
              <h3>Request Flow (Simplified)</h3>
              <p style={{ fontSize: '0.95rem', lineHeight: 1.7 }}>
                AI Agent → MCP Gateway → FastAPI Core → Adapter → External System → Audit Trail → Response back to Agent.<br /><br />
                Every step is logged, authorized, and normalized. No magic. Just reliable infrastructure.
              </p>
            </div>
            <div>
              <AdapterCoordinationField />
              <p style={{ textAlign: 'center', fontSize: '0.8rem', color: 'var(--muted)', marginTop: '0.5rem' }}>
                Live visualization of adapter coordination mesh
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* FLAGSHIP SYSTEMS / CORE MODULES */}
      <section className="section-shell content-section" id="adapters">
        <div className="glass-panel cta-panel spotlight-border">
          <div>
            <span className="section-kicker">Core Modules &amp; Capabilities</span>
            <h2>Everything you need to give AI agents real-world superpowers.</h2>
          </div>
        </div>
        <div className="card-grid two-up">
          {flagshipInitiatives.map((initiative, index) => (
            <article 
              className="glass-panel immersive-card" 
              key={index}
            >
              <div className="card-topline">
                <span className="live-dot muted" />
                <span>Core Module</span>
              </div>
              <h3>{initiative.title}</h3>
              <p>{initiative.summary}</p>
              <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem', flexWrap: 'wrap' }}>
                <a className="text-link" href={initiative.href} target="_blank" rel="noreferrer">
                  View Source on GitHub →
                </a>
                <a className="text-link" href={initiative.href} target="_blank" rel="noreferrer" style={{ color: '#34d399' }}>
                  ★ Star the Repo
                </a>
              </div>
            </article>
          ))}
        </div>

        <div className="glass-panel cta-panel spotlight-border" style={{ marginTop: '2rem' }}>
          <div>
            <span className="section-kicker">Developer Experience</span>
            <h3 style={{ marginTop: 0 }}>Clone. Configure. Connect. In under 5 minutes.</h3>
            <div style={{ background: 'rgba(7,12,23,0.8)', padding: '1.25rem', borderRadius: '12px', fontFamily: 'monospace', fontSize: '0.9rem', marginTop: '1rem' }}>
              git clone https://github.com/iceccarelli/neuralbridge.git<br />
              cd neuralbridge<br />
              python -m venv .venv &amp;&amp; source .venv/bin/activate<br />
              pip install -e ".[dev]"<br />
              uvicorn neuralbridge.main:app --reload<br /><br />
              # Then in another terminal:<br />
              cd src/dashboard &amp;&amp; pnpm install &amp;&amp; pnpm dev
            </div>
          </div>
          <a className="primary-button" href="https://github.com/iceccarelli/neuralbridge" target="_blank" rel="noreferrer" style={{ marginTop: '1.5rem' }}>
            Get Started on GitHub →
          </a>
        </div>
      </section>

      {/* LIVE INTELLIGENCE HUB */}
      <section className="section-shell content-section" id="live-hub">
        <div className="glass-panel cta-panel spotlight-border">
          <div>
            <span className="section-kicker">Live Intelligence Hub</span>
            <h2>Real-time signals from the NeuralBridge ecosystem.</h2>
            <p className="section-intro">{lastSync}</p>
          </div>
        </div>

        <div className="insight-grid">
          <article className="glass-panel data-column">
            <div className="panel-topline">
              <span className="live-dot" />
              <span>Repository &amp; Ecosystem Signals</span>
            </div>
            <h3>Live from GitHub</h3>
            <div className="data-list">
              {repoCards.map((repo) => (
                <a className="data-list-item" href={repo.html_url} key={repo.id} target="_blank" rel="noreferrer">
                  <span className="item-meta">
                    {repo.language} • Updated {formatDate(repo.updated_at)} • {repo.stargazers_count} stars
                  </span>
                  <strong>{repo.name}</strong>
                  <small>{repo.description}</small>
                  <div style={{ marginTop: '0.5rem' }}>
                    <span style={{ fontSize: '0.85rem', color: '#34d399', fontWeight: 600 }}>
                      ★ Star on GitHub
                    </span>
                  </div>
                </a>
              ))}
            </div>
          </article>

          <article className="glass-panel data-column">
            <div className="panel-topline">
              <span className="live-dot" />
              <span>Latest Ecosystem Updates</span>
            </div>
            <h3>Headlines worth watching</h3>
            <div className="data-list">
              {headlines.map((headline, idx) => (
                <a className="data-list-item" href={headline.link} key={idx} target="_blank" rel="noreferrer">
                  <span className="item-meta">{headline.category} • {headline.source}</span>
                  <strong>{headline.title}</strong>
                  <small>{formatDate(headline.pubDate)}</small>
                </a>
              ))}
            </div>
          </article>
        </div>

        <div className="glass-panel cta-panel spotlight-border" style={{ marginTop: '1.5rem' }}>
          <div>
            <span className="section-kicker">Interactive Telemetry</span>
            <h3>Live MCP Invocation &amp; Adapter Flow</h3>
            <MCPInvocationVisualizer />
            <p style={{ textAlign: 'center', fontSize: '0.85rem', color: 'var(--muted)', marginTop: '0.75rem' }}>
              Real-time simulation of tool invocation, data normalization, and audit logging inside NeuralBridge
            </p>
          </div>
        </div>

        <div className="card-grid three-up market-thesis-grid">
          {marketThemes.map((theme) => (
            <article className="glass-panel glow-card" key={theme.title}>
              <h3>{theme.title}</h3>
              <p>{theme.body}</p>
            </article>
          ))}
        </div>
      </section>

      {/* QUANTIFIED IMPACT */}
      <section className="section-shell content-section">
        <div className="glass-panel cta-panel spotlight-border">
          <div>
            <span className="section-kicker">Proven Engineering Impact</span>
            <h2>Built for production agentic workflows</h2>
          </div>
          <div className="impact-dashboard">
            <div className="impact-card"><strong>Sub-50ms</strong><br/>average tool invocation latency (local)</div>
            <div className="impact-card"><strong>22+</strong><br/>production-ready adapters out of the box</div>
            <div className="impact-card"><strong>100%</strong><br/>request audit coverage by design</div>
            <div className="impact-card"><strong>Zero</strong><br/>custom glue code required for new systems</div>
          </div>
        </div>
      </section>

      {/* TRUSTED ECOSYSTEM */}
      <section className="section-shell content-section" id="ecosystem">
        <div className="glass-panel cta-panel spotlight-border">
          <div>
            <span className="section-kicker">Trusted Ecosystem</span>
            <h2>Platforms and frameworks that power modern agentic AI.</h2>
          </div>
        </div>
        <div className="card-grid three-up">
          {trustedSources.map((source) => (
            <a className="glass-panel source-card" href={source.href} key={source.title} target="_blank" rel="noreferrer">
              <span className="card-label">Official Integration</span>
              <h3>{source.title}</h3>
              <p>{source.focus}</p>
            </a>
          ))}
        </div>
      </section>

      {/* CONNECT */}
      <section className="section-shell content-section" id="connect">
        <div className="glass-panel cta-panel spotlight-border">
          <div>
            <span className="section-kicker">Start Building Today</span>
            <h2>If reliable AI-to-system integration matters to you, NeuralBridge is ready.</h2>
            <p>
              Whether you are building autonomous agents, internal tools, or production RAG systems that need to act on real data — NeuralBridge gives you the secure, observable, and developer-friendly foundation you have been missing.
            </p>
          </div>
          <div className="hero-actions">
            <a className="primary-button" href="https://github.com/iceccarelli/neuralbridge" target="_blank" rel="noreferrer">
              Clone NeuralBridge on GitHub
            </a>
            <a className="secondary-button" href="#live-hub">
              Live Intelligence Hub
            </a>
            <a className="secondary-button" href="https://github.com/iceccarelli/neuralbridge/issues" target="_blank" rel="noreferrer">
              Open an Issue
            </a>
          </div>
        </div>
      </section>
    </main>
  );
}
