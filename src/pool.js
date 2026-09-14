import fs from 'node:fs/promises';
import pLimit from 'p-limit';
import { fetchProxySources } from './sources.js';
import { requestViaProxy } from './proxy.js';

export class ProxyPool {
  constructor(config) {
    this.config = config;
    this.nodes = new Map();
    this.sourceStats = [];
    this.lastSourceRefresh = null;
    this.lastHealthSweep = null;
    this.cursor = 0;
  }

  async loadState() {
    try {
      const data = JSON.parse(await fs.readFile('/app/data/proxy-state.json', 'utf8'));
      for (const node of data.nodes || []) this.nodes.set(node.id, node);
    } catch {}
  }

  async saveState() {
    try {
      await fs.mkdir('/app/data', { recursive: true });
      await fs.writeFile('/app/data/proxy-state.json', JSON.stringify({ savedAt: new Date().toISOString(), nodes: [...this.nodes.values()] }, null, 2));
    } catch (error) {
      console.error('[state] save failed:', error.message);
    }
  }

  async refreshSources() {
    const { proxies, sourceStats } = await fetchProxySources(this.config.maxProxies);
    const old = this.nodes;

    // Never erase the last known pool just because every upstream source is temporarily unavailable.
    if (!proxies.length && old.size) {
      this.sourceStats = sourceStats;
      this.lastSourceRefresh = new Date().toISOString();
      await this.saveState();
      return { count: old.size, retained: true, sourceStats };
    }

    const next = new Map();
    for (const incoming of proxies) {
      const previous = old.get(incoming.id);
      if (!previous) {
        next.set(incoming.id, incoming);
        continue;
      }
      next.set(incoming.id, {
        ...incoming,
        status: previous.status,
        latencyMs: previous.latencyMs,
        exitIp: previous.exitIp,
        successes: previous.successes || 0,
        failures: previous.failures || 0,
        consecutiveFailures: previous.consecutiveFailures || 0,
        lastCheck: previous.lastCheck || null,
        lastSuccess: previous.lastSuccess || null,
        lastError: previous.lastError || null
      });
    }
    this.nodes = next;
    this.sourceStats = sourceStats;
    this.lastSourceRefresh = new Date().toISOString();
    await this.saveState();
    return { count: next.size, sourceStats };
  }

  async checkNode(node) {
    const checkedAt = new Date().toISOString();
    try {
      const result = await requestViaProxy(node, this.config.healthcheckUrl, {
        timeoutMs: this.config.healthTimeoutMs,
        maxBytes: 8192
      });
      if (result.statusCode < 200 || result.statusCode >= 400) throw new Error(`health endpoint HTTP ${result.statusCode}`);
      let exitIp = null;
      try { exitIp = JSON.parse(result.body).ip || null; } catch {}
      Object.assign(node, {
        status: 'online',
        latencyMs: result.latencyMs,
        exitIp,
        successes: (node.successes || 0) + 1,
        consecutiveFailures: 0,
        lastCheck: checkedAt,
        lastSuccess: checkedAt
      });
    } catch (error) {
      const failures = (node.failures || 0) + 1;
      const consecutiveFailures = (node.consecutiveFailures || 0) + 1;
      Object.assign(node, {
        status: consecutiveFailures >= 2 ? 'offline' : 'degraded',
        failures,
        consecutiveFailures,
        lastCheck: checkedAt,
        lastError: String(error.message || error).slice(0, 180)
      });
    }
  }

  async healthSweep() {
    const nodes = [...this.nodes.values()];
    if (!nodes.length) return;
    const batch = [];
    for (let i = 0; i < Math.min(this.config.healthBatchSize, nodes.length); i++) {
      batch.push(nodes[(this.cursor + i) % nodes.length]);
    }
    this.cursor = (this.cursor + batch.length) % nodes.length;
    const limit = pLimit(12);
    await Promise.allSettled(batch.map(node => limit(() => this.checkNode(node))));
    this.lastHealthSweep = new Date().toISOString();
    await this.saveState();
  }

  score(node) {
    const total = (node.successes || 0) + (node.failures || 0);
    const reliability = total ? (node.successes || 0) / total : 0.3;
    const latency = node.latencyMs ?? 6000;
    const source = Math.max(0, Math.min(1, Number(node.sourceScore || 0)));
    return reliability * 70 + source * 20 + Math.max(0, 10 - latency / 700);
  }

  select({ country, region, protocol } = {}) {
    return [...this.nodes.values()]
      .filter(n => n.status === 'online')
      .filter(n => !country || n.country === country)
      .filter(n => !region || n.region === region)
      .filter(n => !protocol || n.protocol === protocol)
      .sort((a,b) => this.score(b) - this.score(a))[0] || null;
  }

  list(filters = {}) {
    return [...this.nodes.values()]
      .filter(n => !filters.status || n.status === filters.status)
      .filter(n => !filters.country || n.country === filters.country)
      .filter(n => !filters.region || n.region === filters.region)
      .filter(n => !filters.protocol || n.protocol === filters.protocol)
      .sort((a,b) => this.score(b) - this.score(a));
  }

  stats() {
    const nodes = [...this.nodes.values()];
    const countBy = key => nodes.reduce((acc,n) => { const v=n[key] || 'Unknown'; acc[v]=(acc[v]||0)+1; return acc; }, {});
    return {
      total: nodes.length,
      online: nodes.filter(n=>n.status==='online').length,
      degraded: nodes.filter(n=>n.status==='degraded').length,
      offline: nodes.filter(n=>n.status==='offline').length,
      unchecked: nodes.filter(n=>n.status==='unknown').length,
      byProtocol: countBy('protocol'),
      byCountry: countBy('country'),
      byRegion: countBy('region'),
      lastSourceRefresh: this.lastSourceRefresh,
      lastHealthSweep: this.lastHealthSweep,
      sourceStats: this.sourceStats
    };
  }
}
