
import { DNSQuery, FeatureStats } from '../types';

/**
 * Calculates Shannon Entropy for a given string
 */
export const calculateEntropy = (str: string): number => {
  const len = str.length;
  if (len === 0) return 0;
  
  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  
  return parseFloat(entropy.toFixed(3));
};

export const checkIpReputation = (ip: string): 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN' => {
  // Mock reputation database
  const maliciousIps = ['192.168.1.105', '45.33.22.11', '103.22.11.55', '185.22.11.33'];
  const suspiciousIps = ['192.168.1.200', '104.16.132.229']; 
  
  if (maliciousIps.includes(ip)) return 'MALICIOUS';
  if (suspiciousIps.includes(ip)) return 'SUSPICIOUS';
  if (ip.startsWith('192.168.')) return 'CLEAN';
  return 'UNKNOWN';
};

export const getStats = (logs: DNSQuery[]): FeatureStats => {
  if (logs.length === 0) {
    return { avgEntropy: 0, avgLength: 0, nxDomainRatio: 0, totalQueries: 0, uniqueSubdomains: 0 };
  }
  
  const totalQueries = logs.length;
  const avgEntropy = logs.reduce((acc, curr) => acc + curr.entropy, 0) / totalQueries;
  const avgLength = logs.reduce((acc, curr) => acc + curr.length, 0) / totalQueries;
  
  const subdomains = new Set(logs.map(l => l.query.split('.')[0]));
  
  return {
    avgEntropy: parseFloat(avgEntropy.toFixed(3)),
    avgLength: parseFloat(avgLength.toFixed(1)),
    nxDomainRatio: 0.12, // Simulated for demo purposes
    totalQueries,
    uniqueSubdomains: subdomains.size
  };
};

export const calculateThreatScore = (query: DNSQuery): number => {
  let score = 0;

  // 1. Entropy Factor (Max 40)
  // Entropy > 4.0 is suspicious, > 4.5 is highly suspicious
  if (query.entropy > 3.5) {
    score += Math.min(40, (query.entropy - 3.5) * 30);
  }

  // 2. Length Factor (Max 20)
  // Length > 50 is suspicious
  if (query.length > 40) {
    score += Math.min(20, (query.length - 40) * 0.5);
  }

  // 3. Response Code Factor (Max 15)
  if (query.responseCode === 'NXDOMAIN') {
    score += 15;
  } else if (query.responseCode === 'SERVFAIL') {
    score += 10;
  }

  // 4. Query Type Factor (Max 10)
  if (query.type === 'TXT') {
    score += 10;
  } else if (query.type === 'NULL') {
    score += 15;
  }

  // 5. Geo-location Factor (Max 15)
  // Simulated high-risk regions or unknown locations
  const highRiskLocations = ['Russia', 'China', 'North Korea', 'Iran', 'Unknown'];
  if (query.location && highRiskLocations.some(loc => query.location?.includes(loc))) {
    score += 15;
  } else if (!query.location || query.location === 'Resolving...') {
    score += 5;
  }

  // 6. Reputation Factor (Max 25)
  if (query.reputation === 'MALICIOUS') {
    score += 25;
  } else if (query.reputation === 'SUSPICIOUS') {
    score += 15;
  }

  return Math.min(100, Math.round(score));
};

export const classifyQuery = (query: Partial<DNSQuery>): { label: 'Normal' | 'Tunneling', confidence: number } => {
  const entropy = query.entropy ?? calculateEntropy(query.query ?? "");
  const length = query.length ?? (query.query?.length ?? 0);
  
  // Base classification on thresholds
  const entropyThreshold = 4.2;
  const lengthThreshold = 55;
  
  const isSuspicious = entropy > entropyThreshold || length > lengthThreshold;
  
  // If we have a threat score already, use it to refine confidence
  const score = query.threatScore ?? 0;
  const label = (isSuspicious || score > 60) ? 'Tunneling' as const : 'Normal' as const;
  
  let confidence = 0.85;
  if (label === 'Tunneling') {
    confidence = Math.min(0.99, 0.7 + (score / 200) + (Math.random() * 0.1));
  } else {
    confidence = Math.min(0.99, 0.8 + (Math.random() * 0.15));
  }

  return { label, confidence };
};

/**
 * Normalizes various log formats into a standard DNSQuery object
 */
const normalizeDNSQuery = (data: any): DNSQuery => {
  const query = data.query || data.domain || data.qname || data.Question || '';
  const entropy = calculateEntropy(query);
  const length = query.length;
  
  // Extract metadata - everything that isn't a core field
  const coreFields = ['id', 'timestamp', 'time', 'sourceIp', 'src_ip', 'client_ip', 'query', 'domain', 'qname', 'type', 'qtype', 'responseCode', 'rcode'];
  const metadata: Record<string, any> = {};
  Object.keys(data).forEach(key => {
    if (!coreFields.includes(key)) {
      metadata[key] = data[key];
    }
  });

  const queryObj: DNSQuery = {
    id: data.id || Math.random().toString(36).substr(2, 9),
    timestamp: data.timestamp || data.time || data.Timestamp || new Date().toISOString(),
    sourceIp: data.sourceIp || data.src_ip || data.client_ip || data.SourceIP || '192.168.1.1',
    query,
    type: (data.type || data.qtype || data.QueryType || 'A').toUpperCase(),
    responseCode: data.responseCode || data.rcode || data.ResponseCode || 'NOERROR',
    length,
    entropy,
    metadata,
    reputation: 'UNKNOWN',
    threatScore: 0, // Will be updated after classification
    ...classifyQuery({ query, length, entropy })
  };
  
  // Update reputation
  queryObj.reputation = checkIpReputation(queryObj.sourceIp);
  
  // Update threat score with full object
  queryObj.threatScore = calculateThreatScore(queryObj);
  return queryObj;
};

/**
 * Parses a string content (JSON, CSV, or plain text logs)
 */
export const parseLogContent = (content: string): DNSQuery[] => {
  const trimmed = content.trim();
  if (!trimmed) return [];

  // 1. Try parsing as a single JSON array or object
  try {
    const parsed = JSON.parse(trimmed);
    const items = Array.isArray(parsed) ? parsed : [parsed];
    return items.map(item => normalizeDNSQuery(item));
  } catch (e) {
    // Not a single JSON blob
  }

  const lines = trimmed.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  const queries: DNSQuery[] = [];

  // 2. Check for CSV
  const firstLine = lines[0];
  const isCSV = firstLine.includes(',') && !firstLine.includes('\t');
  
  if (isCSV) {
    const headers = firstLine.split(',').map(h => h.trim().replace(/^["']|["']$/g, ''));
    const likelyHeaders = ['query', 'domain', 'qname', 'ip', 'src', 'timestamp', 'time'];
    const hasHeaders = headers.some(h => likelyHeaders.some(lh => h.toLowerCase().includes(lh)));
    
    const dataLines = hasHeaders ? lines.slice(1) : lines;
    const currentHeaders = hasHeaders ? headers : ['timestamp', 'sourceIp', 'query', 'type', 'responseCode'];

    dataLines.forEach(line => {
      const parts = line.split(',').map(p => p.trim().replace(/^["']|["']$/g, ''));
      const obj: any = {};
      currentHeaders.forEach((h, i) => {
        if (parts[i] !== undefined) obj[h] = parts[i];
      });
      if (obj.query || obj.domain || parts.length >= 3) {
        queries.push(normalizeDNSQuery(obj));
      }
    });
    
    if (queries.length > 0) return queries;
  }

  // 3. Line-by-line JSON or Plain Text
  lines.forEach((line) => {
    // Try line-by-line JSON
    try {
      const data = JSON.parse(line);
      queries.push(normalizeDNSQuery(data));
      return;
    } catch (e) {}

    // Fallback to space/tab separated
    const parts = line.split(/[\t\s]+/);
    const queryStr = parts.find(p => p.includes('.') && !p.match(/^\d+$/));
    const ipStr = parts.find(p => p.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/));
    const type = parts.find(p => ['A', 'AAAA', 'TXT', 'CNAME', 'MX', 'NS'].includes(p.toUpperCase())) || 'A';
    
    if (queryStr) {
      queries.push(normalizeDNSQuery({
        query: queryStr,
        sourceIp: ipStr,
        type: type,
        timestamp: parts[0].length > 10 ? parts[0] : undefined // Heuristic for timestamp
      }));
    }
  });
  
  return queries;
};

export const generateMockData = (): DNSQuery[] => {
  const queries = [
    "google.com", "github.com", "microsoft.com", "amazon.aws", 
    "cdn.cloudflare.net", "api.stripe.com", "static.doubleclick.net"
  ];
  
  const malicious = [
    "v1.4a2b3c4d5e6f.tunnel.c2server.top",
    "init.base64encodedpayloadhere.attacker.xyz",
    "chunk1.deadbeef0011223344.exfil.dns",
    "a.b.c.d.e.f.g.h.root.io",
    "ping.1234567890abcdef.c2.net"
  ];
  
  const data: DNSQuery[] = [];
  const now = new Date();

  const publicIps = [
    '8.8.8.8', '1.1.1.1', '208.67.222.222', '64.233.160.0', '13.248.169.48',
    '104.16.132.229', '151.101.1.69', '172.217.1.14'
  ];

  for (let i = 0; i < 100; i++) {
    const isMalicious = Math.random() < 0.15;
    const baseDomain = isMalicious 
      ? malicious[Math.floor(Math.random() * malicious.length)]
      : queries[Math.floor(Math.random() * queries.length)];
    
    const queryStr = isMalicious ? baseDomain : (Math.random() > 0.5 ? `www.${baseDomain}` : baseDomain);
    
    const d = new Date(now.getTime() - (100 - i) * 10000);
    
    const entropy = calculateEntropy(queryStr);
    const sourceIp = isMalicious 
      ? (Math.random() > 0.5 ? '192.168.1.105' : publicIps[Math.floor(Math.random() * publicIps.length)])
      : (Math.random() > 0.7 ? publicIps[Math.floor(Math.random() * publicIps.length)] : `192.168.1.${Math.floor(Math.random() * 50) + 10}`);

    const queryObj: DNSQuery = {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: d.toISOString(),
      sourceIp,
      query: queryStr,
      type: Math.random() > 0.9 ? 'TXT' : 'A',
      responseCode: isMalicious && Math.random() > 0.5 ? 'NXDOMAIN' : 'NOERROR',
      length: queryStr.length,
      entropy: entropy,
      reputation: checkIpReputation(sourceIp),
      threatScore: 0,
    };

    const classification = classifyQuery(queryObj);
    queryObj.label = classification.label;
    queryObj.confidence = classification.confidence;
    queryObj.threatScore = calculateThreatScore(queryObj);

    data.push(queryObj);
  }
  
  return data;
};
