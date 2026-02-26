
export enum ThreatLevel {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface DNSQuery {
  id: string;
  timestamp: string;
  sourceIp: string;
  query: string;
  type: string;
  responseCode?: string;
  length: number;
  entropy: number;
  location?: string;
  lat?: number;
  lng?: number;
  label?: 'Normal' | 'Tunneling';
  confidence?: number;
  threatScore: number;
  reputation?: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  isNew?: boolean;
  metadata?: Record<string, any>;
}

export interface ForensicReport {
  summary: string;
  threatLevel: ThreatLevel;
  indicators: string[];
  timeline: { time: string; event: string }[];
  recommendation: string;
  detectedTunnels: string[];
}

export interface FeatureStats {
  avgEntropy: number;
  avgLength: number;
  nxDomainRatio: number;
  totalQueries: number;
  uniqueSubdomains: number;
}

export interface Alert {
  id: string;
  timestamp: string;
  type: 'TUNNELING_DETECTED' | 'HIGH_ENTROPY' | 'C2_PATTERN';
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  message: string;
  queryId: string;
  isRead: boolean;
}

export interface AppState {
  logs: DNSQuery[];
  liveLogs: DNSQuery[];
  alerts: Alert[];
  isAnalyzing: boolean;
  isLive: boolean;
  activeView: 'dashboard' | 'logs' | 'forensics' | 'reports' | 'live' | 'alerts' | 'map';
  stats: FeatureStats | null;
  report: ForensicReport | null;
}
