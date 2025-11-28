import { useState, useCallback } from 'react';

const API_BASE = 'http://localhost:8080/api';

export interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  found_at: string;
}

export interface AgentEvent {
  agent_id: string;
  event_type: string;
  message: string;
  tool?: string;
  timestamp?: string;
}

export interface Scan {
  id: string;
  status: 'starting' | 'running' | 'completed' | 'error' | 'stopped';
  targets: string[];
  start_time: string;
  vulnerabilities: Vulnerability[];
  events: AgentEvent[];
}

export interface ScanRequest {
  targets: string[];
  instruction?: string;
  run_name?: string;
}

export function useScan() {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentScan, setCurrentScan] = useState<Scan | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);

  const createScan = useCallback(async (request: ScanRequest): Promise<Scan | null> => {
    setIsLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        throw new Error(`Failed to create scan: ${response.statusText}`);
      }

      const scan = await response.json();
      setCurrentScan(scan);
      return scan;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(message);
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const getScan = useCallback(async (id: string): Promise<Scan | null> => {
    try {
      const response = await fetch(`${API_BASE}/scans/${id}`);
      if (!response.ok) {
        throw new Error(`Failed to get scan: ${response.statusText}`);
      }
      const scan = await response.json();
      setCurrentScan(scan);
      return scan;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(message);
      return null;
    }
  }, []);

  const listScans = useCallback(async (): Promise<Scan[]> => {
    try {
      const response = await fetch(`${API_BASE}/scans`);
      if (!response.ok) {
        throw new Error(`Failed to list scans: ${response.statusText}`);
      }
      const scanList = await response.json();
      setScans(scanList);
      return scanList;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(message);
      return [];
    }
  }, []);

  const stopScan = useCallback(async (id: string): Promise<boolean> => {
    try {
      const response = await fetch(`${API_BASE}/scans/${id}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        throw new Error(`Failed to stop scan: ${response.statusText}`);
      }
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(message);
      return false;
    }
  }, []);

  const getWebSocketUrl = useCallback((scanId: string): string => {
    return `ws://localhost:8080/api/scans/${scanId}/ws`;
  }, []);

  return {
    isLoading,
    error,
    currentScan,
    scans,
    setCurrentScan,
    createScan,
    getScan,
    listScans,
    stopScan,
    getWebSocketUrl,
  };
}
