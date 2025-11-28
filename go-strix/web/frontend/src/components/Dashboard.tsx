import React, { useState, useCallback, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Header } from './Header';
import { ScanForm } from './ScanForm';
import { ScanStatus } from './ScanStatus';
import { VulnerabilityList } from './VulnerabilityList';
import { ActivityLog } from './ActivityLog';
import { useScan, type Vulnerability, type Scan } from '../hooks/useScan';
import { useWebSocket } from '../hooks/useWebSocket';
import { EndpointLogo } from './EndpointLogo';
import {
  Radar,
  History,
  Settings,
  HelpCircle,
  Sparkles,
  ArrowRight,
  Clock,
  Target,
  Shield,
  AlertTriangle,
} from 'lucide-react';

interface LogEntry {
  timestamp: string;
  stream: 'stdout' | 'stderr';
  line: string;
}

export function Dashboard() {
  const { isLoading, error, currentScan, setCurrentScan, createScan, stopScan, getWebSocketUrl, listScans, scans } =
    useScan();
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [wsUrl, setWsUrl] = useState<string | null>(null);
  const [view, setView] = useState<'new' | 'active' | 'history'>('new');

  // Fetch existing scans on mount
  useEffect(() => {
    listScans();
  }, [listScans]);

  const handleWebSocketMessage = useCallback((message: any) => {
    switch (message.type) {
      case 'init':
        setVulnerabilities(message.data.vulnerabilities || []);
        break;
      case 'output':
        setLogs((prev) => [
          ...prev,
          {
            timestamp: message.timestamp,
            stream: message.data.stream,
            line: message.data.line,
          },
        ]);
        break;
      case 'vulnerability':
        setVulnerabilities((prev) => [...prev, message.data]);
        break;
      case 'status':
        setCurrentScan((prev: Scan | null) =>
          prev ? { ...prev, status: message.data } : null
        );
        break;
      case 'error':
        console.error('Scan error:', message.data);
        break;
    }
  }, [setCurrentScan]);

  const { isConnected } = useWebSocket(wsUrl, {
    onMessage: handleWebSocketMessage,
  });

  const handleStartScan = async (data: { targets: string[]; instruction?: string; run_name?: string }) => {
    setLogs([]);
    setVulnerabilities([]);

    const scan = await createScan(data);
    if (scan) {
      setWsUrl(getWebSocketUrl(scan.id));
      setView('active');
    }
  };

  const handleStopScan = async () => {
    if (currentScan) {
      await stopScan(currentScan.id);
    }
  };

  return (
    <div className="min-h-screen">
      <Header isConnected={isConnected} />

      <main className="max-w-7xl mx-auto px-6 py-8">
        {/* View Tabs */}
        <div className="flex items-center gap-2 mb-8">
          <button
            onClick={() => setView('new')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-medium transition-all duration-300 ${
              view === 'new'
                ? 'bg-endpoint-500/10 text-endpoint-400 border border-endpoint-500/30'
                : 'text-dark-400 hover:text-white hover:bg-dark-800'
            }`}
          >
            <Sparkles className="w-4 h-4" />
            New Scan
          </button>
          <button
            onClick={() => setView('active')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-medium transition-all duration-300 ${
              view === 'active'
                ? 'bg-endpoint-500/10 text-endpoint-400 border border-endpoint-500/30'
                : 'text-dark-400 hover:text-white hover:bg-dark-800'
            }`}
          >
            <Radar className="w-4 h-4" />
            Active Scan
            {currentScan?.status === 'running' && (
              <span className="w-2 h-2 rounded-full bg-endpoint-400 animate-pulse" />
            )}
          </button>
          <button
            onClick={() => setView('history')}
            className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-medium transition-all duration-300 ${
              view === 'history'
                ? 'bg-endpoint-500/10 text-endpoint-400 border border-endpoint-500/30'
                : 'text-dark-400 hover:text-white hover:bg-dark-800'
            }`}
          >
            <History className="w-4 h-4" />
            History
          </button>
        </div>

        <AnimatePresence mode="wait">
          {/* New Scan View */}
          {view === 'new' && (
            <motion.div
              key="new"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="grid grid-cols-1 lg:grid-cols-2 gap-8"
            >
              <ScanForm onSubmit={handleStartScan} isLoading={isLoading} />

              {/* Quick Start Guide */}
              <div className="space-y-6">
                <div className="glass-card p-6">
                  <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                    <HelpCircle className="w-5 h-5 text-endpoint-400" />
                    Quick Start
                  </h3>
                  <div className="space-y-4">
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 rounded-lg bg-endpoint-500/10 flex items-center justify-center text-endpoint-400 font-bold shrink-0">
                        1
                      </div>
                      <div>
                        <h4 className="font-medium text-white">Add Target</h4>
                        <p className="text-sm text-dark-400">
                          Enter a URL, GitHub repo, or local path to scan
                        </p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 rounded-lg bg-endpoint-500/10 flex items-center justify-center text-endpoint-400 font-bold shrink-0">
                        2
                      </div>
                      <div>
                        <h4 className="font-medium text-white">Configure (Optional)</h4>
                        <p className="text-sm text-dark-400">
                          Add custom instructions to focus on specific vulnerabilities
                        </p>
                      </div>
                    </div>
                    <div className="flex items-start gap-3">
                      <div className="w-8 h-8 rounded-lg bg-endpoint-500/10 flex items-center justify-center text-endpoint-400 font-bold shrink-0">
                        3
                      </div>
                      <div>
                        <h4 className="font-medium text-white">Launch</h4>
                        <p className="text-sm text-dark-400">
                          Watch as AI agents discover and validate vulnerabilities
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Supported Targets */}
                <div className="glass-card p-6">
                  <h3 className="text-lg font-semibold text-white mb-4">Supported Targets</h3>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      { icon: '🌐', label: 'URLs', example: 'https://example.com' },
                      { icon: '📦', label: 'GitHub Repos', example: 'github.com/org/repo' },
                      { icon: '📁', label: 'Local Paths', example: './my-app' },
                      { icon: '🖥️', label: 'IP Addresses', example: '192.168.1.1' },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className="p-3 rounded-lg bg-dark-800/50 border border-dark-700/50"
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span>{item.icon}</span>
                          <span className="font-medium text-dark-200">{item.label}</span>
                        </div>
                        <code className="text-xs text-dark-500">{item.example}</code>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {/* Active Scan View */}
          {view === 'active' && (
            <motion.div
              key="active"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="space-y-6"
            >
              {currentScan ? (
                <>
                  <ScanStatus
                    scan={{
                      ...currentScan,
                      vulnerabilities,
                    }}
                    onStop={handleStopScan}
                  />

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <VulnerabilityList vulnerabilities={vulnerabilities} />
                    <ActivityLog logs={logs} onClear={() => setLogs([])} />
                  </div>
                </>
              ) : (
                <div className="glass-card p-12 text-center">
                  <EndpointLogo size="lg" className="mx-auto mb-6" />
                  <h3 className="text-xl font-semibold text-white mb-2">No Active Scan</h3>
                  <p className="text-dark-400 mb-6">
                    Start a new penetration test to see real-time results here
                  </p>
                  <button onClick={() => setView('new')} className="btn-primary">
                    <Sparkles className="w-4 h-4 mr-2 inline" />
                    Start New Scan
                  </button>
                </div>
              )}
            </motion.div>
          )}

          {/* History View */}
          {view === 'history' && (
            <motion.div
              key="history"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
            >
              <div className="glass-card p-6">
                <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
                  <History className="w-5 h-5 text-endpoint-400" />
                  Scan History
                </h2>

                {scans.length === 0 ? (
                  <div className="text-center py-12">
                    <Clock className="w-12 h-12 text-dark-600 mx-auto mb-4" />
                    <p className="text-dark-400">No previous scans found</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {scans.map((scan) => (
                      <div
                        key={scan.id}
                        className="flex items-center justify-between p-4 rounded-xl bg-dark-800/50 border border-dark-700/50 hover:bg-dark-800 transition-colors cursor-pointer"
                      >
                        <div className="flex items-center gap-4">
                          <div className="p-2 rounded-lg bg-dark-700">
                            <Target className="w-5 h-5 text-endpoint-400" />
                          </div>
                          <div>
                            <h4 className="font-medium text-white">{scan.id}</h4>
                            <p className="text-sm text-dark-400">
                              {scan.targets.join(', ')}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-4">
                          <div className="text-right">
                            <div className="flex items-center gap-2">
                              <AlertTriangle className="w-4 h-4 text-orange-400" />
                              <span className="text-dark-200">
                                {(scan as any).vulnerabilities || 0} vulnerabilities
                              </span>
                            </div>
                            <p className="text-xs text-dark-500">
                              {new Date(scan.start_time).toLocaleDateString()}
                            </p>
                          </div>
                          <ArrowRight className="w-5 h-5 text-dark-500" />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Error Display */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="fixed bottom-6 right-6 max-w-md p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400"
          >
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
              <div>
                <h4 className="font-medium">Error</h4>
                <p className="text-sm opacity-80">{error}</p>
              </div>
            </div>
          </motion.div>
        )}
      </main>
    </div>
  );
}
