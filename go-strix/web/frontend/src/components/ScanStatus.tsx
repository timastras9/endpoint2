import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  Clock,
  Target,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Pause,
  Loader2,
  StopCircle,
  Bug,
  Shield,
} from 'lucide-react';
import { formatDuration, getStatusColor, getStatusBg, cn } from '../lib/utils';

interface ScanStatusProps {
  scan: {
    id: string;
    status: string;
    targets: string[];
    start_time: string;
    vulnerabilities?: any[];
  };
  onStop?: () => void;
}

export function ScanStatus({ scan, onStop }: ScanStatusProps) {
  const [elapsed, setElapsed] = useState('0s');

  useEffect(() => {
    const interval = setInterval(() => {
      setElapsed(formatDuration(scan.start_time));
    }, 1000);
    return () => clearInterval(interval);
  }, [scan.start_time]);

  const getStatusIcon = () => {
    switch (scan.status) {
      case 'starting':
        return <Loader2 className="w-5 h-5 animate-spin" />;
      case 'running':
        return <Activity className="w-5 h-5 animate-pulse" />;
      case 'completed':
        return <CheckCircle2 className="w-5 h-5" />;
      case 'error':
        return <XCircle className="w-5 h-5" />;
      case 'stopped':
        return <Pause className="w-5 h-5" />;
      default:
        return <Activity className="w-5 h-5" />;
    }
  };

  const vulnCount = scan.vulnerabilities?.length || 0;
  const criticalCount = scan.vulnerabilities?.filter((v: any) => v.severity === 'critical').length || 0;
  const highCount = scan.vulnerabilities?.filter((v: any) => v.severity === 'high').length || 0;

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="glass-card p-6"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-4">
          <div className={cn('p-3 rounded-xl border', getStatusBg(scan.status), getStatusColor(scan.status))}>
            {getStatusIcon()}
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">{scan.id}</h3>
            <p className="text-sm text-dark-400">
              {scan.targets.length} target{scan.targets.length > 1 ? 's' : ''}
            </p>
          </div>
        </div>

        {(scan.status === 'running' || scan.status === 'starting') && onStop && (
          <button
            onClick={onStop}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500/20 transition-all duration-300"
          >
            <StopCircle className="w-4 h-4" />
            Stop Scan
          </button>
        )}
      </div>

      {/* Status Bar */}
      {scan.status === 'running' && (
        <div className="mb-6">
          <div className="h-1 bg-dark-800 rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-gradient-to-r from-endpoint-500 to-endpoint-400"
              initial={{ width: '0%' }}
              animate={{ width: '100%' }}
              transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
            />
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Status */}
        <div className="p-4 rounded-xl bg-dark-800/50 border border-dark-700/50">
          <div className="flex items-center gap-2 text-dark-400 mb-1">
            <Shield className="w-4 h-4" />
            <span className="text-xs font-medium uppercase tracking-wide">Status</span>
          </div>
          <p className={cn('text-lg font-semibold capitalize', getStatusColor(scan.status))}>
            {scan.status}
          </p>
        </div>

        {/* Duration */}
        <div className="p-4 rounded-xl bg-dark-800/50 border border-dark-700/50">
          <div className="flex items-center gap-2 text-dark-400 mb-1">
            <Clock className="w-4 h-4" />
            <span className="text-xs font-medium uppercase tracking-wide">Duration</span>
          </div>
          <p className="text-lg font-semibold text-white">{elapsed}</p>
        </div>

        {/* Vulnerabilities */}
        <div className="p-4 rounded-xl bg-dark-800/50 border border-dark-700/50">
          <div className="flex items-center gap-2 text-dark-400 mb-1">
            <Bug className="w-4 h-4" />
            <span className="text-xs font-medium uppercase tracking-wide">Found</span>
          </div>
          <p className="text-lg font-semibold text-white">
            {vulnCount}
            {vulnCount > 0 && (
              <span className="text-sm font-normal text-dark-400 ml-2">
                vulnerabilities
              </span>
            )}
          </p>
        </div>

        {/* Critical/High */}
        <div className="p-4 rounded-xl bg-dark-800/50 border border-dark-700/50">
          <div className="flex items-center gap-2 text-dark-400 mb-1">
            <AlertTriangle className="w-4 h-4" />
            <span className="text-xs font-medium uppercase tracking-wide">Critical/High</span>
          </div>
          <div className="flex items-center gap-2">
            {criticalCount > 0 && (
              <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 text-sm font-semibold">
                {criticalCount}
              </span>
            )}
            {highCount > 0 && (
              <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-400 text-sm font-semibold">
                {highCount}
              </span>
            )}
            {criticalCount === 0 && highCount === 0 && (
              <span className="text-lg font-semibold text-endpoint-400">0</span>
            )}
          </div>
        </div>
      </div>

      {/* Targets */}
      <div className="mt-6 pt-6 border-t border-dark-800">
        <div className="flex items-center gap-2 text-dark-400 mb-3">
          <Target className="w-4 h-4" />
          <span className="text-xs font-medium uppercase tracking-wide">Targets</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {scan.targets.map((target, index) => (
            <span
              key={index}
              className="px-3 py-1.5 rounded-lg bg-dark-800 text-dark-200 text-sm font-mono border border-dark-700"
            >
              {target}
            </span>
          ))}
        </div>
      </div>
    </motion.div>
  );
}
