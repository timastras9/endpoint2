import React, { useRef, useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Terminal,
  ChevronDown,
  ChevronUp,
  Search,
  Download,
  Trash2,
  Maximize2,
  Minimize2,
} from 'lucide-react';
import { cn } from '../lib/utils';

interface LogEntry {
  timestamp: string;
  stream: 'stdout' | 'stderr';
  line: string;
}

interface ActivityLogProps {
  logs: LogEntry[];
  onClear?: () => void;
}

export function ActivityLog({ logs, onClear }: ActivityLogProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filter, setFilter] = useState('');
  const [showStderr, setShowStderr] = useState(true);
  const [isExpanded, setIsExpanded] = useState(false);

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 50;
    setAutoScroll(isAtBottom);
  };

  const filteredLogs = logs.filter((log) => {
    if (!showStderr && log.stream === 'stderr') return false;
    if (filter && !log.line.toLowerCase().includes(filter.toLowerCase())) return false;
    return true;
  });

  const getLineStyle = (line: string) => {
    if (line.includes('ERROR') || line.includes('error') || line.includes('Error')) {
      return 'text-red-400';
    }
    if (line.includes('WARNING') || line.includes('warning') || line.includes('Warning')) {
      return 'text-yellow-400';
    }
    if (line.includes('SUCCESS') || line.includes('success') || line.includes('✅')) {
      return 'text-endpoint-400';
    }
    if (line.includes('VULNERABILITY') || line.includes('🐞')) {
      return 'text-red-400 font-semibold';
    }
    if (line.startsWith('>>>') || line.startsWith('$')) {
      return 'text-endpoint-300';
    }
    return 'text-dark-300';
  };

  const downloadLogs = () => {
    const content = logs.map((l) => `[${l.stream}] ${l.line}`).join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `endpoint-log-${new Date().toISOString()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className={cn(
        'glass-card overflow-hidden flex flex-col transition-all duration-300',
        isExpanded ? 'fixed inset-4 z-50' : ''
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-dark-800">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-dark-800">
            <Terminal className="w-5 h-5 text-endpoint-400" />
          </div>
          <div>
            <h3 className="font-semibold text-white">Activity Log</h3>
            <p className="text-xs text-dark-400">{logs.length} entries</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-500" />
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter logs..."
              className="pl-9 pr-3 py-1.5 w-48 text-sm bg-dark-800 border border-dark-700 rounded-lg text-dark-200 placeholder-dark-500 focus:outline-none focus:border-endpoint-500/50"
            />
          </div>

          {/* Toggle stderr */}
          <button
            onClick={() => setShowStderr(!showStderr)}
            className={cn(
              'px-3 py-1.5 rounded-lg text-sm transition-colors',
              showStderr
                ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                : 'bg-dark-800 text-dark-400 border border-dark-700'
            )}
          >
            stderr
          </button>

          {/* Auto-scroll indicator */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={cn(
              'p-1.5 rounded-lg transition-colors',
              autoScroll
                ? 'bg-endpoint-500/10 text-endpoint-400'
                : 'bg-dark-800 text-dark-400'
            )}
            title={autoScroll ? 'Auto-scroll enabled' : 'Auto-scroll disabled'}
          >
            {autoScroll ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
          </button>

          {/* Download */}
          <button
            onClick={downloadLogs}
            className="p-1.5 rounded-lg bg-dark-800 text-dark-400 hover:text-white transition-colors"
            title="Download logs"
          >
            <Download className="w-4 h-4" />
          </button>

          {/* Clear */}
          {onClear && (
            <button
              onClick={onClear}
              className="p-1.5 rounded-lg bg-dark-800 text-dark-400 hover:text-red-400 transition-colors"
              title="Clear logs"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          )}

          {/* Expand */}
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1.5 rounded-lg bg-dark-800 text-dark-400 hover:text-white transition-colors"
            title={isExpanded ? 'Minimize' : 'Maximize'}
          >
            {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Log Content */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className={cn(
          'flex-1 overflow-auto terminal',
          isExpanded ? 'max-h-[calc(100vh-120px)]' : 'max-h-[400px]'
        )}
      >
        {filteredLogs.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-dark-500">
            <p>No log entries{filter ? ' matching filter' : ''}</p>
          </div>
        ) : (
          <div className="py-2">
            <AnimatePresence initial={false}>
              {filteredLogs.map((log, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  className={cn(
                    'terminal-line flex gap-3',
                    log.stream === 'stderr' && 'bg-red-500/5'
                  )}
                >
                  <span className="text-dark-600 select-none shrink-0 w-12 text-right">
                    {index + 1}
                  </span>
                  <span className={cn('whitespace-pre-wrap break-all', getLineStyle(log.line))}>
                    {log.line}
                  </span>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between px-4 py-2 border-t border-dark-800 text-xs text-dark-500">
        <span>
          Showing {filteredLogs.length} of {logs.length} entries
        </span>
        {autoScroll && (
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-endpoint-400 animate-pulse" />
            Live
          </span>
        )}
      </div>
    </div>
  );
}
