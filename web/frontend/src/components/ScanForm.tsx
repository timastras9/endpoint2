import React, { useState } from 'react';
import { Target, FileText, Play, Plus, X, Zap, Globe, Github, Folder } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface ScanFormProps {
  onSubmit: (data: { targets: string[]; instruction?: string; run_name?: string }) => void;
  isLoading?: boolean;
}

export function ScanForm({ onSubmit, isLoading = false }: ScanFormProps) {
  const [targets, setTargets] = useState<string[]>(['']);
  const [instruction, setInstruction] = useState('');
  const [runName, setRunName] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const addTarget = () => {
    setTargets([...targets, '']);
  };

  const removeTarget = (index: number) => {
    if (targets.length > 1) {
      setTargets(targets.filter((_, i) => i !== index));
    }
  };

  const updateTarget = (index: number, value: string) => {
    const updated = [...targets];
    updated[index] = value;
    setTargets(updated);
  };

  const getTargetIcon = (target: string) => {
    if (target.includes('github.com')) return <Github className="w-4 h-4 text-dark-400" />;
    if (target.startsWith('http')) return <Globe className="w-4 h-4 text-dark-400" />;
    if (target.startsWith('/') || target.startsWith('./')) return <Folder className="w-4 h-4 text-dark-400" />;
    return <Target className="w-4 h-4 text-dark-400" />;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const validTargets = targets.filter(t => t.trim());
    if (validTargets.length === 0) return;

    onSubmit({
      targets: validTargets,
      instruction: instruction || undefined,
      run_name: runName || undefined,
    });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card glow-border p-8"
    >
      <div className="flex items-center gap-3 mb-6">
        <div className="p-3 rounded-xl bg-endpoint-500/10 border border-endpoint-500/20">
          <Zap className="w-6 h-6 text-endpoint-400" />
        </div>
        <div>
          <h2 className="text-xl font-bold text-white">New Penetration Test</h2>
          <p className="text-sm text-dark-400">Configure and launch an AI-powered security scan</p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Targets */}
        <div className="space-y-3">
          <label className="block text-sm font-medium text-dark-200">
            Targets
            <span className="text-dark-500 font-normal ml-2">URL, GitHub repo, or local path</span>
          </label>

          <AnimatePresence mode="popLayout">
            {targets.map((target, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="flex items-center gap-2"
              >
                <div className="relative flex-1">
                  <div className="absolute left-4 top-1/2 -translate-y-1/2">
                    {getTargetIcon(target)}
                  </div>
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => updateTarget(index, e.target.value)}
                    placeholder="https://example.com or ./my-app"
                    className="input-field pl-12"
                  />
                </div>
                {targets.length > 1 && (
                  <button
                    type="button"
                    onClick={() => removeTarget(index)}
                    className="p-3 rounded-xl bg-dark-800 hover:bg-red-500/10 text-dark-400 hover:text-red-400 transition-all duration-300 border border-dark-700 hover:border-red-500/30"
                  >
                    <X className="w-5 h-5" />
                  </button>
                )}
              </motion.div>
            ))}
          </AnimatePresence>

          <button
            type="button"
            onClick={addTarget}
            className="flex items-center gap-2 text-sm text-endpoint-400 hover:text-endpoint-300 transition-colors"
          >
            <Plus className="w-4 h-4" />
            Add another target
          </button>
        </div>

        {/* Advanced Options Toggle */}
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-2 text-sm text-dark-400 hover:text-dark-200 transition-colors"
        >
          <motion.span
            animate={{ rotate: showAdvanced ? 90 : 0 }}
            transition={{ duration: 0.2 }}
          >
            ▶
          </motion.span>
          Advanced Options
        </button>

        <AnimatePresence>
          {showAdvanced && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="space-y-4 overflow-hidden"
            >
              {/* Custom Instructions */}
              <div>
                <label className="block text-sm font-medium text-dark-200 mb-2">
                  <FileText className="w-4 h-4 inline mr-2" />
                  Custom Instructions
                  <span className="text-dark-500 font-normal ml-2">Optional</span>
                </label>
                <textarea
                  value={instruction}
                  onChange={(e) => setInstruction(e.target.value)}
                  placeholder="Focus on IDOR vulnerabilities and authentication bypass..."
                  rows={3}
                  className="input-field resize-none"
                />
              </div>

              {/* Run Name */}
              <div>
                <label className="block text-sm font-medium text-dark-200 mb-2">
                  Run Name
                  <span className="text-dark-500 font-normal ml-2">Optional</span>
                </label>
                <input
                  type="text"
                  value={runName}
                  onChange={(e) => setRunName(e.target.value)}
                  placeholder="my-security-audit-2024"
                  className="input-field"
                />
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isLoading || targets.every(t => !t.trim())}
          className="btn-primary w-full flex items-center justify-center gap-3 text-lg py-4"
        >
          {isLoading ? (
            <>
              <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Initializing Scan...
            </>
          ) : (
            <>
              <Play className="w-5 h-5" />
              Launch Penetration Test
            </>
          )}
        </button>
      </form>
    </motion.div>
  );
}
