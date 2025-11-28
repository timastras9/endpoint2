import React from 'react';
import { EndpointLogo } from './EndpointLogo';
import { Shield, Activity, Github } from 'lucide-react';

interface HeaderProps {
  isConnected?: boolean;
}

export function Header({ isConnected = false }: HeaderProps) {
  return (
    <header className="glass border-b border-dark-800/50 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Logo & Title */}
          <div className="flex items-center gap-4">
            <EndpointLogo size="md" />
            <div>
              <h1 className="text-2xl font-bold text-gradient flex items-center gap-2">
                ENDPOINT
                <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-endpoint-500/20 text-endpoint-300 border border-endpoint-500/30">
                  v0.1.0
                </span>
              </h1>
              <p className="text-sm text-dark-400">AI-Powered Penetration Testing</p>
            </div>
          </div>

          {/* Status & Actions */}
          <div className="flex items-center gap-6">
            {/* Connection Status */}
            <div className="flex items-center gap-2 px-4 py-2 rounded-xl bg-dark-800/50 border border-dark-700/50">
              <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-endpoint-400 animate-pulse' : 'bg-dark-500'}`} />
              <span className="text-sm text-dark-300">
                {isConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>

            {/* Nav Links */}
            <nav className="flex items-center gap-2">
              <a
                href="#"
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-dark-300 hover:text-endpoint-300 hover:bg-dark-800/50 transition-all duration-300"
              >
                <Shield className="w-4 h-4" />
                <span className="text-sm font-medium">Scans</span>
              </a>
              <a
                href="#"
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-dark-300 hover:text-endpoint-300 hover:bg-dark-800/50 transition-all duration-300"
              >
                <Activity className="w-4 h-4" />
                <span className="text-sm font-medium">Activity</span>
              </a>
              <a
                href="https://github.com/timastras9/endpoint2"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-dark-300 hover:text-endpoint-300 hover:bg-dark-800/50 transition-all duration-300"
              >
                <Github className="w-4 h-4" />
              </a>
            </nav>
          </div>
        </div>
      </div>
    </header>
  );
}
