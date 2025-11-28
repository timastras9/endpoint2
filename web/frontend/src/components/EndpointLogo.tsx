import React from 'react';

interface EndpointLogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

export function EndpointLogo({ className = '', size = 'md' }: EndpointLogoProps) {
  const sizes = {
    sm: 'w-8 h-8',
    md: 'w-12 h-12',
    lg: 'w-16 h-16',
  };

  return (
    <div className={`${sizes[size]} ${className} relative`}>
      <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" className="w-full h-full">
        {/* Shield outline */}
        <path d="M50 10 L85 25 L85 55 Q85 80 50 95 Q15 80 15 55 L15 25 Z" className="fill-endpoint-500/20 stroke-endpoint-400" strokeWidth="2" />

        {/* Inner shield */}
        <path d="M50 20 L75 32 L75 52 Q75 72 50 85 Q25 72 25 52 L25 32 Z" className="fill-dark-900 stroke-endpoint-400" strokeWidth="1.5" />

        {/* Target/endpoint symbol */}
        <circle cx="50" cy="50" r="20" className="fill-none stroke-endpoint-400" strokeWidth="2" />
        <circle cx="50" cy="50" r="12" className="fill-none stroke-endpoint-400" strokeWidth="2" />
        <circle cx="50" cy="50" r="4" className="fill-endpoint-400" />

        {/* Cross hairs */}
        <line x1="50" y1="25" x2="50" y2="35" className="stroke-endpoint-400" strokeWidth="2" />
        <line x1="50" y1="65" x2="50" y2="75" className="stroke-endpoint-400" strokeWidth="2" />
        <line x1="25" y1="50" x2="35" y2="50" className="stroke-endpoint-400" strokeWidth="2" />
        <line x1="65" y1="50" x2="75" y2="50" className="stroke-endpoint-400" strokeWidth="2" />
      </svg>

      {/* Glow effect */}
      <div className="absolute inset-0 blur-xl bg-endpoint-500/20 -z-10" />
    </div>
  );
}
