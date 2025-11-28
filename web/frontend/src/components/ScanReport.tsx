import React, { useRef } from 'react';
import { motion } from 'framer-motion';
import {
  FileDown,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Lock,
  Globe,
  Cookie,
  Server,
  Database,
  Code,
  ArrowLeft,
  Calendar,
  Clock,
  Target,
} from 'lucide-react';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { cn } from '../lib/utils';

interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  found_at: string;
  url?: string;
  timestamp?: string;
}

interface ScanReportProps {
  scan: {
    id: string;
    status: string;
    targets: string[];
    start_time: string;
  };
  vulnerabilities: Vulnerability[];
  onBack: () => void;
}

const severityConfig = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', icon: XCircle },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', icon: AlertTriangle },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', icon: AlertTriangle },
  low: { color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/30', icon: Info },
  info: { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30', icon: Info },
};

// Categorize vulnerabilities by type
const categorizeVulnerabilities = (vulnerabilities: Vulnerability[]) => {
  const categories = {
    ssl: { title: 'SSL/TLS Issues', icon: Lock, items: [] as Vulnerability[] },
    headers: { title: 'Security Headers', icon: Shield, items: [] as Vulnerability[] },
    cors: { title: 'CORS Misconfigurations', icon: Globe, items: [] as Vulnerability[] },
    cookies: { title: 'Cookie Security', icon: Cookie, items: [] as Vulnerability[] },
    methods: { title: 'HTTP Methods', icon: Server, items: [] as Vulnerability[] },
    exposure: { title: 'Sensitive Data Exposure', icon: Database, items: [] as Vulnerability[] },
    injection: { title: 'Injection Vulnerabilities', icon: Code, items: [] as Vulnerability[] },
    other: { title: 'Other Findings', icon: AlertTriangle, items: [] as Vulnerability[] },
  };

  vulnerabilities.forEach((vuln) => {
    const title = vuln.title.toLowerCase();
    if (title.includes('ssl') || title.includes('tls') || title.includes('certificate')) {
      categories.ssl.items.push(vuln);
    } else if (title.includes('header') || title.includes('hsts') || title.includes('csp') || title.includes('x-frame') || title.includes('x-content')) {
      categories.headers.items.push(vuln);
    } else if (title.includes('cors')) {
      categories.cors.items.push(vuln);
    } else if (title.includes('cookie')) {
      categories.cookies.items.push(vuln);
    } else if (title.includes('method') || title.includes('trace') || title.includes('connect') || title.includes('webdav')) {
      categories.methods.items.push(vuln);
    } else if (title.includes('.git') || title.includes('.env') || title.includes('exposed') || title.includes('backup') || title.includes('config') || title.includes('dump') || title.includes('admin') || title.includes('actuator') || title.includes('phpinfo') || title.includes('phpmyadmin')) {
      categories.exposure.items.push(vuln);
    } else if (title.includes('sql') || title.includes('xss') || title.includes('injection')) {
      categories.injection.items.push(vuln);
    } else {
      categories.other.items.push(vuln);
    }
  });

  return categories;
};

export function ScanReport({ scan, vulnerabilities, onBack }: ScanReportProps) {
  const reportRef = useRef<HTMLDivElement>(null);

  const counts = {
    critical: vulnerabilities.filter((v) => v.severity === 'critical').length,
    high: vulnerabilities.filter((v) => v.severity === 'high').length,
    medium: vulnerabilities.filter((v) => v.severity === 'medium').length,
    low: vulnerabilities.filter((v) => v.severity === 'low').length,
    info: vulnerabilities.filter((v) => v.severity === 'info').length,
    total: vulnerabilities.length,
  };

  const categories = categorizeVulnerabilities(vulnerabilities);
  const riskScore = counts.critical * 40 + counts.high * 25 + counts.medium * 10 + counts.low * 3 + counts.info;
  const riskLevel = riskScore > 100 ? 'Critical' : riskScore > 50 ? 'High' : riskScore > 20 ? 'Medium' : riskScore > 0 ? 'Low' : 'None';
  const riskColor = riskScore > 100 ? 'text-red-400' : riskScore > 50 ? 'text-orange-400' : riskScore > 20 ? 'text-yellow-400' : riskScore > 0 ? 'text-green-400' : 'text-blue-400';

  const generatePDF = () => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    let yPos = 20;

    // Header
    doc.setFillColor(17, 24, 39);
    doc.rect(0, 0, pageWidth, 45, 'F');

    doc.setTextColor(34, 197, 94);
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('ENDPOINT', 20, 25);

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'normal');
    doc.text('Security Assessment Report', 20, 35);

    yPos = 55;

    // Scan Info
    doc.setTextColor(100, 100, 100);
    doc.setFontSize(10);
    doc.text(`Scan ID: ${scan.id}`, 20, yPos);
    doc.text(`Date: ${new Date(scan.start_time).toLocaleString()}`, 20, yPos + 6);
    doc.text(`Target(s): ${scan.targets.join(', ')}`, 20, yPos + 12);

    yPos += 25;

    // Executive Summary
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.text('Executive Summary', 20, yPos);
    yPos += 10;

    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(60, 60, 60);
    doc.text(`This security assessment identified ${counts.total} potential vulnerabilities across the target(s).`, 20, yPos);
    yPos += 6;
    doc.text(`Risk Level: ${riskLevel} (Score: ${riskScore})`, 20, yPos);
    yPos += 15;

    // Severity Summary Table
    autoTable(doc, {
      startY: yPos,
      head: [['Severity', 'Count', 'Description']],
      body: [
        ['Critical', String(counts.critical), 'Immediate action required - exploitable vulnerabilities'],
        ['High', String(counts.high), 'Should be addressed urgently - significant security risk'],
        ['Medium', String(counts.medium), 'Should be planned for remediation'],
        ['Low', String(counts.low), 'Minor issues - address when convenient'],
        ['Info', String(counts.info), 'Informational findings'],
      ],
      theme: 'grid',
      headStyles: { fillColor: [34, 197, 94], textColor: [255, 255, 255] },
      styles: { fontSize: 9 },
      columnStyles: {
        0: { cellWidth: 30 },
        1: { cellWidth: 20, halign: 'center' },
        2: { cellWidth: 'auto' },
      },
    });

    yPos = (doc as any).lastAutoTable.finalY + 15;

    // Vulnerability Details
    doc.setFontSize(16);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(0, 0, 0);
    doc.text('Vulnerability Details', 20, yPos);
    yPos += 10;

    // Group by category
    Object.entries(categories).forEach(([key, category]) => {
      if (category.items.length === 0) return;

      if (yPos > 250) {
        doc.addPage();
        yPos = 20;
      }

      doc.setFontSize(12);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(34, 197, 94);
      doc.text(category.title, 20, yPos);
      yPos += 8;

      const tableData = category.items.map((vuln) => [
        vuln.severity.toUpperCase(),
        vuln.title,
        vuln.description.substring(0, 100) + (vuln.description.length > 100 ? '...' : ''),
        vuln.url || 'N/A',
      ]);

      autoTable(doc, {
        startY: yPos,
        head: [['Severity', 'Title', 'Description', 'URL']],
        body: tableData,
        theme: 'striped',
        headStyles: { fillColor: [55, 65, 81], textColor: [255, 255, 255] },
        styles: { fontSize: 8, cellPadding: 2 },
        columnStyles: {
          0: { cellWidth: 20 },
          1: { cellWidth: 40 },
          2: { cellWidth: 70 },
          3: { cellWidth: 40 },
        },
        didParseCell: (data) => {
          if (data.column.index === 0 && data.section === 'body') {
            const severity = data.cell.raw?.toString().toLowerCase();
            if (severity === 'critical') data.cell.styles.textColor = [239, 68, 68];
            else if (severity === 'high') data.cell.styles.textColor = [249, 115, 22];
            else if (severity === 'medium') data.cell.styles.textColor = [234, 179, 8];
            else if (severity === 'low') data.cell.styles.textColor = [34, 197, 94];
            else if (severity === 'info') data.cell.styles.textColor = [59, 130, 246];
          }
        },
      });

      yPos = (doc as any).lastAutoTable.finalY + 10;
    });

    // Footer on last page
    const pageCount = doc.internal.pages.length - 1;
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.setTextColor(150, 150, 150);
      doc.text(
        `Generated by Endpoint Security Scanner - Page ${i} of ${pageCount}`,
        pageWidth / 2,
        doc.internal.pageSize.getHeight() - 10,
        { align: 'center' }
      );
    }

    // Save
    const filename = `endpoint-report-${scan.targets[0]?.replace(/[^a-z0-9]/gi, '-') || scan.id}-${new Date().toISOString().split('T')[0]}.pdf`;
    doc.save(filename);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="space-y-6"
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <button
          onClick={onBack}
          className="flex items-center gap-2 text-dark-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
          Back to Scan
        </button>
        <button
          onClick={generatePDF}
          className="btn-primary flex items-center gap-2"
        >
          <FileDown className="w-5 h-5" />
          Download PDF Report
        </button>
      </div>

      {/* Report Content */}
      <div ref={reportRef} className="space-y-6">
        {/* Executive Summary */}
        <div className="glass-card p-6">
          <h2 className="text-2xl font-bold text-white mb-6 flex items-center gap-3">
            <Shield className="w-7 h-7 text-endpoint-400" />
            Security Assessment Report
          </h2>

          {/* Scan Info */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div className="p-4 rounded-xl bg-dark-800/50 border border-dark-700/50">
              <div className="flex items-center gap-2 text-dark-400 mb-1">
                <Target className="w-4 h-4" />
                <span className="text-sm">Target(s)</span>
              </div>
              <p className="text-white font-medium truncate">{scan.targets.join(', ')}</p>
            </div>
            <div className="p-4 rounded-xl bg-dark-800/50 border border-dark-700/50">
              <div className="flex items-center gap-2 text-dark-400 mb-1">
                <Calendar className="w-4 h-4" />
                <span className="text-sm">Scan Date</span>
              </div>
              <p className="text-white font-medium">{new Date(scan.start_time).toLocaleDateString()}</p>
            </div>
            <div className="p-4 rounded-xl bg-dark-800/50 border border-dark-700/50">
              <div className="flex items-center gap-2 text-dark-400 mb-1">
                <Clock className="w-4 h-4" />
                <span className="text-sm">Status</span>
              </div>
              <p className="text-white font-medium capitalize">{scan.status}</p>
            </div>
          </div>

          {/* Risk Score */}
          <div className="p-6 rounded-xl bg-dark-800/50 border border-dark-700/50 mb-6">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-white mb-1">Overall Risk Level</h3>
                <p className="text-dark-400 text-sm">Based on vulnerability severity distribution</p>
              </div>
              <div className="text-right">
                <p className={cn('text-3xl font-bold', riskColor)}>{riskLevel}</p>
                <p className="text-dark-500 text-sm">Score: {riskScore}</p>
              </div>
            </div>
          </div>

          {/* Severity Summary */}
          <div className="grid grid-cols-5 gap-3">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => {
              const config = severityConfig[severity];
              const Icon = config.icon;
              return (
                <div
                  key={severity}
                  className={cn(
                    'p-4 rounded-xl border text-center',
                    config.bg,
                    config.border
                  )}
                >
                  <Icon className={cn('w-6 h-6 mx-auto mb-2', config.color)} />
                  <p className={cn('text-2xl font-bold', config.color)}>{counts[severity]}</p>
                  <p className="text-dark-400 text-xs uppercase tracking-wide">{severity}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Severity Distribution */}
        {counts.total > 0 && (
          <div className="glass-card p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Severity Distribution</h3>
            <div className="flex gap-1 h-4 rounded-full overflow-hidden bg-dark-800">
              {counts.critical > 0 && (
                <div
                  className="bg-red-500 transition-all"
                  style={{ width: `${(counts.critical / counts.total) * 100}%` }}
                  title={`Critical: ${counts.critical}`}
                />
              )}
              {counts.high > 0 && (
                <div
                  className="bg-orange-500 transition-all"
                  style={{ width: `${(counts.high / counts.total) * 100}%` }}
                  title={`High: ${counts.high}`}
                />
              )}
              {counts.medium > 0 && (
                <div
                  className="bg-yellow-500 transition-all"
                  style={{ width: `${(counts.medium / counts.total) * 100}%` }}
                  title={`Medium: ${counts.medium}`}
                />
              )}
              {counts.low > 0 && (
                <div
                  className="bg-green-500 transition-all"
                  style={{ width: `${(counts.low / counts.total) * 100}%` }}
                  title={`Low: ${counts.low}`}
                />
              )}
              {counts.info > 0 && (
                <div
                  className="bg-blue-500 transition-all"
                  style={{ width: `${(counts.info / counts.total) * 100}%` }}
                  title={`Info: ${counts.info}`}
                />
              )}
            </div>
            <div className="flex justify-between mt-2 text-xs text-dark-500">
              <span>Critical Risk</span>
              <span>Informational</span>
            </div>
          </div>
        )}

        {/* Categorized Vulnerabilities */}
        {Object.entries(categories).map(([key, category]) => {
          if (category.items.length === 0) return null;
          const Icon = category.icon;

          return (
            <div key={key} className="glass-card p-6">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-3">
                <div className="p-2 rounded-lg bg-endpoint-500/10">
                  <Icon className="w-5 h-5 text-endpoint-400" />
                </div>
                {category.title}
                <span className="ml-auto text-sm text-dark-400 font-normal">
                  {category.items.length} finding{category.items.length !== 1 ? 's' : ''}
                </span>
              </h3>

              <div className="space-y-3">
                {category.items.map((vuln) => {
                  const config = severityConfig[vuln.severity];
                  const SeverityIcon = config.icon;

                  return (
                    <div
                      key={vuln.id}
                      className={cn(
                        'p-4 rounded-xl border',
                        config.bg,
                        config.border
                      )}
                    >
                      <div className="flex items-start gap-3">
                        <SeverityIcon className={cn('w-5 h-5 mt-0.5 shrink-0', config.color)} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={cn('text-xs font-bold uppercase', config.color)}>
                              {vuln.severity}
                            </span>
                            <h4 className="text-white font-medium">{vuln.title}</h4>
                          </div>
                          <p className="text-dark-300 text-sm">{vuln.description}</p>
                          {vuln.url && (
                            <p className="text-dark-500 text-xs mt-2 font-mono truncate">
                              {vuln.url}
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}

        {/* No Vulnerabilities */}
        {counts.total === 0 && (
          <div className="glass-card p-12 text-center">
            <CheckCircle className="w-16 h-16 text-green-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-white mb-2">No Vulnerabilities Found</h3>
            <p className="text-dark-400">
              The security scan did not identify any vulnerabilities in the target(s).
            </p>
          </div>
        )}
      </div>
    </motion.div>
  );
}
