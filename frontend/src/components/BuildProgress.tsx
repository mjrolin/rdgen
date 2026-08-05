'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { BuildJob } from '@/types';
import { getBuildStatus } from '@/lib/api';

interface BuildProgressProps {
  jobId: string;
  onComplete?: (job: BuildJob) => void;
  onError?: (error: string) => void;
  showDetails?: boolean; // Se false, mostra apenas loading simples
}

function formatElapsedTime(seconds: number): string {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;

  if (hours > 0) {
    return `${hours}h ${minutes}m ${secs}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${secs}s`;
  }
  return `${secs}s`;
}

export default function BuildProgress({ jobId, onComplete, onError, showDetails = false }: BuildProgressProps) {
  const [job, setJob] = useState<BuildJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [elapsedTime, setElapsedTime] = useState(0);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const retryCountRef = useRef(0); // Usar ref para evitar problemas de closure
  const intervalRef = useRef<NodeJS.Timeout | null>(null);
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const startTimeRef = useRef<Date>(new Date());

  const isTerminalStatus = useCallback((status: string) => {
    return ['completed', 'failed', 'cancelled'].includes(status);
  }, []);

  const pollStatus = useCallback(async () => {
    try {
      const result = await getBuildStatus(jobId);

      if (result.success && result.data) {
        setJob(result.data);
        setLastUpdate(new Date());
        retryCountRef.current = 0; // Reset retry count on success
        setError(null); // Limpar erro quando conexão voltar

        if (isTerminalStatus(result.data.status)) {
          // Stop polling when build is complete
          if (intervalRef.current) {
            clearInterval(intervalRef.current);
            intervalRef.current = null;
          }

          if (result.data.status === 'completed') {
            onComplete?.(result.data);
          } else {
            onError?.(result.data.statusMessage || 'Build failed');
          }
        }
      } else {
        // Handle error but don't stop polling immediately
        retryCountRef.current += 1;

        if (retryCountRef.current >= 5 && retryCountRef.current < 10) {
          setError('Connection lost. Retrying...');
        } else if (retryCountRef.current >= 10) {
          setError(`Failed to get build status. Retrying... (${retryCountRef.current} attempts)`);
        }
      }
    } catch (err) {
      retryCountRef.current += 1;
      if (retryCountRef.current >= 5) {
        setError(`Connection error. Retrying... (${retryCountRef.current} attempts)`);
      }
    }
  }, [jobId, onComplete, onError, isTerminalStatus]);

  // Start polling on mount
  useEffect(() => {
    startTimeRef.current = new Date();

    // Initial poll
    pollStatus();

    // Set up polling interval (every 5 seconds)
    intervalRef.current = setInterval(pollStatus, 5000);

    // Set up elapsed time counter (every second)
    timerRef.current = setInterval(() => {
      setElapsedTime(Math.floor((Date.now() - startTimeRef.current.getTime()) / 1000));
    }, 1000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [jobId]); // Only re-run if jobId changes

  // Update polling when pollStatus changes
  useEffect(() => {
    if (job && !isTerminalStatus(job.status)) {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
      intervalRef.current = setInterval(pollStatus, 5000);
    }

    return () => {
      if (intervalRef.current && job && isTerminalStatus(job.status)) {
        clearInterval(intervalRef.current);
      }
    };
  }, [pollStatus, job, isTerminalStatus]);

  const getStatusColor = () => {
    if (!job) return 'status-pending';
    switch (job.status) {
      case 'pending':
      case 'queued':
        return 'status-pending';
      case 'in_progress':
        return 'status-building';
      case 'completed':
        return 'status-success';
      case 'failed':
      case 'cancelled':
        return 'status-error';
      default:
        return 'status-pending';
    }
  };

  const getStatusText = () => {
    if (!job) return 'Loading...';
    switch (job.status) {
      case 'pending':
        return 'Pending';
      case 'queued':
        return 'Queued';
      case 'in_progress':
        return 'Building';
      case 'completed':
        return 'Completed';
      case 'failed':
        return 'Failed';
      case 'cancelled':
        return 'Cancelled';
      default:
        return job.status;
    }
  };

  if (!job && !error) {
    return (
      <div className="section">
        <div className="flex items-center gap-3">
          <div className="animate-spin w-5 h-5 border-2 border-primary border-t-transparent rounded-full"></div>
          <span className="text-sm">Loading build status...</span>
        </div>
      </div>
    );
  }

  // Renderização simplificada durante o build (sem detalhes do GitHub)
  const isBuilding = job && ['pending', 'queued', 'in_progress'].includes(job.status);

  if (isBuilding && !showDetails) {
    return (
      <div className="section">
        <div className="flex flex-col items-center justify-center py-8">
          {/* Spinner animado grande */}
          <div className="relative mb-6">
            <div className="w-16 h-16 border-4 border-primary/20 rounded-full"></div>
            <div className="absolute top-0 left-0 w-16 h-16 border-4 border-primary border-t-transparent rounded-full animate-spin"></div>
          </div>

          {/* Texto de status */}
          <h2 className="text-white text-lg font-semibold mb-2">
            Building your application...
          </h2>
          <p className="text-gray-400 text-sm mb-4">
            This may take 40-70 minutes
          </p>

          {/* Barra de progresso simples */}
          <div className="w-full max-w-xs mb-2">
            <div className="progress-bar">
              <div
                className="progress-bar-fill"
                style={{ width: `${job?.progress || 0}%` }}
              ></div>
            </div>
          </div>
          <span className="text-gray-500 text-xs">{job?.progress || 0}%</span>

          {/* Tempo decorrido */}
          <div className="text-gray-500 text-xs mt-4">
            <i className="far fa-clock mr-1"></i>
            Elapsed: {formatElapsedTime(elapsedTime)}
          </div>

          {/* Erro de conexão (se houver) */}
          {error && (
            <div className="bg-yellow-900/30 border border-yellow-600/50 rounded p-2 mt-4 text-xs text-yellow-400">
              <i className="fas fa-exclamation-triangle mr-1"></i>
              {error}
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="section">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className={`status-dot ${getStatusColor()}`}></div>
          <h2 className="text-white text-base font-semibold">
            {job?.status === 'completed' ? 'Build Complete!' : `Build ${getStatusText()}`}
          </h2>
        </div>
        {showDetails && (
          <div className="flex items-center gap-3 text-xs">
            {job?.workflowRunUrl && (
              <a
                href={job.workflowRunUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline"
              >
                <i className="fab fa-github mr-1"></i>
                GitHub
              </a>
            )}
          </div>
        )}
      </div>

      {showDetails && (
        <>
          {/* Time info */}
          <div className="flex justify-between text-xs text-gray-500 mb-2">
            <span>Elapsed: {formatElapsedTime(elapsedTime)}</span>
            <span>Updated: {lastUpdate.toLocaleTimeString()}</span>
          </div>

          {/* Connection status warning */}
          {error && (
            <div className="bg-yellow-900/30 border border-yellow-600/50 rounded p-2 mb-2 text-xs text-yellow-400">
              <i className="fas fa-exclamation-triangle mr-1"></i>
              {error}
            </div>
          )}

          {/* Progress */}
          <div className="mb-3">
            <div className="flex justify-between text-xs mb-1">
              <span className="text-gray-400 truncate max-w-[70%]">
                {job?.statusMessage || 'Initializing...'}
              </span>
              <span className="text-gray-400">{job?.progress || 0}%</span>
            </div>
            <div className="progress-bar">
              <div
                className="progress-bar-fill"
                style={{ width: `${job?.progress || 0}%` }}
              ></div>
            </div>
          </div>

          {/* Estimated time remaining */}
          {job && job.status === 'in_progress' && job.progress > 0 && job.progress < 100 && (
            <div className="text-xs text-gray-500 mb-3">
              <i className="far fa-clock mr-1"></i>
              Estimated time remaining: ~{Math.max(1, Math.round((100 - job.progress) * 0.5))} min
              <span className="text-gray-600 ml-2">(builds typically take 40-70 min)</span>
            </div>
          )}
        </>
      )}

      {/* Download buttons - sempre mostra quando completado */}
      {job?.status === 'completed' && (
        <div className="flex flex-col items-center py-4">
          <div className="text-green-400 mb-4">
            <i className="fas fa-check-circle text-4xl"></i>
          </div>
          <h3 className="text-white text-lg font-semibold mb-4">Build Complete!</h3>
          <div className="flex flex-wrap justify-center gap-3">
            {/* Windows */}
            {job.artifactUrl && (
              <a
                href={job.artifactUrl}
                className="btn-primary inline-flex items-center gap-2 text-sm px-6 py-2"
                download
              >
                <i className="fas fa-download"></i>
                Download EXE
              </a>
            )}
            {job.artifactMsiUrl && (
              <a
                href={job.artifactMsiUrl}
                className="btn-secondary inline-flex items-center gap-2 text-sm px-6 py-2"
                download
              >
                <i className="fas fa-download"></i>
                Download MSI
              </a>
            )}
            {/* Linux */}
            {job.artifactDebUrl && (
              <a
                href={job.artifactDebUrl}
                className="btn-primary inline-flex items-center gap-2 text-sm px-6 py-2"
                download
              >
                <i className="fas fa-download"></i>
                Download DEB
              </a>
            )}
            {job.artifactRpmUrl && (
              <a
                href={job.artifactRpmUrl}
                className="btn-secondary inline-flex items-center gap-2 text-sm px-6 py-2"
                download
              >
                <i className="fas fa-download"></i>
                Download RPM
              </a>
            )}
            {job.artifactRpmSuseUrl && (
              <a
                href={job.artifactRpmSuseUrl}
                className="btn-secondary inline-flex items-center gap-2 text-sm px-6 py-2"
                download
              >
                <i className="fas fa-download"></i>
                Download RPM (SUSE)
              </a>
            )}
            {job.artifactAppImageUrl && (
              <a
                href={job.artifactAppImageUrl}
                className="btn-secondary inline-flex items-center gap-2 text-sm px-6 py-2"
                download
              >
                <i className="fas fa-download"></i>
                Download AppImage
              </a>
            )}
            {job.artifactPkgUrl && (
              <a
                href={job.artifactPkgUrl}
                className="btn-secondary inline-flex items-center gap-2 text-sm px-6 py-2"
                download
              >
                <i className="fas fa-download"></i>
                Download PKG
              </a>
            )}
            {/* macOS */}
            {job.artifactDmgX64Url && (
              <a
                href={job.artifactDmgX64Url}
                className="btn-primary inline-flex items-center gap-2 text-sm px-6 py-2"
                download
              >
                <i className="fas fa-download"></i>
                Download DMG (Intel)
              </a>
            )}
            {job.artifactDmgArm64Url && (
              <a
                href={job.artifactDmgArm64Url}
                className="btn-primary inline-flex items-center gap-2 text-sm px-6 py-2"
                download
              >
                <i className="fas fa-download"></i>
                Download DMG (Apple Silicon)
              </a>
            )}
            {/* Android */}
            {job.artifactApkUrl && (
              <a
                href={job.artifactApkUrl}
                className="btn-primary inline-flex items-center gap-2 text-sm px-6 py-2"
                download
              >
                <i className="fas fa-download"></i>
                Download APK
              </a>
            )}
          </div>
          {!job.artifactUrl && !job.artifactMsiUrl && !job.artifactDebUrl && !job.artifactRpmUrl && !job.artifactAppImageUrl && !job.artifactPkgUrl && !job.artifactDmgX64Url && !job.artifactDmgArm64Url && !job.artifactApkUrl && (
            <p className="text-yellow-400 text-sm mt-2">
              <i className="fas fa-exclamation-triangle mr-1"></i>
              Download links not available yet. Please wait...
            </p>
          )}
        </div>
      )}

      {/* Failed status */}
      {job?.status === 'failed' && (
        <div className="bg-red-900/30 border border-red-600/50 rounded p-3 mt-3 text-sm text-red-400 text-center">
          <i className="fas fa-times-circle text-2xl mb-2"></i>
          <p>{job.statusMessage || 'Build failed. Please try again.'}</p>
        </div>
      )}

      {/* Logs section (collapsible) - só mostra se showDetails */}
      {showDetails && job?.logs && job.logs.length > 0 && (
        <details className="mt-3">
          <summary className="text-xs text-gray-400 cursor-pointer hover:text-gray-300">
            Build Logs ({job.logs.length} entries)
          </summary>
          <div className="bg-[#000] p-2 rounded max-h-48 overflow-y-auto font-mono text-xs text-gray-300 mt-1">
            {job.logs.map((log, index) => (
              <div key={index} className="py-0.5">{log}</div>
            ))}
          </div>
        </details>
      )}

      {/* Job ID for reference - só mostra se showDetails */}
      {showDetails && (
        <div className="text-xs text-gray-600 mt-3">
          Job ID: {jobId}
        </div>
      )}
    </div>
  );
}
