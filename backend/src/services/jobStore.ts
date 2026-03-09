import { BuildJob, BuildStatus } from '../types';
import logger from '../utils/logger';
import fs from 'fs';
import path from 'path';

// File-based persistence for jobs
const JOBS_FILE = path.join(__dirname, '../../data/jobs.json');

// Ensure data directory exists
const dataDir = path.dirname(JOBS_FILE);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// In-memory job store backed by file persistence
const jobs: Map<string, BuildJob> = new Map();

// Load jobs from file on startup
function loadJobs(): void {
  try {
    if (fs.existsSync(JOBS_FILE)) {
      const data = fs.readFileSync(JOBS_FILE, 'utf-8');
      const jobsArray: BuildJob[] = JSON.parse(data);
      jobsArray.forEach((job) => jobs.set(job.id, job));
      logger.info(`Loaded ${jobsArray.length} jobs from file`);
    }
  } catch (error) {
    logger.error('Failed to load jobs from file:', error);
  }
}

// Save jobs to file
function saveJobs(): void {
  try {
    const jobsArray = Array.from(jobs.values());
    fs.writeFileSync(JOBS_FILE, JSON.stringify(jobsArray, null, 2));
  } catch (error) {
    logger.error('Failed to save jobs to file:', error);
  }
}

// Load jobs on module initialization
loadJobs();

export function createJob(job: BuildJob): BuildJob {
  jobs.set(job.id, job);
  logger.info(`Created job ${job.id}`);
  saveJobs();
  return job;
}

export function getJob(id: string): BuildJob | undefined {
  return jobs.get(id);
}

export function getJobByUuid(uuid: string): BuildJob | undefined {
  for (const job of jobs.values()) {
    if (job.uuid === uuid) {
      return job;
    }
  }
  return undefined;
}

export function updateJob(id: string, updates: Partial<BuildJob>): BuildJob | undefined {
  const job = jobs.get(id);
  if (!job) {
    logger.warn(`Job ${id} not found for update`);
    return undefined;
  }

  const updatedJob: BuildJob = {
    ...job,
    ...updates,
    updatedAt: new Date().toISOString(),
  };

  jobs.set(id, updatedJob);
  logger.info(`Updated job ${id}: ${updates.status || 'no status change'}`);
  saveJobs();
  return updatedJob;
}

export function updateJobStatus(
  id: string,
  status: BuildStatus,
  statusMessage: string,
  progress?: number
): BuildJob | undefined {
  const updates: Partial<BuildJob> = {
    status,
    statusMessage,
  };

  if (progress !== undefined) {
    updates.progress = progress;
  }

  if (status === 'completed' || status === 'failed' || status === 'cancelled') {
    updates.completedAt = new Date().toISOString();
  }

  return updateJob(id, updates);
}

export function addJobLog(id: string, log: string): BuildJob | undefined {
  const job = jobs.get(id);
  if (!job) {
    return undefined;
  }

  const logs = [...job.logs, `[${new Date().toISOString()}] ${log}`];
  return updateJob(id, { logs });
}

export function getAllJobs(): BuildJob[] {
  return Array.from(jobs.values()).sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
}

export function deleteJob(id: string): boolean {
  const deleted = jobs.delete(id);
  if (deleted) {
    logger.info(`Deleted job ${id}`);
    saveJobs();
  }
  return deleted;
}

// Cleanup old jobs (older than 24 hours)
export function cleanupOldJobs(): number {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  let deleted = 0;

  for (const [id, job] of jobs.entries()) {
    const jobDate = new Date(job.createdAt).getTime();
    if (jobDate < cutoff) {
      jobs.delete(id);
      deleted++;
    }
  }

  if (deleted > 0) {
    logger.info(`Cleaned up ${deleted} old jobs`);
    saveJobs();
  }

  return deleted;
}

// Run cleanup every hour
setInterval(cleanupOldJobs, 60 * 60 * 1000);
