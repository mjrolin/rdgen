import { exec } from 'child_process';
import { promisify } from 'util';
import logger from '../utils/logger';

const execAsync = promisify(exec);

const JSIGN_PATH = '/usr/local/bin/jsign.jar';
const GCLOUD_PATH = '/opt/google-cloud-sdk/bin/gcloud';
const CERT_PATH = '/root/user.pem';
const KMS_KEYSTORE = 'projects/certera-sign/locations/global/keyRings/certera-code-signing';
const KMS_ALIAS = 'certera-code-signing';
const TSA_URL = 'http://timestamp.sectigo.com';

// Set environment variable for Google Cloud authentication
process.env.GOOGLE_APPLICATION_CREDENTIALS = '/opt/rdgen/gcp-sa-key.json';

async function getAccessToken(): Promise<string> {
  try {
    const { stdout } = await execAsync(`${GCLOUD_PATH} auth print-access-token`);
    return stdout.trim();
  } catch (error: any) {
    logger.error('Failed to get GCloud access token:', error.message);
    throw new Error('Failed to authenticate with Google Cloud');
  }
}

export async function signFile(filePath: string): Promise<{ success: boolean; error?: string }> {
  // Only sign .exe and .msi files
  if (!filePath.endsWith('.exe') && !filePath.endsWith('.msi')) {
    logger.info(`Skipping signing for non-Windows file: ${filePath}`);
    return { success: true };
  }

  logger.info(`Starting code signing for: ${filePath}`);

  try {
    const accessToken = await getAccessToken();

    const command = [
      'java',
      '-jar',
      JSIGN_PATH,
      '--storetype', 'GOOGLECLOUD',
      '--storepass', `"${accessToken}"`,
      '--keystore', `"${KMS_KEYSTORE}"`,
      '--alias', `"${KMS_ALIAS}"`,
      '--certfile', CERT_PATH,
      '--tsaurl', TSA_URL,
      `"${filePath}"`,
    ].join(' ');

    const { stdout, stderr } = await execAsync(command, { timeout: 120000 });

    if (stderr && !stderr.includes('Adding Authenticode signature')) {
      logger.warn(`Signing stderr: ${stderr}`);
    }

    logger.info(`Successfully signed: ${filePath}`);
    return { success: true };
  } catch (error: any) {
    logger.error(`Failed to sign ${filePath}:`, error.message);
    return { success: false, error: error.message };
  }
}

export async function signBuildArtifacts(uuid: string, files: string[]): Promise<void> {
  for (const file of files) {
    const result = await signFile(file);
    if (!result.success) {
      logger.error(`Signing failed for ${file}: ${result.error}`);
      // Continue signing other files even if one fails
    }
  }
}
