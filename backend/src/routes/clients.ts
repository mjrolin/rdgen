import { Router, Request, Response } from 'express';
import {
  listClients,
  getClient,
  createClient,
  renameClient,
  deleteClient,
  createProfile,
  addProfileVersion,
  getProfileVersion,
  renameProfile,
  deleteProfile,
  updateProfileHost,
} from '../services/clientStore';
import logger from '../utils/logger';

const router = Router();

// ── Client routes ──────────────────────────────────────────────────────────────

router.get('/', (req: Request, res: Response) => {
  try {
    const clients = listClients();
    res.json({ success: true, data: clients });
  } catch (error: any) {
    logger.error('Error listing clients:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/', (req: Request, res: Response) => {
  try {
    const { name } = req.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ success: false, error: 'name is required' });
    }
    const client = createClient(name.trim());
    res.status(201).json({ success: true, data: client });
  } catch (error: any) {
    logger.error('Error creating client:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/:id', (req: Request, res: Response) => {
  try {
    const client = getClient(req.params.id);
    if (!client) {
      return res.status(404).json({ success: false, error: 'Client not found' });
    }
    res.json({ success: true, data: client });
  } catch (error: any) {
    logger.error('Error getting client:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.patch('/:id', (req: Request, res: Response) => {
  try {
    const { name } = req.body;
    if (!name || typeof name !== 'string' || !name.trim()) {
      return res.status(400).json({ success: false, error: 'name is required' });
    }
    const client = renameClient(req.params.id, name.trim());
    if (!client) {
      return res.status(404).json({ success: false, error: 'Client not found' });
    }
    res.json({ success: true, data: client });
  } catch (error: any) {
    logger.error('Error renaming client:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.delete('/:id', (req: Request, res: Response) => {
  try {
    const deleted = deleteClient(req.params.id);
    if (!deleted) {
      return res.status(404).json({ success: false, error: 'Client not found' });
    }
    res.json({ success: true, message: 'Client deleted' });
  } catch (error: any) {
    logger.error('Error deleting client:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ── Profile routes ─────────────────────────────────────────────────────────────

router.post('/:id/profiles', (req: Request, res: Response) => {
  try {
    const { profileName, host, platform, config } = req.body;
    if (!profileName || !host || !platform || !config) {
      return res.status(400).json({
        success: false,
        error: 'profileName, host, platform, and config are required',
      });
    }
    const profile = createProfile(req.params.id, profileName, host, platform, config);
    if (!profile) {
      return res.status(404).json({ success: false, error: 'Client not found' });
    }
    res.status(201).json({ success: true, data: profile });
  } catch (error: any) {
    logger.error('Error creating profile:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.patch('/:id/profiles/:pid', (req: Request, res: Response) => {
  try {
    const { name, host } = req.body;

    if (name !== undefined) {
      if (typeof name !== 'string' || !name.trim()) {
        return res.status(400).json({ success: false, error: 'name must be a non-empty string' });
      }
      const profile = renameProfile(req.params.id, req.params.pid, name.trim());
      if (!profile) {
        return res.status(404).json({ success: false, error: 'Client or profile not found' });
      }
      return res.json({ success: true, data: profile });
    }

    if (host !== undefined) {
      if (typeof host !== 'string' || !host.trim()) {
        return res.status(400).json({ success: false, error: 'host must be a non-empty string' });
      }
      const profile = updateProfileHost(req.params.id, req.params.pid, host.trim());
      if (!profile) {
        return res.status(404).json({ success: false, error: 'Client or profile not found' });
      }
      return res.json({ success: true, data: profile });
    }

    return res.status(400).json({ success: false, error: 'name or host is required' });
  } catch (error: any) {
    logger.error('Error patching profile:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.delete('/:id/profiles/:pid', (req: Request, res: Response) => {
  try {
    const deleted = deleteProfile(req.params.id, req.params.pid);
    if (!deleted) {
      return res.status(404).json({ success: false, error: 'Client or profile not found' });
    }
    res.json({ success: true, message: 'Profile deleted' });
  } catch (error: any) {
    logger.error('Error deleting profile:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/:id/profiles/:pid/versions/:vid', (req: Request, res: Response) => {
  try {
    const config = getProfileVersion(req.params.id, req.params.pid, req.params.vid);
    if (!config) {
      return res.status(404).json({ success: false, error: 'Client, profile, or version not found' });
    }
    res.json({ success: true, data: config });
  } catch (error: any) {
    logger.error('Error getting profile version:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.put('/:id/profiles/:pid', (req: Request, res: Response) => {
  try {
    const { config } = req.body;
    if (!config) {
      return res.status(400).json({ success: false, error: 'config is required' });
    }
    const profile = addProfileVersion(req.params.id, req.params.pid, config);
    if (!profile) {
      return res.status(404).json({ success: false, error: 'Client or profile not found' });
    }
    res.json({ success: true, data: profile });
  } catch (error: any) {
    logger.error('Error adding profile version:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
