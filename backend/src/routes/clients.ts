import { Router, Request, Response } from 'express';
import {
  listClients,
  getClient,
  getClientVersion,
  createClient,
  addClientVersion,
  deleteClient,
  renameClient,
} from '../services/clientStore';
import { requireAdmin } from '../middleware/apiKeyAuth';
import logger from '../utils/logger';

const router = Router();


router.get('/', (req: Request, res: Response) => {
  try {
    const clients = listClients();
    res.json({ success: true, data: clients });
  } catch (error: any) {
    logger.error('Error listing clients:', error);
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

router.get('/:id/versions/:versionId', (req: Request, res: Response) => {
  try {
    const config = getClientVersion(req.params.id, req.params.versionId);
    if (!config) {
      return res.status(404).json({ success: false, error: 'Client or version not found' });
    }
    res.json({ success: true, data: config });
  } catch (error: any) {
    logger.error('Error getting client version:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.post('/', (req: Request, res: Response) => {
  try {
    const { name, host, config } = req.body;
    if (!name || !config) {
      return res.status(400).json({
        success: false,
        error: "name and config are required",
      });
    }
    const client = createClient(name, host, config);
    res.status(201).json({ success: true, data: client });
  } catch (error: any) {
    logger.error('Error creating client:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.put('/:id', (req: Request, res: Response) => {
  try {
    const { config } = req.body;
    if (!config) {
      return res.status(400).json({ success: false, error: 'config is required' });
    }
    const client = addClientVersion(req.params.id, config);
    if (!client) {
      return res.status(404).json({ success: false, error: 'Client not found' });
    }
    res.json({ success: true, data: client });
  } catch (error: any) {
    logger.error('Error updating client:', error);
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

export default router;
