import { Router } from 'express';
import { labFixtures } from '../services/lab/fixtures';
import { runEvidenceLab, runLabEvaluation, validateLabInput, verifyReceipt } from '../services/lab/service';

export const labRoutes = Router();
labRoutes.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
labRoutes.get('/cases', (_req, res) => res.json(labFixtures));
labRoutes.post('/analyze', async (req, res) => {
  try { res.json(await runEvidenceLab(validateLabInput(req.body))); }
  catch (error) { res.status(400).json({ error: error instanceof Error ? error.message : 'Unable to analyze input.' }); }
});
labRoutes.post('/evaluate', async (_req, res) => {
  try { res.json(await runLabEvaluation()); }
  catch { res.status(500).json({ error: 'Evaluation could not complete.' }); }
});
labRoutes.post('/verify', (req, res) => {
  try { res.json({ valid: verifyReceipt(req.body), meaning: 'Checksum consistency only; not authenticity or accuracy.' }); }
  catch { res.status(400).json({ error: 'Invalid receipt.' }); }
});
