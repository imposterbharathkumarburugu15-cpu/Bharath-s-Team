/**
 * NeuroShield Request Schema Validation & Sanitization Middleware
 * Enforces payload size, valid channels, schema types, and prevents malformed inputs.
 */

import { Request, Response, NextFunction } from 'express';
import { config } from '../config';

const VALID_SOURCES = ['email', 'sms', 'web', 'qr', 'chat'];

export function validateScanRequest(req: Request, res: Response, next: NextFunction) {
  const body = req.body;

  if (!body || typeof body !== 'object') {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Request body must be a valid JSON object.',
      code: 'INVALID_JSON_BODY',
    });
  }

  // Validate payload size
  const rawLength = JSON.stringify(body).length;
  if (rawLength > config.maxPayloadBytes) {
    return res.status(413).json({
      error: 'Payload Too Large',
      message: `Payload size (${Math.round(rawLength / 1024)}KB) exceeds maximum limit of ${Math.round(config.maxPayloadBytes / 1024)}KB.`,
      code: 'PAYLOAD_TOO_LARGE',
    });
  }

  // If source is provided, check against valid channels
  if (body.source && !VALID_SOURCES.includes(body.source)) {
    return res.status(400).json({
      error: 'Bad Request',
      message: `Unsupported threat source '${body.source}'. Allowed sources: ${VALID_SOURCES.join(', ')}.`,
      code: 'UNSUPPORTED_SOURCE',
    });
  }

  // Validate content or text field
  const content = body.content || body.text || body.rawPayload || body.url;
  if (!content && !body.base64Image && !body.base64Audio) {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Scan request must contain at least one of: "content", "text", "rawPayload", "url", or "base64Image".',
      code: 'MISSING_PAYLOAD_CONTENT',
    });
  }

  // Ensure URLs array contains strings if provided
  if (body.urls && !Array.isArray(body.urls)) {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'The "urls" field must be an array of string URLs.',
      code: 'INVALID_URLS_FORMAT',
    });
  }

  next();
}

export function validateFeedbackRequest(req: Request, res: Response, next: NextFunction) {
  const body = req.body;

  if (!body || typeof body !== 'object') {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'Request body must be a valid JSON object.',
      code: 'INVALID_JSON_BODY',
    });
  }

  const VALID_LABELS = ['CORRECT', 'MARK_SAFE', 'MARK_PHISHING', 'NOT_SURE'];
  const FEEDBACK_MAPPING: Record<string, string> = {
    'TRUE_POSITIVE': 'CORRECT',
    'FALSE_POSITIVE': 'MARK_SAFE',
    'MISSED_THREAT': 'MARK_PHISHING'
  };

  if (body.feedback && FEEDBACK_MAPPING[body.feedback]) {
    body.userFeedbackLabel = FEEDBACK_MAPPING[body.feedback];
    if (body.incident_id && !body.targetId) {
      body.targetId = body.incident_id;
    }
  }

  if (!body.userFeedbackLabel || !VALID_LABELS.includes(body.userFeedbackLabel)) {
    return res.status(400).json({
      error: 'Bad Request',
      message: `Feedback must include either userFeedbackLabel (${VALID_LABELS.join(', ')}) or feedback (TRUE_POSITIVE, FALSE_POSITIVE, MISSED_THREAT).`,
      code: 'INVALID_FEEDBACK_LABEL',
    });
  }

  next();
}
