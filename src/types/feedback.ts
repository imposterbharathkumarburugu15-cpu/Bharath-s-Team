export type FeedbackLabel = 'CORRECT' | 'MARK_SAFE' | 'MARK_PHISHING' | 'NOT_SURE';

export type FeedbackType = 'CONFIRMATION' | 'FALSE_POSITIVE' | 'FALSE_NEGATIVE' | 'UNRESOLVED';

export type ReviewStatus = 'PENDING' | 'VERIFIED' | 'REJECTED';

export interface FeedbackFeatures {
  signals?: string[];
  keywords?: string[];
  detectedLinks?: string[];
  sender?: string;
  subject?: string;
  snippet?: string;
  source?: string;
  target?: string;
  language?: string;
  domainAge?: string;
  sslCertificate?: string;
}

export interface FeedbackRecord {
  id: string;
  timestamp: string;
  targetId: string;
  modelPrediction: string;
  riskScore: number;
  predictedAttackType: string;
  userFeedbackLabel: FeedbackLabel;
  feedbackType: FeedbackType;
  extractedFeatures: FeedbackFeatures;
  isVerified: boolean;
  reviewStatus: ReviewStatus;
  reviewerNotes?: string;
  reviewedAt?: string;
  reviewedBy?: string;
  calibrationEligible: boolean;
  userNotes?: string;
}

export interface FeedbackMetrics {
  totalFeedback: number;
  correctPredictions: number;
  falsePositives: number;
  falseNegatives: number;
  safeCorrections: number;
  phishingCorrections: number;
  unresolvedFeedback: number;
  verifiedCount: number;
  pendingCount: number;
  rejectedCount: number;
  modelAccuracy: number; // percentage based on verified feedback
  rawAccuracy: number; // percentage based on all user clicks
  verifiedDatasetSize: number;
  lastCalibrationTimestamp?: string;
  calibrationRuns: number;
  pipelineStages: {
    predictionCount: number;
    userFeedbackCount: number;
    databaseCount: number;
    validationPendingCount: number;
    verifiedDatasetCount: number;
    retrainedEpochs: number;
  };
}

export interface CalibrationResult {
  runId: string;
  timestamp: string;
  verifiedSamplesUsed: number;
  previousAccuracy: number;
  newAccuracy: number;
  accuracyDelta: number;
  weightsAdjusted: string[];
  status: 'SUCCESS' | 'NO_NEW_DATA' | 'ERROR';
  message: string;
}
