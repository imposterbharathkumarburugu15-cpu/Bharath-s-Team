import test from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryAndSqliteRepository } from '../src/db/repository';
import {
  extractInfrastructureObservationsFromDossier,
  buildInfrastructureCorrelation,
  generateForensicCaseReport
} from '../src/services/forensicsEngine';
import type { ForensicDossier } from '../src/services/forensicsEngine';
import type { InfrastructureObservation } from '../src/types/infrastructure';

test('Repository: Historical infrastructure observations are strictly additive and never overwritten', async () => {
  const repo = new InMemoryAndSqliteRepository();
  const incidentId = 'NS-TEST-001';

  // 1. Initial observation in Singapore
  await repo.saveInfrastructureObservation({
    id: 'obs-test-1',
    incidentId,
    ip: '185.220.101.44',
    timestamp: '2026-09-14T10:42:01.000Z',
    country: 'Singapore',
    region: 'Central',
    city: 'Singapore',
    latitude: 1.3521,
    longitude: 103.8198,
    asn: 'AS12345',
    provider: 'Pacific Datacenter Transit',
    domain: 'secure-update-portal.com',
    source: 'received-chain',
    confidence: 84,
    nodeRole: 'probable-origin',
    statusNote: 'Inbound transmission hop #1'
  });

  // Check count is 1
  let history = await repo.getInfrastructureObservations(incidentId);
  assert.equal(history.length, 1);
  assert.equal(history[0].country, 'Singapore');
  assert.equal(history[0].isCurrentActive, true);

  // 2. IP Rotation occurs: Infrastructure rotates to Netherlands
  await repo.saveInfrastructureObservation({
    id: 'obs-test-2',
    incidentId,
    ip: '103.253.42.87',
    timestamp: '2026-09-14T10:43:17.000Z',
    country: 'Netherlands',
    region: 'North Holland',
    city: 'Amsterdam',
    latitude: 52.3676,
    longitude: 4.9041,
    asn: 'AS12345', // Same ASN maintained across rotation!
    provider: 'Pacific Datacenter Transit',
    domain: 'secure-update-portal.com',
    source: 'url-resolution',
    confidence: 78,
    nodeRole: 'payload-url',
    statusNote: 'Credential harvest redirect target'
  });

  // Crucial check: History must have BOTH observations. Observation 1 was NOT overwritten or erased!
  history = await repo.getInfrastructureObservations(incidentId);
  assert.equal(history.length, 2);
  assert.equal(history[0].country, 'Singapore');
  assert.equal(history[0].isCurrentActive, false); // Previous observation preserved as historical
  assert.equal(history[1].country, 'Netherlands');
  assert.equal(history[1].isCurrentActive, true); // Latest active

  // 3. Third rotation: United States
  await repo.saveInfrastructureObservation({
    id: 'obs-test-3',
    incidentId,
    ip: '45.154.255.192',
    timestamp: '2026-09-14T10:45:03.000Z',
    country: 'United States',
    region: 'Virginia',
    city: 'Ashburn',
    latitude: 39.0438,
    longitude: -77.4874,
    asn: 'AS67890',
    provider: 'Equinix Hosting Services',
    domain: 'api-login-auth.com',
    source: 'dns',
    confidence: 89,
    nodeRole: 'secondary-redirect',
    statusNote: 'DNS secondary round-robin record'
  });

  history = await repo.getInfrastructureObservations(incidentId);
  assert.equal(history.length, 3);
  assert.deepEqual(history.map(o => o.country), ['Singapore', 'Netherlands', 'United States']);
  assert.equal(history[0].isCurrentActive, false);
  assert.equal(history[1].isCurrentActive, false);
  assert.equal(history[2].isCurrentActive, true);
});

test('Forensics Engine: extractInfrastructureObservationsFromDossier extracts immutable observations', () => {
  const mockDossier: ForensicDossier = {
    headerFields: {
      from: 'billing@m1crosoft-support.com',
      to: 'victim@enterprise.com',
      subject: 'Urgent: Account Suspension Notice',
      date: 'Mon, 14 Sep 2026 10:42:01 +0000',
      messageId: '<msg-12345@m1crosoft-support.com>'
    },
    senderIdentity: {
      fromAddress: 'billing@m1crosoft-support.com',
      fromDomain: 'm1crosoft-support.com',
      displayName: 'Microsoft Security Team',
      replyToAddress: 'drop-box@external-phish.net',
      returnPathAddress: 'bounce@m1crosoft-support.com',
      returnPathDomain: 'm1crosoft-support.com',
      domainMatch: false,
      replyToDivergence: true,
      senderType: 'EXTERNAL'
    },
    authentication: {
      spf: { status: 'FAIL', rawHeader: 'spf=fail', senderIp: '185.220.101.44' } as any,
      dkim: { status: 'FAIL', rawHeader: 'dkim=fail' } as any,
      dmarc: { status: 'FAIL', policy: 'REJECT', alignmentStatus: 'FAIL' } as any
    },
    originIP: {
      ip: '185.220.101.44',
      country: 'Singapore',
      countryCode: 'SG',
      city: 'Singapore',
      region: 'Central',
      asn: 'AS12345',
      isp: 'Pacific Cloud Services',
      hostingProvider: 'Pacific Cloud Services',
      isTor: false,
      isVpn: false,
      isProxy: true,
      threatReputation: 'SUSPICIOUS',
      abuseScore: 82,
      latitude: 1.3521,
      longitude: 103.8198
    },
    relayReconstruction: {
      chronologicalHops: [
        {
          hopNumber: 1,
          sourceIP: '185.220.101.44',
          destinationIP: '103.253.42.87',
          country: 'Singapore',
          city: 'Singapore',
          isAnomalous: false,
          delaySeconds: 1
        } as any,
        {
          hopNumber: 2,
          sourceIP: '103.253.42.87',
          destinationIP: 'mail.enterprise.com',
          country: 'Netherlands',
          city: 'Amsterdam',
          isAnomalous: false,
          delaySeconds: 2
        } as any
      ],
      totalTransitTimeSeconds: 3,
      isAnomalousRoute: false,
      unusualDelaysDetected: false
    } as any,
    classification: {
      threatType: 'Credential Phishing',
      riskScore: 92,
      severity: 'CRITICAL',
      confidence: 88,
      primaryReason: 'DMARC rejection and lookalike domain'
    },
    chainOfCustody: {
      caseId: 'INC-2026-TEST-99',
      ingestionTimestamp: '2026-09-14T10:42:01.000Z',
      sha256EvidenceHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      rfcCompliant: true,
      validationVerdict: 'TAMPER_FREE'
    } as any
  } as any;

  const observations = extractInfrastructureObservationsFromDossier(mockDossier);
  assert.ok(observations.length >= 2, 'Should extract origin IP and relay hop IP');

  // Verify non-attribution source tagging
  for (const obs of observations) {
    assert.ok(obs.source, 'Every observation must have an evidence source');
    assert.ok(obs.confidence >= 50 && obs.confidence <= 100, 'Confidence must be within 50-100');
    assert.ok(obs.ip, 'IP address must be present');
  }

  // Verify origin hop was tagged
  const originObs = observations.find(o => o.ip === '185.220.101.44');
  assert.ok(originObs);
  assert.equal(originObs?.country, 'Singapore');
  assert.equal(originObs?.trustBoundary, 'origin');
});

test('Forensics Engine: buildInfrastructureCorrelation establishes cross-indicator correlation', () => {
  const mockDossier: ForensicDossier = {
    senderIdentity: {
      fromDomain: 'm1crosoft-support.com'
    },
    chainOfCustody: {
      caseId: 'INC-2026-0914-1042'
    }
  } as any;

  const observations: InfrastructureObservation[] = [
    {
      id: 'obs-1',
      incidentId: 'INC-2026-0914-1042',
      ip: '185.220.101.44',
      timestamp: '2026-09-14T10:42:01Z',
      country: 'Singapore',
      asn: 'AS12345 (Equinix Asia Backbone)',
      provider: 'Pacific Cloud',
      domain: 'm1crosoft-support.com',
      source: 'received-chain',
      confidence: 82,
      nodeRole: 'probable-origin',
      isCurrentActive: false
    },
    {
      id: 'obs-2',
      incidentId: 'INC-2026-0914-1042',
      ip: '103.253.42.87',
      timestamp: '2026-09-14T10:43:17Z',
      country: 'Netherlands',
      asn: 'AS12345 (Equinix Asia Backbone)', // Shared ASN!
      provider: 'Pacific Cloud',
      domain: 'm1crosoft-support.com', // Shared Domain!
      source: 'url-resolution',
      confidence: 76,
      nodeRole: 'payload-url',
      isCurrentActive: true
    }
  ];

  const correlation = buildInfrastructureCorrelation(mockDossier, observations);

  assert.equal(correlation.primaryIncidentId, 'INC-2026-0914-1042');
  assert.equal(correlation.activeIp, '103.253.42.87');
  assert.equal(correlation.totalHistoricalObservations, 2);
  assert.equal(correlation.campaignConfidenceLevel, 'HIGH');
  assert.ok(correlation.correlatedIncidents.length > 0, 'Correlated incidents must be linked');
  assert.ok(correlation.continuityEvidence.length >= 3);
});

test('Forensics Engine: generateForensicCaseReport enforces Investigation-Ready non-attribution format', () => {
  const mockDossier: ForensicDossier = {
    chainOfCustody: {
      caseId: 'CASE-2026-0914-1042',
      sha256EvidenceHash: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0'
    },
    classification: {
      threatType: 'Phishing / BEC Vector',
      riskScore: 92,
      severity: 'CRITICAL',
      protectionAction: 'BLOCK'
    },
    headerFields: {
      subject: 'Security Alert: Immediate Action Required',
      date: '2026-09-14T10:42:01Z',
      messageId: '<alert-1042@m1crosoft-support.com>'
    },
    senderIdentity: {
      displayName: 'IT Security',
      fromAddress: 'admin@m1crosoft-support.com',
      fromDomain: 'm1crosoft-support.com'
    },
    authentication: {
      spf: { status: 'FAIL' },
      dkim: { status: 'FAIL' },
      dmarc: { status: 'FAIL', alignmentStatus: 'FAIL' }
    }
  } as any;

  const observations: InfrastructureObservation[] = [
    {
      id: 'obs-1',
      incidentId: 'CASE-2026-0914-1042',
      ip: '185.220.101.44',
      timestamp: '2026-09-14T10:42:01Z',
      country: 'Singapore',
      asn: 'AS12345',
      provider: 'Pacific Cloud',
      source: 'received-chain',
      confidence: 85,
      nodeRole: 'probable-origin'
    }
  ];

  const correlation = buildInfrastructureCorrelation(mockDossier, observations);
  const report = generateForensicCaseReport(mockDossier, observations, correlation);

  assert.equal(report.caseId, 'CASE-2026-0914-1042');
  assert.equal(report.classification.protectionAction, 'BLOCK');
  assert.ok(report.evidenceProvenance.length > 0);
  assert.ok(report.chainOfCustody.analystAttributionNote.includes('IP Geolocation reflects observed transmission network infrastructure'));
  assert.ok(report.chainOfCustody.analystAttributionNote.includes('not physical adversary attribution'));
});
