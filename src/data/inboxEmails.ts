import { ForensicDossier } from '@/services/forensicsEngine';

export interface InboxEmailItem {
  id: string;
  senderName: string;
  senderEmail: string;
  isVerified?: boolean;
  avatarLetter: string;
  subject: string;
  snippet: string;
  timeString: string;
  score: number;
  riskCategory: 'HIGH RISK' | 'SUSPICIOUS' | 'LOW RISK';
  tags: { text: string; type: 'red' | 'amber' | 'emerald' }[];
  rawHeaders: string;
  body: string;
  dossier?: ForensicDossier;
}

export const SHOWCASE_INBOX_EMAILS: InboxEmailItem[] = [
  {
    id: 'exec_wire_01',
    senderName: 'Executive Desk',
    senderEmail: 'ceo.management@global-corp.info',
    isVerified: false,
    avatarLetter: 'E',
    subject: 'URGENT: Confidential Acquisition Wire Instruction',
    snippet: 'Please process the confidential vendor settlement wire prior to EOD...',
    timeString: '10:14 AM',
    score: 92,
    riskCategory: 'HIGH RISK',
    tags: [
      { text: '🚫 Sender Impersonation', type: 'red' },
      { text: 'Suspicious Domain', type: 'red' },
      { text: 'Urgency', type: 'red' }
    ],
    rawHeaders: `From: "Executive Desk" <ceo.management@global-corp.info>
To: target-analyst@company.com
Reply-To: wire.settlements.desk@gmail.com
Return-Path: <bounce@mail.global-corp.info>
Subject: URGENT: Confidential Acquisition Wire Instruction
Message-ID: <wire-92817@global-corp.info>
Date: Today, 10:14:00 +0000

Received: from mail.global-corp.info (185.220.101.45)
    by mx.company.com with ESMTPS;
    Today, 10:13:55 +0000

Authentication-Results: mx.company.com;
    spf=fail smtp.mailfrom=global-corp.info;
    dkim=none;
    dmarc=fail header.from=global-corp.info`,
    body: `Please process the confidential vendor settlement wire prior to EOD. Do not discuss through typical internal channels as this acquisition remains strictly embargoed under corporate non-disclosure agreements. Transmit the full $480,000 disbursement immediately to secure closing.`
  },
  {
    id: 'billing_res_02',
    senderName: 'Billing Resolution',
    senderEmail: 'invoice.dispute.desk@gmail.com',
    isVerified: false,
    avatarLetter: 'B',
    subject: 'Past Due Final Demand: Invoice #INV-88910',
    snippet: 'Your subscription is suspended. Re-verify payment billing immediately...',
    timeString: 'Yesterday 4:45 PM',
    score: 87,
    riskCategory: 'HIGH RISK',
    tags: [
      { text: 'Payment Fraud', type: 'red' },
      { text: '⚠️ Suspicious Link', type: 'amber' },
      { text: 'Brand Impersonation', type: 'amber' }
    ],
    rawHeaders: `From: "Billing Resolution" <invoice.dispute.desk@gmail.com>
To: finance@company.com
Reply-To: collections@billing-resolution-disputes.com
Return-Path: <bounce@billing-resolution-disputes.com>
Subject: Past Due Final Demand: Invoice #INV-88910
Message-ID: <inv-88910@billing-resolution-disputes.com>
Date: Yesterday, 16:45:00 +0000

Received: from relay02.billing-resolution-disputes.com (194.26.29.110)
    by mx.company.com with ESMTP;
    Yesterday, 16:44:50 +0000

Authentication-Results: mx.company.com;
    spf=fail smtp.mailfrom=billing-resolution-disputes.com;
    dkim=fail;
    dmarc=fail header.from=billing-resolution-disputes.com`,
    body: `Your corporate subscription is suspended. Re-verify payment billing immediately via the secure dispute portal to prevent complete service termination and statutory late collection penalties: http://billing-resolution-disputes.com/pay-invoice`
  },
  {
    id: 'it_ops_03',
    senderName: 'IT Operations',
    senderEmail: 'service-notification@outlook.com',
    isVerified: false,
    avatarLetter: 'S',
    subject: 'Security Alert: Password Expiring in 2 Hours',
    snippet: 'Your single-sign on credentials are scheduled for revocation. Update...',
    timeString: '2 days ago',
    score: 61,
    riskCategory: 'SUSPICIOUS',
    tags: [
      { text: 'Urgency', type: 'red' },
      { text: 'Credential Harvesting', type: 'amber' },
      { text: 'Suspicious Domain', type: 'red' }
    ],
    rawHeaders: `From: "IT Operations" <service-notification@outlook.com>
To: internal-user@company.com
Reply-To: it-helpdesk-verification@gmail.com
Return-Path: <bounce@service-notification-sso.xyz>
Subject: Security Alert: Password Expiring in 2 Hours
Message-ID: <alert-7721@service-notification-sso.xyz>
Date: Mon, 31 Aug 2026 09:12:00 +0000

Received: from sso-relay.service-notification-sso.xyz (185.220.101.99)
    by mx.company.com with ESMTPS;
    Mon, 31 Aug 2026 09:11:45 +0000

Authentication-Results: mx.company.com;
    spf=neutral smtp.mailfrom=service-notification-sso.xyz;
    dkim=none;
    dmarc=fail header.from=outlook.com`,
    body: `Your single-sign on credentials are scheduled for revocation. Update your corporate active directory credentials within 2 hours to avoid mandatory manual helpdesk verification.`
  },
  {
    id: 'google_04',
    senderName: 'Google',
    senderEmail: 'no-reply@accounts.google.com',
    isVerified: true,
    avatarLetter: 'G',
    subject: 'Security alert',
    snippet: 'A new sign-in was made to your Google Account from a Windows device...',
    timeString: '3 days ago',
    score: 14,
    riskCategory: 'LOW RISK',
    tags: [
      { text: '✓ Legitimate Sender', type: 'emerald' },
      { text: 'No Suspicious Links', type: 'emerald' }
    ],
    rawHeaders: `From: "Google" <no-reply@accounts.google.com>
To: user@gmail.com
Subject: Security alert
Message-ID: <google-sec-9812@accounts.google.com>
Date: Sun, 30 Aug 2026 14:00:00 +0000

Received: from mail-wm1-x32e.google.com (209.85.128.175)
    by mx.google.com with ESMTPS;
    Sun, 30 Aug 2026 13:59:58 +0000

Authentication-Results: mx.google.com;
    spf=pass smtp.mailfrom=accounts.google.com;
    dkim=pass header.i=@accounts.google.com;
    dmarc=pass header.from=accounts.google.com`,
    body: `A new sign-in was made to your Google Account from a Windows device in Bangalore, India. If this was you, you don't need to take any action. If not, we'll help you secure your account.`
  },
  {
    id: 'notion_05',
    senderName: 'Notion',
    senderEmail: 'team@notion.so',
    isVerified: true,
    avatarLetter: 'N',
    subject: 'Your Notion workspace weekly digest',
    snippet: "Here's what happened in your workspace this week...",
    timeString: '3 days ago',
    score: 8,
    riskCategory: 'LOW RISK',
    tags: [
      { text: '✓ Trusted Sender', type: 'emerald' },
      { text: 'No Threats Detected', type: 'emerald' }
    ],
    rawHeaders: `From: "Notion" <team@notion.so>
To: user@company.com
Subject: Your Notion workspace weekly digest
Message-ID: <notion-digest-1928@notion.so>
Date: Sun, 30 Aug 2026 08:30:00 +0000

Received: from mail.notion.so (54.240.48.25)
    by mx.company.com with ESMTPS;
    Sun, 30 Aug 2026 08:29:55 +0000

Authentication-Results: mx.company.com;
    spf=pass smtp.mailfrom=notion.so;
    dkim=pass header.i=@notion.so;
    dmarc=pass header.from=notion.so`,
    body: `Here's what happened in your workspace this week. 14 pages were edited, 3 teammates joined your project channel, and all documents are synced.`
  },
  {
    id: 'hr_team_06',
    senderName: 'HR Team',
    senderEmail: 'hr@career-opportunities.com',
    isVerified: false,
    avatarLetter: 'H',
    subject: 'Interview Invitation – Software Developer Role',
    snippet: 'We were impressed with your profile. Please confirm your availability...',
    timeString: '4 days ago',
    score: 58,
    riskCategory: 'SUSPICIOUS',
    tags: [
      { text: 'Unusual Sender', type: 'amber' },
      { text: 'External Domain', type: 'amber' }
    ],
    rawHeaders: `From: "HR Team" <hr@career-opportunities.com>
To: applicant@gmail.com
Reply-To: recruitment-desk@outlook.com
Return-Path: <bounce@career-opportunities.com>
Subject: Interview Invitation – Software Developer Role
Message-ID: <interview-4412@career-opportunities.com>
Date: Sat, 29 Aug 2026 11:20:00 +0000

Received: from relay01.career-opportunities.com (104.28.19.44)
    by mx.gmail.com with ESMTPS;
    Sat, 29 Aug 2026 11:19:48 +0000

Authentication-Results: mx.gmail.com;
    spf=neutral smtp.mailfrom=career-opportunities.com;
    dkim=none;
    dmarc=none`,
    body: `We were impressed with your profile on our career portal. Please confirm your availability for an initial round with our engineering hiring managers this week.`
  }
];
