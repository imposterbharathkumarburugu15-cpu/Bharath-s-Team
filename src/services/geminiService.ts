import { GoogleGenAI, Type } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

export interface ScanResult {
  detectedType: 'EMAIL' | 'CHAT' | 'URL' | 'CODE' | 'NETWORK_LOG' | 'QR' | 'FILE' | 'AI_MANIPULATION' | 'UNKNOWN';
  riskScore: number;
  signals: string[];
  source: string;
  target: string;
  payloadDescription: string;
  maskedData?: Array<{ original: string; masked: string; type?: string }>;
  threatName?: string;
  aiExplanation?: string;
  suspiciousKeywords?: string[];
  detectedLinks?: string[];
  textMetrics?: {
    urgency: number;
    financial: number;
    impersonation: number;
    deception: number;
    coercion: number;
  };
  urlMetrics?: {
    domainAge: string;
    sslCertificate: string;
    blacklistStatus: string;
    typosquatting: string;
    subdomains: string;
    radarData: {
      domainAge: number;
      sslStatus: number;
      blacklist: number;
      typosquatting: number;
      subdomains: number;
      contentRisk: number;
    }
  };
}

export async function analyzeThreat(
  text: string,
  language: string = 'en',
  base64Image?: string,
  mimeType?: string
): Promise<ScanResult> {
  const parts: any[] = [];

  if (text && text.trim()) {
    parts.push({ text });
  }

  if (base64Image && mimeType) {
    parts.push({
      inlineData: {
        data: base64Image,
        mimeType,
      },
    });
  }

  const languageMap: Record<string, string> = {
    'en': 'English',
    'hi': 'Hindi',
    'te': 'Telugu'
  };
  const targetLang = languageMap[language] || 'English';

  parts.push({
    text: `Analyze the provided input (text and/or image) for potential phishing, scams, or malicious intent. 
1. Auto-detect whether this represents an EMAIL, a CHAT message, a URL/Domain, CODE, a NETWORK_LOG, a QR code, a FILE or UNKNOWN.
2. Provide a risk score from 0 to 100 (100 being most dangerous).
3. List detection signals (short, bold phrases like "URGENT LANGUAGE DETECTED").
4. Identify the likely source (attacker IP, sender email, or domain) and target (user or system).
5. Describe the payload/attack vector briefly.
6. Identify any sensitive data exposed (e.g., credit cards, tokens, personal info) and provide a masked version. If none, return an empty array.
7. Provide a short threat name (e.g., "Impersonation Scam").
8. Provide a clear AI explanation of why this was flagged.
9. Extract an array of suspicious keywords.
10. Extract an array of detected links.

ALL RESPONSES AND STRINGS (EXCEPT ENUM VALUES) MUST BE IN ${targetLang}.`,
  });

  const response = await ai.models.generateContent({
    model: "gemini-2.0-flash",
    contents: { parts },
    config: {
      temperature: 0.2,
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          detectedType: {
            type: Type.STRING,
            description: "The auto-detected type of the threat.",
            enum: ["EMAIL", "CHAT", "URL", "CODE", "NETWORK_LOG", "QR", "FILE", "AI_MANIPULATION", "UNKNOWN"],
          },
          riskScore: {
            type: Type.NUMBER,
            description: "The risk score from 0 to 100.",
          },
          signals: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
            description: "Short, impactful signals like 'URGENT LANGUAGE DETECTED'",
          },
          source: {
            type: Type.STRING,
            description: "The attacker source, e.g., '192.168.*.*' or 'fake@paypal.com'",
          },
          target: {
            type: Type.STRING,
            description: "The target, e.g., 'USER SYSTEM' or 'finance@corp.com'",
          },
          payloadDescription: {
            type: Type.STRING,
            description: "A short description of the payload or attack, e.g., 'Phishing Link'",
          },
          maskedData: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                original: { type: Type.STRING },
                masked: { type: Type.STRING },
              },
            },
          },
          threatName: {
            type: Type.STRING,
            description: "A short name for the threat, e.g. 'Impersonation Scam'",
          },
          aiExplanation: {
            type: Type.STRING,
            description: "AI's explanation of the threat, e.g. 'This message exhibits signs of an impersonation scam...'",
          },
          suspiciousKeywords: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
            description: "Array of suspicious words/phrases found in the input.",
          },
          detectedLinks: {
            type: Type.ARRAY,
            items: { type: Type.STRING },
            description: "Array of links found in the input.",
          },
          textMetrics: {
            type: Type.OBJECT,
            description: "If the input is text (CHAT, EMAIL, etc.), provide these vector scores.",
            properties: {
              urgency: { type: Type.NUMBER, description: "Score out of 100" },
              financial: { type: Type.NUMBER, description: "Score out of 100" },
              impersonation: { type: Type.NUMBER, description: "Score out of 100" },
              deception: { type: Type.NUMBER, description: "Score out of 100" },
              coercion: { type: Type.NUMBER, description: "Score out of 100" },
            },
            required: ["urgency", "financial", "impersonation", "deception", "coercion"]
          },
          urlMetrics: {
            type: Type.OBJECT,
            description: "If the input is a URL, provide these metrics.",
            properties: {
              domainAge: { type: Type.STRING, description: "e.g., '1 week', '5+ years'" },
              sslCertificate: { type: Type.STRING, description: "e.g., 'Valid (Let\\'s Encrypt)', 'Invalid'" },
              blacklistStatus: { type: Type.STRING, description: "e.g., 'Clean', 'Flagged by 3 engines'" },
              typosquatting: { type: Type.STRING, description: "e.g., 'None detected', 'Matches paypal.com'" },
              subdomains: { type: Type.STRING, description: "e.g., 'None', 'suspicious-auth'" },
              radarData: {
                type: Type.OBJECT,
                properties: {
                  domainAge: { type: Type.NUMBER, description: "Score out of 100" },
                  sslStatus: { type: Type.NUMBER, description: "Score out of 100" },
                  blacklist: { type: Type.NUMBER, description: "Score out of 100" },
                  typosquatting: { type: Type.NUMBER, description: "Score out of 100" },
                  subdomains: { type: Type.NUMBER, description: "Score out of 100" },
                  contentRisk: { type: Type.NUMBER, description: "Score out of 100" },
                },
                required: ["domainAge", "sslStatus", "blacklist", "typosquatting", "subdomains", "contentRisk"],
              }
            },
            required: ["domainAge", "sslCertificate", "blacklistStatus", "typosquatting", "subdomains", "radarData"]
          }
        },
        required: ["detectedType", "riskScore", "signals", "source", "target", "payloadDescription", "maskedData"],
      },
    },
  });

  const textRes = response.text;
  if (!textRes) throw new Error("No response from AI");
  
  return JSON.parse(textRes) as ScanResult;
}

export interface AudioScanResult {
  isDeepfake: boolean;
  authenticityScore: number;
  transcript: string[];
  signals: string[];
  explanation: string;
}

export async function analyzeAudio(
  base64Audio: string,
  mimeType: string,
  language: string = 'en'
): Promise<AudioScanResult> {
  const parts: any[] = [];

  parts.push({
    inlineData: {
      data: base64Audio,
      mimeType,
    },
  });

  const languageMap: Record<string, string> = {
    'en': 'English',
    'hi': 'Hindi',
    'te': 'Telugu'
  };
  const targetLang = languageMap[language] || 'English';

  parts.push({
    text: `You are SENTINEL VOICE, an AI deepfake and scam detection engine. Analyze the provided audio.
1. Determine if it's likely a deepfake/synthetic voice, AI generated, or a common scam.
2. Provide an authenticity score from 0 to 100 (where 100 is authentic human voice, and 0 is definitely synthetic/scam).
3. Transcribe the audio as an array of strings (e.g. ["Caller: Hello", "User: Hi"]). Feel free to use "Speaker 1" format.
4. List detection signals (short phrases like "SYNTHETIC CADENCE DETECTED", "SCAM SCRIPT DETECTED").
5. Provide a short explanation.

ALL TEXT FIELDS EXPLANATION MUST BE IN ${targetLang}.`,
  });

  const response = await ai.models.generateContent({
    model: "gemini-2.5-flash",
    contents: { parts },
    config: {
      temperature: 0.1,
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          isDeepfake: { type: Type.BOOLEAN, description: "True if highly likely to be deepfake or scam." },
          authenticityScore: { type: Type.NUMBER, description: "Authenticity score 0-100." },
          transcript: { type: Type.ARRAY, items: { type: Type.STRING }, description: "Line by line transcription." },
          signals: { type: Type.ARRAY, items: { type: Type.STRING }, description: "Deception signals." },
          explanation: { type: Type.STRING, description: "Why it was rated this way." },
        },
        required: ["isDeepfake", "authenticityScore", "transcript", "signals", "explanation"],
      },
    },
  });

  const textRes = response.text;
  if (!textRes) throw new Error("No response from AI");
  
  return JSON.parse(textRes) as AudioScanResult;
}

export interface CopilotMessage {
  role: 'user' | 'model';
  content: string;
}

export async function chatWithCopilot(
  history: CopilotMessage[],
  newMessage: string,
  language: string = 'en'
): Promise<string> {
  const languageMap: Record<string, string> = {
    'en': 'English',
    'hi': 'Hindi',
    'te': 'Telugu'
  };
  const targetLang = languageMap[language] || 'English';

  const systemPrompt = `You are SENTINEL COPILOT, an advanced enterprise cybersecurity AI assistant.
Your goal is to help users investigate threats, understand security architecture, investigate logs, and provide mitigation strategies.
Keep your responses concise, highly technical but accessible, and structured with markdown. Use a cutting-edge, "cyber" tone.
IMPORTANT: Respond entirely in ${targetLang}.`;

  const contents = [
    { role: 'user', parts: [{ text: systemPrompt }] },
    { role: 'model', parts: [{ text: 'Acknowledged. Sentinel Copilot sequence initiated.' }] }
  ];

  for (const msg of history) {
    contents.push({ role: msg.role, parts: [{ text: msg.content }] });
  }
  
  contents.push({ role: 'user', parts: [{ text: newMessage }] });

  const response = await ai.models.generateContent({
    model: "gemini-2.0-flash",
    contents,
    config: {
      temperature: 0.3,
    },
  });

  return response.text || "NO RESPONSE DETECTED FROM AI ENGINE.";
}
