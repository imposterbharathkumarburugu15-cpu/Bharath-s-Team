import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: "50mb" }));
  app.use(express.urlencoded({ extended: true, limit: "50mb" }));

  // Safe server-side Gemini client retrieval
  const getAiClient = () => {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey || apiKey === "MY_GEMINI_API_KEY" || apiKey.trim() === "" || apiKey === "undefined") {
      return null;
    }
    try {
      return new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          }
        }
      });
    } catch (e) {
      console.warn("Failed to instantiate GoogleGenAI server client:", e);
      return null;
    }
  };

  // Health check
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // Threat Scan endpoint
  app.post("/api/scan", async (req, res) => {
    try {
      const { text, language = "en", base64Image, mimeType } = req.body;
      const ai = getAiClient();
      if (!ai) {
        return res.status(200).json({ fallback: true, message: "AI client unconfigured" });
      }

      const parts: any[] = [];
      if (text && typeof text === "string" && text.trim()) {
        parts.push({ text });
      }
      if (base64Image && mimeType) {
        parts.push({
          inlineData: { data: base64Image, mimeType }
        });
      }

      const languageMap: Record<string, string> = {
        en: 'English',
        hi: 'Hindi',
        te: 'Telugu'
      };
      const targetLang = languageMap[language] || 'English';

      parts.push({
        text: `Analyze the provided input (text and/or image) for potential phishing, scams, or malicious intent. 
1. Auto-detect whether this represents an EMAIL, a CHAT message, a URL/Domain, CODE, a NETWORK_LOG, a QR code, a FILE or UNKNOWN.
2. Provide a risk score from 0 to 100 (100 being most dangerous). If the input is a benign website, legitimate web application, portfolio, staging deployment (e.g. Vercel, Netlify, GitHub Pages), or normal text with no malicious code, scams, or credential harvesting, assign a low/safe risk score (0-15) and note that the domain appears legitimate and safe.
3. List detection signals (short, bold phrases like "CLEAN_REPUTATION" or "URGENT LANGUAGE DETECTED").
4. Identify the likely source (attacker IP, sender email, or domain) and target (user or system).
5. Describe the payload/attack vector briefly. If benign, state "Legitimate web application" or "No threat detected".
6. Identify any sensitive data exposed (e.g., credit cards, tokens, personal info) and provide a masked version. If none, return an empty array.
7. Provide a short threat name (e.g., "Safe Web Deployment" if benign, or "Impersonation Scam" if malicious).
8. Provide a clear AI explanation of the findings.
9. Extract an array of suspicious keywords (empty if benign).
10. Extract an array of detected links.

ALL RESPONSES AND STRINGS (EXCEPT ENUM VALUES) MUST BE IN ${targetLang}.`,
      });

      const response = await ai.models.generateContent({
        model: "gemini-3.7-flash",
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
                properties: {
                  urgency: { type: Type.NUMBER },
                  financial: { type: Type.NUMBER },
                  impersonation: { type: Type.NUMBER },
                  deception: { type: Type.NUMBER },
                  coercion: { type: Type.NUMBER },
                },
                required: ["urgency", "financial", "impersonation", "deception", "coercion"]
              },
              urlMetrics: {
                type: Type.OBJECT,
                properties: {
                  domainAge: { type: Type.STRING },
                  sslCertificate: { type: Type.STRING },
                  blacklistStatus: { type: Type.STRING },
                  typosquatting: { type: Type.STRING },
                  subdomains: { type: Type.STRING },
                  radarData: {
                    type: Type.OBJECT,
                    properties: {
                      domainAge: { type: Type.NUMBER },
                      sslStatus: { type: Type.NUMBER },
                      blacklist: { type: Type.NUMBER },
                      typosquatting: { type: Type.NUMBER },
                      subdomains: { type: Type.NUMBER },
                      contentRisk: { type: Type.NUMBER },
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
      if (!textRes) return res.status(200).json({ fallback: true });
      return res.json(JSON.parse(textRes));
    } catch (err: any) {
      console.warn("Server-side scan fallback engaged:", err?.message || err);
      return res.status(200).json({ fallback: true, error: err?.message || "AI unavailable" });
    }
  });

  // Audio scan endpoint
  app.post("/api/audio", async (req, res) => {
    try {
      const { base64Audio, mimeType, language = "en" } = req.body;
      const ai = getAiClient();
      if (!ai) {
        return res.status(200).json({ fallback: true });
      }

      const parts: any[] = [{
        inlineData: { data: base64Audio, mimeType }
      }];
      const languageMap: Record<string, string> = { en: 'English', hi: 'Hindi', te: 'Telugu' };
      const targetLang = languageMap[language] || 'English';

      parts.push({
        text: `You are NEUROSHIELD VOICE, an AI deepfake and scam detection engine. Analyze the provided audio accurately.
1. Determine if it's likely a deepfake/synthetic voice, AI generated, or an authentic human recording.
2. Provide an authenticity score from 0 to 100 (where 100 is authentic human voice, and 0 is definitely synthetic/deepfake).
3. Transcribe ONLY what was actually spoken in the audio recording. If there is no speech, silent background, or indistinct noise, return ["No spoken dialogue detected / Ambient background audio."]. DO NOT hallucinate or generate fictional phone conversations.
4. List detection signals (short phrases like "NATURAL_VOCAL_RESONANCE", "ORGANIC_BREATH_PATTERN" or "SYNTHETIC_CADENCE_DETECTED").
5. Provide a short, factual explanation of the acoustic findings.

ALL TEXT FIELDS EXPLANATION MUST BE IN ${targetLang}.`
      });

      const response = await ai.models.generateContent({
        model: "gemini-3.7-flash",
        contents: { parts },
        config: {
          temperature: 0.1,
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              isDeepfake: { type: Type.BOOLEAN },
              authenticityScore: { type: Type.NUMBER },
              transcript: { type: Type.ARRAY, items: { type: Type.STRING } },
              signals: { type: Type.ARRAY, items: { type: Type.STRING } },
              explanation: { type: Type.STRING }
            },
            required: ["isDeepfake", "authenticityScore", "transcript", "signals", "explanation"]
          }
        }
      });

      const textRes = response.text;
      if (!textRes) return res.status(200).json({ fallback: true });
      return res.json(JSON.parse(textRes));
    } catch (err: any) {
      console.warn("Server-side audio analysis fallback engaged:", err?.message || err);
      return res.status(200).json({ fallback: true, error: err?.message || "AI unavailable" });
    }
  });

  // Copilot endpoint
  app.post("/api/copilot", async (req, res) => {
    try {
      const { history = [], newMessage, language = "en" } = req.body;
      const ai = getAiClient();
      if (!ai) {
        return res.status(200).json({ fallback: true });
      }

      const languageMap: Record<string, string> = { en: 'English', hi: 'Hindi', te: 'Telugu' };
      const targetLang = languageMap[language] || 'English';

      const systemPrompt = `You are NEUROSHIELD COPILOT, an advanced enterprise cybersecurity AI assistant.
Your goal is to help users investigate threats, understand security architecture, investigate logs, and provide mitigation strategies.
Keep your responses concise, highly technical but accessible, and structured with markdown. Use a cutting-edge, "cyber" tone.
IMPORTANT: Respond entirely in ${targetLang}.`;

      const contents = [
        { role: 'user', parts: [{ text: systemPrompt }] },
        { role: 'model', parts: [{ text: 'Acknowledged. NeuroShield Copilot sequence initiated.' }] }
      ];

      for (const msg of history) {
        contents.push({ role: msg.role, parts: [{ text: msg.content }] });
      }
      contents.push({ role: 'user', parts: [{ text: newMessage }] });

      const response = await ai.models.generateContent({
        model: "gemini-3.7-flash",
        contents,
        config: { temperature: 0.3 }
      });

      if (response.text) {
        return res.json({ response: response.text });
      }
      return res.status(200).json({ fallback: true });
    } catch (err: any) {
      console.warn("Server-side Copilot fallback engaged:", err?.message || err);
      return res.status(200).json({ fallback: true, error: err?.message || "AI unavailable" });
    }
  });

  // Vite middleware / static files
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
