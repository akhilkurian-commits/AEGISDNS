
import { GoogleGenAI, Type } from "@google/genai";
import { DNSQuery, ForensicReport, ThreatLevel } from "../types";

const genAI = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });

export const analyzeForensics = async (logs: DNSQuery[]): Promise<ForensicReport> => {
  const model = genAI.models.generateContent({
    model: "gemini-3-flash-preview",
    contents: `Analyze the following DNS traffic for tunneling activity. 
    Traffic Data (sample): ${JSON.stringify(logs.slice(0, 30))}
    
    Look for:
    1. High entropy strings (Base64/Hex encoding)
    2. Long subdomain chains
    3. C2 communication patterns
    4. Unusual query structures`,
    config: {
      responseMimeType: "application/json",
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          summary: { type: Type.STRING, description: "Detailed executive summary of findings." },
          threatLevel: { type: Type.STRING, description: "One of: LOW, MEDIUM, HIGH, CRITICAL" },
          indicators: { type: Type.ARRAY, items: { type: Type.STRING }, description: "List of IOCs detected." },
          timeline: { 
            type: Type.ARRAY, 
            items: { 
              type: Type.OBJECT, 
              properties: { 
                time: { type: Type.STRING }, 
                event: { type: Type.STRING } 
              },
              required: ["time", "event"]
            } 
          },
          recommendation: { type: Type.STRING, description: "Specific remediation steps." },
          detectedTunnels: { type: Type.ARRAY, items: { type: Type.STRING }, description: "Specific domains identified as tunnels." }
        },
        required: ["summary", "threatLevel", "indicators", "timeline", "recommendation", "detectedTunnels"]
      }
    }
  });

  const response = await model;
  const result = JSON.parse(response.text || '{}');
  return result as ForensicReport;
};
