/**
 * Aegis AI Firewall - Official Lightweight TypeScript / Node.js SDK
 */

export interface AegisScanResponse {
  decision: 'ALLOW' | 'SANITIZE' | 'BLOCK' | 'REQUIRE_REVIEW';
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  sanitizedContent?: string;
  attackTypes: string[];
  requestId: string;
  evidence: Array<{ detector: string; signal: string; severity: string }>;
}

export interface AegisToolCheckResponse {
  decision: 'ALLOW' | 'BLOCK' | 'REQUIRE_REVIEW';
  reason: string;
  riskScore: number;
  tool: string;
}

export class AegisFirewall {
  private baseUrl: string;
  private apiKey: string;

  constructor(options: { baseUrl?: string; apiKey: string }) {
    this.baseUrl = (options.baseUrl || 'http://localhost:8000').replace(/\/+$/, '');
    this.apiKey = options.apiKey;
  }

  /**
   * Pre-flight prompt inspection
   */
  async scan(params: {
    content: string;
    sessionId?: string;
    sourceType?: string;
  }): Promise<AegisScanResponse> {
    const res = await fetch(`${this.baseUrl}/v1/security/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
        'X-API-Key': this.apiKey,
      },
      body: JSON.stringify({
        content: params.content,
        sessionId: params.sessionId || 'default-session',
        sourceType: params.sourceType || 'user',
      }),
    });

    if (!res.ok) {
      throw new Error(`Aegis scan failed with status: ${res.status}`);
    }

    return (await res.json()) as AegisScanResponse;
  }

  /**
   * Authorize tool call before agent execution
   */
  async checkTool(params: {
    tool: string;
    arguments: Record<string, any>;
    requestedBy?: string;
    sessionId?: string;
  }): Promise<AegisToolCheckResponse> {
    const res = await fetch(`${this.baseUrl}/v1/security/tool/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${this.apiKey}`,
        'X-API-Key': this.apiKey,
      },
      body: JSON.stringify({
        tool: params.tool,
        arguments: params.arguments,
        requestedBy: params.requestedBy || 'agent',
        sessionId: params.sessionId || 'default-session',
      }),
    });

    if (!res.ok) {
      throw new Error(`Aegis tool check failed with status: ${res.status}`);
    }

    return (await res.json()) as AegisToolCheckResponse;
  }
}
