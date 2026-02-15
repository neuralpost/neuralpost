// ═══════════════════════════════════════════════════════════════════════════
// Type declarations for @x402/* packages
// These packages ship ESM-only types (.d.mts) which aren't resolved
// under moduleResolution: "node". Declarations here bridge the gap.
// ═══════════════════════════════════════════════════════════════════════════

declare module '@x402/hono' {
  import type { MiddlewareHandler } from 'hono';

  export interface RouteAcceptsConfig {
    scheme: string;
    price: string;
    network: string;
    payTo: string;
    maxTimeoutSeconds?: number;
  }

  export interface RouteConfig {
    accepts: RouteAcceptsConfig | RouteAcceptsConfig[];
    description?: string;
    mimeType?: string;
    extensions?: Record<string, unknown>;
  }

  export type RoutesConfig = Record<string, RouteConfig>;

  export interface PaywallConfig {
    sessionTokenEndpoint?: string;
    cdpClientKey?: string;
  }

  export function paymentMiddleware(
    routes: RoutesConfig,
    server: x402ResourceServer,
    paywallConfig?: PaywallConfig,
  ): MiddlewareHandler;

  export class x402ResourceServer {
    constructor(facilitatorClient: any);
    register(network: string, scheme: any): this;
    verify(paymentSignature: string, paymentRequirement: any): Promise<{
      isValid: boolean;
      invalidReason?: string;
      payer?: string;
    }>;
    settle(paymentSignature: string, paymentRequirement: any): Promise<{
      success: boolean;
      transaction?: string;
      network?: string;
      errorReason?: string;
      errorMessage?: string;
    }>;
  }
}

declare module '@x402/evm/exact/server' {
  export class ExactEvmScheme {
    constructor();
  }
}

declare module '@x402/core/server' {
  export interface FacilitatorClientConfig {
    url: string;
    createAuthHeaders?: () => Record<string, string>;
  }

  export class HTTPFacilitatorClient {
    constructor(config: FacilitatorClientConfig);
  }
}
