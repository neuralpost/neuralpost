// ═══════════════════════════════════════════════════════════════════════════
// Type declarations for @x402/* packages
// These packages ship ESM-only types (.d.mts) which aren't resolved
// under moduleResolution: "node". Declarations here bridge the gap.
//
// Generated from actual CJS exports in node_modules/@x402/*/dist/cjs/
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
    resource?: string;
    extensions?: Record<string, unknown>;
    unpaidResponseBody?: (context: any) => Promise<any>;
    customPaywallHtml?: string;
  }

  export type RoutesConfig = Record<string, RouteConfig>;

  export interface PaywallConfig {
    sessionTokenEndpoint?: string;
    cdpClientKey?: string;
  }

  /**
   * Official @x402/hono paymentMiddleware
   * Handles full flow: 402 → verify → next() → settle (deferred)
   */
  export function paymentMiddleware(
    routes: RoutesConfig,
    server: x402ResourceServer,
    paywallConfig?: PaywallConfig,
    paywall?: any,
    syncFacilitatorOnStart?: boolean,
  ): MiddlewareHandler;

  export function paymentMiddlewareFromHTTPServer(
    httpServer: any,
    paywallConfig?: PaywallConfig,
    paywall?: any,
    syncFacilitatorOnStart?: boolean,
  ): MiddlewareHandler;

  export function paymentMiddlewareFromConfig(
    routes: RoutesConfig,
    facilitatorClients: any,
    schemes?: Array<{ network: string; server: any }>,
    paywallConfig?: PaywallConfig,
    paywall?: any,
    syncFacilitatorOnStart?: boolean,
  ): MiddlewareHandler;

  export class HonoAdapter {
    constructor(c: any);
    getHeader(name: string): string | undefined;
    getAcceptHeader(): string;
    getUserAgent(): string;
    getUrl(): string;
  }

  // Re-exported from @x402/core/server
  export class x402ResourceServer {
    constructor(facilitatorClients?: any);

    register(network: string, scheme: any): this;
    hasRegisteredScheme(network: string, scheme: string): boolean;

    registerExtension(extension: any): this;
    hasExtension(key: string): boolean;
    getExtensions(): any[];

    /** Fetch supported kinds from facilitator(s) — MUST call before verify/settle */
    initialize(): Promise<void>;

    /** Build payment requirements for a route config */
    buildPaymentRequirements(resourceConfig: any): Promise<any[]>;

    /** Build requirements from multiple payment options */
    buildPaymentRequirementsFromOptions(paymentOptions: any[], context: any): Promise<any[]>;

    /** Create 402 response object */
    createPaymentRequiredResponse(
      requirements: any[],
      resourceInfo: any,
      error?: string,
      extensions?: any,
    ): Promise<any>;

    /**
     * Verify a decoded payment payload against requirements.
     * @param paymentPayload - Decoded PaymentPayload object (NOT raw base64 string)
     * @param requirements - PaymentRequirement to verify against
     */
    verifyPayment(paymentPayload: any, requirements: any): Promise<{
      isValid: boolean;
      invalidReason?: string;
      invalidMessage?: string;
      payer?: string;
    }>;

    /**
     * Settle a verified payment on-chain via facilitator.
     * @param paymentPayload - Decoded PaymentPayload object (NOT raw base64 string)
     * @param requirements - PaymentRequirement for settlement
     * @param declaredExtensions - Optional extensions
     */
    settlePayment(paymentPayload: any, requirements: any, declaredExtensions?: any): Promise<{
      success: boolean;
      transaction?: string;
      network?: string;
      errorReason?: string;
      errorMessage?: string;
      extensions?: Record<string, any>;
    }>;

    /** Find matching requirements for a payment payload */
    findMatchingRequirements(availableRequirements: any[], paymentPayload: any): any | undefined;

    // Hooks
    onBeforeVerify(hook: any): this;
    onAfterVerify(hook: any): this;
    onVerifyFailure(hook: any): this;
    onBeforeSettle(hook: any): this;
    onAfterSettle(hook: any): this;
    onSettleFailure(hook: any): this;
  }

  export class x402HTTPResourceServer {
    constructor(resourceServer: x402ResourceServer, routes: RoutesConfig);
    get server(): x402ResourceServer;
    get routes(): RoutesConfig;
    initialize(): Promise<void>;
    requiresPayment(context: any): boolean;
    processHTTPRequest(context: any, paywallConfig?: PaywallConfig): Promise<any>;
    processSettlement(paymentPayload: any, requirements: any, declaredExtensions?: any): Promise<any>;
    onProtectedRequest(hook: any): this;
    registerPaywallProvider(provider: any): this;
  }

  export class RouteConfigurationError extends Error {
    constructor(errors: string[]);
  }
}

declare module '@x402/evm/exact/server' {
  export class ExactEvmScheme {
    constructor();
    readonly scheme: string;
    parsePrice(price: string, network: string): Promise<any>;
    enhancePaymentRequirements(requirements: any, kind: any, extensions?: any[]): Promise<any>;
  }
}

declare module '@x402/core/server' {
  export interface FacilitatorClientConfig {
    url?: string;
    createAuthHeaders?: (operation: string) => Promise<{ headers: Record<string, string> }> | { headers: Record<string, string> };
  }

  export class HTTPFacilitatorClient {
    constructor(config?: FacilitatorClientConfig);

    /** Fetch supported payment kinds from facilitator */
    getSupported(): Promise<{
      kinds: Array<{
        x402Version: number;
        scheme: string;
        network: string;
      }>;
      extensions?: any[];
    }>;

    /** Verify payment with facilitator POST /verify */
    verify(paymentPayload: any, paymentRequirements: any): Promise<{
      isValid: boolean;
      invalidReason?: string;
      invalidMessage?: string;
      payer?: string;
    }>;

    /** Settle payment with facilitator POST /settle */
    settle(paymentPayload: any, paymentRequirements: any): Promise<{
      success: boolean;
      transaction?: string;
      network?: string;
      errorReason?: string;
      errorMessage?: string;
    }>;
  }

  // Re-exports
  export class x402ResourceServer {
    constructor(facilitatorClients?: any);
    register(network: string, scheme: any): this;
    initialize(): Promise<void>;
    verifyPayment(paymentPayload: any, requirements: any): Promise<any>;
    settlePayment(paymentPayload: any, requirements: any, declaredExtensions?: any): Promise<any>;
  }

  export class x402HTTPResourceServer {
    constructor(resourceServer: any, routes: any);
    initialize(): Promise<void>;
    processHTTPRequest(context: any, paywallConfig?: any): Promise<any>;
    processSettlement(paymentPayload: any, requirements: any, declaredExtensions?: any): Promise<any>;
  }

  export class RouteConfigurationError extends Error {}
}
