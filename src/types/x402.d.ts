// ═══════════════════════════════════════════════════════════════════════════
// Type declarations for @x402/* packages
// These packages ship ESM-only types (.d.mts) which aren't resolved
// under moduleResolution: "node". Declarations here bridge the gap.
//
// VERIFIED against @x402/core@2.3.1 + @x402/hono@2.3.0 actual source
// Last checked: 2026-02-15
// ═══════════════════════════════════════════════════════════════════════════

declare module '@x402/hono' {
  import type { MiddlewareHandler } from 'hono';

  export interface RouteAcceptsConfig {
    scheme: string;
    price: string;
    network: string;
    payTo: string;
    maxTimeoutSeconds?: number;
    extra?: Record<string, unknown>;
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

  // paymentMiddleware(routes, server, paywallConfig?, paywall?, syncFacilitatorOnStart?)
  export function paymentMiddleware(
    routes: RoutesConfig,
    server: x402ResourceServer,
    paywallConfig?: PaywallConfig,
    paywall?: any,
    syncFacilitatorOnStart?: boolean,
  ): MiddlewareHandler;

  export function paymentMiddlewareFromHTTPServer(
    httpServer: x402HTTPResourceServer,
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
    getMethod(): string;
    getPath(): string;
    getUrl(): string;
  }

  // Re-exports from @x402/core/server
  export { x402ResourceServer, x402HTTPResourceServer } from '@x402/core/server';
}

declare module '@x402/evm/exact/server' {
  export class ExactEvmScheme {
    constructor();
    readonly scheme: string;
    parsePrice(price: string, network: string): Promise<{
      amount: string;
      asset: string;
      extra?: Record<string, unknown>;
    }>;
    enhancePaymentRequirements(
      baseRequirements: any,
      supportedKind: any,
      facilitatorExtensions: any[],
    ): Promise<any>;
  }
}

declare module '@x402/core/server' {
  export interface FacilitatorClientConfig {
    url?: string;
    createAuthHeaders?: (action: string) => Promise<{ headers: Record<string, string> }>;
  }

  export class HTTPFacilitatorClient {
    constructor(config?: FacilitatorClientConfig);
    verify(paymentPayload: any, paymentRequirements: any): Promise<VerifyResponse>;
    settle(paymentPayload: any, paymentRequirements: any): Promise<SettleResponse>;
    getSupported(): Promise<{ kinds: any[]; extensions?: any[] }>;
  }

  export interface VerifyResponse {
    isValid: boolean;
    invalidReason?: string;
    invalidMessage?: string;
    payer?: string;
  }

  export interface SettleResponse {
    success: boolean;
    transaction?: string;
    network?: string;
    payer?: string;
    errorReason?: string;
    errorMessage?: string;
  }

  export class x402ResourceServer {
    constructor(facilitatorClients?: HTTPFacilitatorClient | HTTPFacilitatorClient[]);
    register(network: string, scheme: any): this;
    hasRegisteredScheme(network: string, scheme: string): boolean;
    registerExtension(extension: any): this;
    hasExtension(key: string): boolean;
    getExtensions(): any[];

    // Lifecycle
    initialize(): Promise<void>;

    // Payment processing — actual method names from SDK source
    verifyPayment(paymentPayload: any, requirements: any): Promise<VerifyResponse>;
    settlePayment(paymentPayload: any, requirements: any, declaredExtensions?: any): Promise<SettleResponse>;

    // Hooks
    onBeforeVerify(hook: (ctx: any) => Promise<any>): this;
    onAfterVerify(hook: (ctx: any) => Promise<any>): this;
    onVerifyFailure(hook: (ctx: any) => Promise<any>): this;
    onBeforeSettle(hook: (ctx: any) => Promise<any>): this;
    onAfterSettle(hook: (ctx: any) => Promise<any>): this;
    onSettleFailure(hook: (ctx: any) => Promise<any>): this;
  }

  export class x402HTTPResourceServer {
    constructor(resourceServer: x402ResourceServer, routes: any);
    get server(): x402ResourceServer;
    get routes(): any;
    initialize(): Promise<void>;
    requiresPayment(context: { path: string; method: string }): boolean;
    processHTTPRequest(context: any, paywallConfig?: any): Promise<any>;
    processSettlement(paymentPayload: any, requirements: any, declaredExtensions?: any): Promise<any>;
  }

  export class RouteConfigurationError extends Error {
    errors: any[];
  }
}
