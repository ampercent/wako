import axios from 'axios';

const API_BASE = 'http://localhost:8001';

const telemetryClient = axios.create({
  baseURL: API_BASE,
  timeout: 3000,
  headers: { 'Content-Type': 'application/json' },
});

interface FrontendLogEntry {
  endpoint: string;
  error: string;
  component: string;
  stack?: string;
  request_id?: string;
  user_agent?: string;
}

/**
 * Send error telemetry to the backend.
 * Fire-and-forget — never blocks the UI or surfaces its own errors.
 */
export async function reportFrontendError(entry: FrontendLogEntry): Promise<void> {
  try {
    await telemetryClient.post('/logs/frontend', {
      ...entry,
      user_agent: navigator.userAgent,
      timestamp: new Date().toISOString(),
    });
  } catch {
    // Silently fail — telemetry must never crash the app
  }
}

/**
 * Capture unhandled errors and promise rejections.
 * Call once at app startup (e.g., in main.tsx).
 */
export function installGlobalErrorHandlers(): void {
  // Unhandled errors
  window.addEventListener('error', (event) => {
    reportFrontendError({
      endpoint: window.location.pathname,
      error: event.message || 'Unknown error',
      component: 'window.onerror',
      stack: event.error?.stack?.slice(0, 1000),
    });
  });

  // Unhandled promise rejections
  window.addEventListener('unhandledrejection', (event) => {
    const reason = event.reason;
    reportFrontendError({
      endpoint: window.location.pathname,
      error: reason?.message || String(reason) || 'Unhandled rejection',
      component: 'unhandledrejection',
      stack: reason?.stack?.slice(0, 1000),
    });
  });
}

/**
 * Log a caught error from a specific component.
 * Use this in catch blocks for important operations.
 */
export function logComponentError(
  component: string,
  error: unknown,
  endpoint?: string,
): void {
  const msg = error instanceof Error ? error.message : String(error);
  const stack = error instanceof Error ? error.stack?.slice(0, 1000) : undefined;

  reportFrontendError({
    endpoint: endpoint || window.location.pathname,
    error: msg,
    component,
    stack,
  });
}
