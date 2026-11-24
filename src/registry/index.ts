// Process registry (01-REQ-05): hands the config resolved by withSecurity() to the reporter and
// the fixtures of the same process. Symbol.for gives one slot even when the ESM and the CJS
// build are both loaded.
import type { ResolvedSecurityConfig } from '../core/config/index.ts';
import type { Diagnostic } from '../core/types/index.ts';
import type { ScanMode } from '../mode/index.ts';

export const REGISTRY_KEY: unique symbol = Symbol.for('playwright-security-scan.registry');

export interface RegisteredState {
  config: ResolvedSecurityConfig;
  mode: ScanMode;
  runId: string;
  /** Redaction salt of the run (07-REQ-15); the same in every process of the run. */
  salt: string;
  pkgVersion: string;
  /** Origins of use.baseURL of the scanned projects (05-REQ-04). */
  baseOrigins: string[];
  /** Names of the projects the collector runs in (05-REQ-03). */
  scannedProjects: string[];
  /** withSecurity() got a package config (argument or PW_SEC_CONFIG). */
  configPassed: boolean;
  /** Warnings found by withSecurity(); the reporter reports them. */
  warnings: Diagnostic[];
}

interface RegistrySlot {
  state: RegisteredState | undefined;
  /** test objects returned by withSecurityFixtures(). */
  wrappedTests: WeakSet<object>;
  /** Contexts registered with trackContext() in this worker (05-REQ-02). */
  trackedContexts: Set<object>;
  /** The collector of the running test, so trackContext() during a test applies at once. */
  activeCollector: unknown;
  /** APIRequestContext objects whose methods are wrapped (15-REQ-02). */
  wrappedRequestContexts: WeakSet<object>;
}

function slot(): RegistrySlot {
  const global = globalThis as Record<symbol, unknown>;
  let current = global[REGISTRY_KEY] as RegistrySlot | undefined;
  if (current === undefined) {
    current = {
      state: undefined,
      wrappedTests: new WeakSet(),
      trackedContexts: new Set(),
      activeCollector: undefined,
      wrappedRequestContexts: new WeakSet(),
    };
    global[REGISTRY_KEY] = current;
  }
  return current;
}

export function setRegistered(state: RegisteredState): void {
  slot().state = state;
}

export function getRegistered(): RegisteredState | undefined {
  return slot().state;
}

export function wrappedTests(): WeakSet<object> {
  return slot().wrappedTests;
}

export function trackedContexts(): Set<object> {
  return slot().trackedContexts;
}

export function wrappedRequestContexts(): WeakSet<object> {
  return slot().wrappedRequestContexts;
}

export function activeCollector<T>(): T | undefined {
  return slot().activeCollector as T | undefined;
}

export function setActiveCollector(collector: unknown): void {
  slot().activeCollector = collector;
}

/** Clears the registry; for tests of the package only. */
export function resetRegistryForTests(): void {
  Reflect.deleteProperty(globalThis, REGISTRY_KEY);
}
