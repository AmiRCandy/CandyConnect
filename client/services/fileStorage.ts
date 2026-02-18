// ============================================================
// CandyConnect VPN Client - File Storage Service
// Handles reading/writing settings.json, account.json, candy.logs
// Files are stored in the Tauri app data directory.
// ============================================================

import {
  readTextFile,
  writeTextFile,
  exists,
} from '@tauri-apps/plugin-fs';
import { BaseDirectory } from '@tauri-apps/api/path';

import type { Settings, ClientAccount } from './api';

// --- Types ---

export interface LogEntry {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
}

// File paths relative to AppData directory
const FILES = {
  SETTINGS: 'settings.json',
  ACCOUNT: 'account.json',
  LOGS: 'candy.logs',
} as const;

const BASE_DIR = BaseDirectory.AppData;

// ============================================================
// Generic File Helpers
// ============================================================

/**
 * Read a JSON file from app data directory and parse it.
 * Returns the parsed object, or the fallback value if the file doesn't exist or is invalid.
 */
async function readJsonFile<T>(filename: string, fallback: T): Promise<T> {
  try {
    const fileExists = await exists(filename, { baseDir: BASE_DIR });
    if (!fileExists) {
      return fallback;
    }
    const content = await readTextFile(filename, { baseDir: BASE_DIR });
    return JSON.parse(content) as T;
  } catch (error) {
    console.error(`Failed to read ${filename}:`, error);
    return fallback;
  }
}

/**
 * Write a value as JSON to a file in the app data directory.
 */
async function writeJsonFile<T>(filename: string, data: T): Promise<void> {
  try {
    const content = JSON.stringify(data, null, 2);
    await writeTextFile(filename, content, { baseDir: BASE_DIR });
  } catch (error) {
    console.error(`Failed to write ${filename}:`, error);
    throw error;
  }
}

// ============================================================
// Settings (settings.json)
// ============================================================

/**
 * Read all settings from settings.json.
 */
export async function readSettings(): Promise<Settings> {
  return readJsonFile<Settings>(FILES.SETTINGS, {});
}

/**
 * Write the entire settings object to settings.json (full replace).
 */
export async function writeSettings(settings: Settings): Promise<void> {
  await writeJsonFile(FILES.SETTINGS, settings);
}

/**
 * Update specific settings fields without overwriting the entire file.
 * Merges the partial settings with the existing ones.
 */
export async function updateSettings(partial: Partial<Settings>): Promise<Settings> {
  const current = await readSettings();
  const merged = { ...current, ...partial };
  await writeSettings(merged);
  return merged;
}

/**
 * Read a single setting value by key.
 * Returns undefined if the key doesn't exist.
 */
export async function getSettingValue<K extends keyof Settings>(key: K): Promise<Settings[K] | undefined> {
  const settings = await readSettings();
  return settings[key];
}

/**
 * Set a single setting value by key.
 */
export async function setSettingValue<K extends keyof Settings>(key: K, value: Settings[K]): Promise<void> {
  await updateSettings({ [key]: value } as Partial<Settings>);
}

/**
 * Reset settings to defaults by writing an empty object.
 * On next app start, Rust will regenerate the defaults.
 */
export async function resetSettings(): Promise<void> {
  const defaults: Settings = {
    autoConnect: false,
    launchAtStartup: false,
    selectedProfile: '',
    selectedProtocol: 'v2ray',
    theme: 'light',
    language: 'en',
    proxyHost: '127.0.0.1',
    proxyPort: 1080,
    adBlocking: true,
    malwareProtection: true,
    phishingPrevention: false,
    cryptominerBlocking: false,
    directCountryAccess: true,
    v2rayCore: 'sing-box',
    wireguardCore: 'amnezia',
    proxyMode: 'proxy',
    proxyType: 'socks',
    autoReconnect: true,
    killSwitch: false,
    dnsLeakProtection: true,
    splitTunneling: false,
    dnsttResolver: 'auto',
    dnsttProxyPort: 7070,
  };
  await writeSettings(defaults);
}

// ============================================================
// Account (account.json)
// ============================================================

/**
 * Read the account data from account.json.
 * Returns null if no account is stored.
 */
export async function readAccount(): Promise<ClientAccount | null> {
  const data = await readJsonFile<ClientAccount | Record<string, never>>(FILES.ACCOUNT, {});
  // If the object is empty (no username), treat it as no account
  if (!data || !('username' in data) || !data.username) {
    return null;
  }
  return data as ClientAccount;
}

/**
 * Write account data to account.json (full replace).
 */
export async function writeAccount(account: ClientAccount): Promise<void> {
  await writeJsonFile(FILES.ACCOUNT, account);
}

/**
 * Update specific account fields without overwriting the entire file.
 */
export async function updateAccount(partial: Partial<ClientAccount>): Promise<ClientAccount | null> {
  const current = await readAccount();
  if (!current) {
    console.warn('No account exists to update');
    return null;
  }
  const merged = { ...current, ...partial };
  await writeAccount(merged);
  return merged;
}

/**
 * Clear the stored account data (e.g. on logout).
 * Writes an empty object to account.json.
 */
export async function clearAccount(): Promise<void> {
  await writeJsonFile(FILES.ACCOUNT, {});
}

/**
 * Check if an account is currently stored.
 */
export async function hasAccount(): Promise<boolean> {
  const account = await readAccount();
  return account !== null;
}

// ============================================================
// Logs (candy.logs)
// ============================================================

/**
 * Read all log entries from candy.logs.
 */
export async function readLogs(): Promise<LogEntry[]> {
  return readJsonFile<LogEntry[]>(FILES.LOGS, []);
}

/**
 * Write the entire log array to candy.logs (full replace).
 */
export async function writeLogs(logs: LogEntry[]): Promise<void> {
  await writeJsonFile(FILES.LOGS, logs);
}

/**
 * Append a single log entry to candy.logs.
 */
export async function addLog(level: LogEntry['level'], message: string): Promise<void> {
  const logs = await readLogs();
  logs.push({
    timestamp: new Date().toISOString(),
    level,
    message,
  });
  await writeLogs(logs);
}

/**
 * Append multiple log entries at once to candy.logs.
 */
export async function addLogs(entries: Omit<LogEntry, 'timestamp'>[]): Promise<void> {
  const logs = await readLogs();
  const now = new Date().toISOString();
  for (const entry of entries) {
    logs.push({
      timestamp: now,
      level: entry.level,
      message: entry.message,
    });
  }
  await writeLogs(logs);
}

/**
 * Clear all logs from candy.logs.
 */
export async function clearLogs(): Promise<void> {
  await writeLogs([]);
}

/**
 * Get logs filtered by level.
 */
export async function getLogsByLevel(level: LogEntry['level']): Promise<LogEntry[]> {
  const logs = await readLogs();
  return logs.filter((log) => log.level === level);
}

/**
 * Get the most recent N log entries.
 */
export async function getRecentLogs(count: number): Promise<LogEntry[]> {
  const logs = await readLogs();
  return logs.slice(-count);
}

/**
 * Get logs within a date range.
 */
export async function getLogsByDateRange(from: Date, to: Date): Promise<LogEntry[]> {
  const logs = await readLogs();
  return logs.filter((log) => {
    const logDate = new Date(log.timestamp);
    return logDate >= from && logDate <= to;
  });
}

// ============================================================
// Utility
// ============================================================

/**
 * Check if a specific app data file exists.
 */
export async function fileExists(filename: 'settings' | 'account' | 'logs'): Promise<boolean> {
  const fileMap = {
    settings: FILES.SETTINGS,
    account: FILES.ACCOUNT,
    logs: FILES.LOGS,
  };
  try {
    return await exists(fileMap[filename], { baseDir: BASE_DIR });
  } catch {
    return false;
  }
}

/**
 * Check if all required app data files exist.
 */
export async function allFilesExist(): Promise<boolean> {
  const [s, a, l] = await Promise.all([
    fileExists('settings'),
    fileExists('account'),
    fileExists('logs'),
  ]);
  return s && a && l;
}
