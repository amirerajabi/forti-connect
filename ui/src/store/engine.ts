import { create } from 'zustand';
import type { Backends, EngineState, Settings } from '../../../shared/protocol';
import { api } from '../api/client';

const NO_BACKEND = { available: false, path: null, version: null } as const;

/** Engine-owned configuration: settings, the VPN programs found and the engine version. */
interface EngineConfigState {
  settings: Settings | null;
  backends: Backends;
  version: string;
  load(s: EngineState): void;
  setSettings(s: Settings): void;
  setBackends(b: Backends): void;
  updateSettings(patch: Partial<Settings>): Promise<void>;
}

export const useEngine = create<EngineConfigState>((set) => ({
  settings: null,
  backends: { ssl: { ...NO_BACKEND, kind: 'openconnect' }, ipsec: { ...NO_BACKEND, kind: 'ras' }, elevated: false, platform: 'win32' },
  version: '',
  load(s) {
    set({ settings: s.settings, backends: s.backends, version: s.version });
  },
  setSettings(settings) {
    set({ settings });
  },
  setBackends(backends) {
    set({ backends });
  },
  async updateSettings(patch) {
    const settings = await api.updateSettings(patch);
    set({ settings });
  },
}));

export function useSettings<T>(pick: (s: Settings) => T, fallback: T): T {
  return useEngine((s) => (s.settings ? pick(s.settings) : fallback));
}
