import type { EngineEvent } from '../../../shared/protocol';
import { api } from '../api/client';
import { connectEvents } from '../api/ws';
import { getPlatform } from '../platform';
import { useConnection } from '../store/connection';
import { useEngine } from '../store/engine';
import { currentProfile, useProfiles } from '../store/profiles';
import { useUi } from '../store/ui';
import { useUpdates } from '../store/updates';

async function loadState(): Promise<void> {
  try {
    const state = await api.state();
    useEngine.getState().load(state);
    useProfiles.getState().setProfiles(state.profiles, state.selectedId);
    const c = useConnection.getState();
    c.setConnection(state.connection);
    c.setLogs(state.logs);
    c.setTesting(state.testing);
    useUi.getState().setEngineError(null);
    syncPreferences();
    syncTray();
  } catch (e) {
    useUi.getState().setEngineError(e instanceof Error ? e.message : String(e));
  }
}

function syncPreferences(): void {
  const s = useEngine.getState().settings;
  if (s) getPlatform().setPreferences({ minimizeToTray: s.minimizeToTray, autoUpdate: s.autoUpdate, launchAtLogin: s.launchAtLogin, language: s.language });
}

/** The tray icon and its Connect / Disconnect item follow the connection. */
function syncTray(): void {
  const { connection } = useConnection.getState();
  const { profiles, selectedId } = useProfiles.getState();
  const profile = currentProfile(profiles, connection.profileId, selectedId);
  const status = connection.status === 'connected' ? 'connected' : connection.status === 'connecting' ? 'connecting' : 'disconnected';
  getPlatform().setTrayState({ status, profile: profile?.name ?? '' });
}

function onEvent(e: EngineEvent): void {
  switch (e.type) {
    case 'settings':
      useEngine.getState().setSettings(e.settings);
      syncPreferences();
      return;
    case 'profiles':
      useProfiles.getState().setProfiles(e.profiles, e.selectedId);
      syncTray();
      return;
    case 'connection': {
      const prev = useConnection.getState().connection;
      useConnection.getState().setConnection(e.connection);
      syncTray();
      const name = useProfiles.getState().profiles.find((p) => p.id === e.connection.profileId)?.name ?? '';
      if (e.connection.status === 'connected' && prev.status !== 'connected') getPlatform().notify('Connected', name);
      // A question while the window is hidden (a FortiToken code): bring it up so the user sees it.
      if (e.connection.prompt && e.connection.prompt.id !== prev.prompt?.id) getPlatform().notify('FortiConnect is waiting for you', e.connection.prompt.message);
      return;
    }
    case 'traffic':
      useConnection.getState().setTraffic(e.traffic);
      return;
    case 'backends':
      useEngine.getState().setBackends(e.backends);
      return;
    case 'log':
      useConnection.getState().addLogs(e.lines);
      return;
    case 'delay':
      useProfiles.getState().applyDelays(e.results);
      return;
    case 'testing':
      useConnection.getState().setTesting(e.testing);
      return;
    case 'notify':
      useUi.getState().toast({ level: e.level, text: e.text, detail: e.detail });
      if (e.level === 'error') getPlatform().notify(e.text, e.detail ?? '');
      return;
  }
}

let started = false;

export function boot(): void {
  if (started) return;
  started = true;
  connectEvents(onEvent, loadState);
  // In-app updates (desktop): the current state now, then every change the main process pushes.
  const platform = getPlatform();
  void platform.getUpdateStatus().then((s) => s && useUpdates.getState().setStatus(s));
  platform.onUpdateStatus((s) => useUpdates.getState().setStatus(s));
}

export const reloadState = loadState;
