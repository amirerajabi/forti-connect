import type { Backends, ConnectionState, EngineState, GatewayCheck, ImportResult, Profile, ProfileInput, Settings, VpnType } from '../../../shared/protocol';
import { getPlatform } from '../platform';

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const { engineUrl, token } = getPlatform();
  let res: Response;
  try {
    res = await fetch(`${engineUrl}${path}`, {
      method,
      headers: { Authorization: `Bearer ${token}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, 'Cannot reach the FortiConnect engine');
  }
  const data = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) throw new ApiError(res.status, data.error ?? `Request failed (${res.status})`);
  return data as T;
}

export const api = {
  state: () => call<EngineState>('GET', '/api/state'),
  updateSettings: (patch: Partial<Settings>) => call<Settings>('PUT', '/api/settings', patch),
  addProfile: (input: ProfileInput) => call<Profile>('POST', '/api/profiles', input),
  updateProfile: (id: string, patch: Partial<ProfileInput>) => call<Profile>('PATCH', `/api/profiles/${id}`, patch),
  duplicateProfile: (id: string) => call<Profile>('POST', `/api/profiles/${id}/duplicate`),
  deleteProfiles: (ids: string[]) => call<{ ok: true }>('POST', '/api/profiles/delete', { ids }),
  select: (id: string) => call<{ ok: true }>('POST', `/api/profiles/${id}/select`),
  profileLink: (id: string) => call<{ link: string }>('GET', `/api/profiles/${id}/link`),
  importLinks: (text: string) => call<ImportResult>('POST', '/api/profiles/import', { text }),
  test: (ids: string[]) => call<{ ok: true }>('POST', '/api/profiles/test', { ids }),
  checkGateway: (type: VpnType, gateway: string, port: number) => call<GatewayCheck>('POST', '/api/gateway/check', { type, gateway, port }),
  connect: (id?: string) => call<ConnectionState>('POST', '/api/connect', { id }),
  answer: (id: string, value: string, remember?: boolean) => call<{ ok: true }>('POST', '/api/connect/answer', { id, value, remember }),
  disconnect: () => call<ConnectionState>('POST', '/api/disconnect'),
  refreshBackends: () => call<Backends>('POST', '/api/backends/refresh'),
  clearLogs: () => call<{ ok: true }>('POST', '/api/logs/clear'),
};
