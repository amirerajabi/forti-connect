import { create } from 'zustand';
import type { Profile, VpnType } from '../../../shared/protocol';

/** Which profiles the Profiles page shows: all of them, or one kind. */
export type TypeFilter = 'all' | VpnType;
export type SortKey = 'list' | 'name' | 'delay';

interface ProfilesState {
  profiles: Profile[];
  /** The profile Connect uses (engine state). */
  selectedId: string | null;
  filter: TypeFilter;
  query: string;
  sort: SortKey;
  setProfiles(profiles: Profile[], selectedId: string | null): void;
  applyDelays(results: { id: string; delay: number }[]): void;
  setFilter(f: TypeFilter): void;
  setQuery(q: string): void;
  setSort(s: SortKey): void;
}

export const useProfiles = create<ProfilesState>((set, get) => ({
  profiles: [],
  selectedId: null,
  filter: 'all',
  query: '',
  sort: 'list',
  setProfiles: (profiles, selectedId) => set({ profiles, selectedId }),
  applyDelays(results) {
    const byId = new Map(results.map((r) => [r.id, r.delay]));
    set({ profiles: get().profiles.map((p) => (byId.has(p.id) ? { ...p, delay: byId.get(p.id)! } : p)) });
  },
  setFilter: (filter) => set({ filter }),
  setQuery: (query) => set({ query }),
  setSort: (sort) => set({ sort }),
}));

/** The profiles the page shows, in order. */
export function visibleProfiles(s: Pick<ProfilesState, 'profiles' | 'filter' | 'query' | 'sort'>): Profile[] {
  const q = s.query.trim().toLowerCase();
  let list = s.profiles.filter((p) => s.filter === 'all' || p.type === s.filter);
  if (q) list = list.filter((p) => p.name.toLowerCase().includes(q) || p.gateway.toLowerCase().includes(q) || p.username.toLowerCase().includes(q));
  if (s.sort === 'name') list = [...list].sort((a, b) => a.name.localeCompare(b.name));
  else if (s.sort === 'delay') {
    // Answering gateways fastest first, then failed ones, then unchecked.
    const rank = (d: number | null) => (d === null ? Number.MAX_SAFE_INTEGER : d < 0 ? Number.MAX_SAFE_INTEGER - 1 : d);
    list = [...list].sort((a, b) => rank(a.delay) - rank(b.delay));
  }
  return list;
}

/** The profile the connection uses, or the selected one when disconnected. */
export function currentProfile(profiles: Profile[], connectionProfileId: string | null, selectedId: string | null): Profile | undefined {
  return profiles.find((p) => p.id === (connectionProfileId ?? selectedId));
}
