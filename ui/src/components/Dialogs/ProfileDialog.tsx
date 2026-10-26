import { FolderOpen, Gauge, KeyRound, LoaderCircle, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import type { GatewayCheck, IkeMode, Profile, ProfileInput, VpnType } from '../../../../shared/protocol';
import { api } from '../../api/client';
import { useT } from '../../i18n';
import { ikeLabel } from '../../lib/format';
import { getPlatform } from '../../platform';
import { useEngine } from '../../store/engine';
import { useProfiles } from '../../store/profiles';
import { useUi } from '../../store/ui';
import { Dialog, Field } from '../common/Dialog';

const IKE_MODES: { id: IkeMode; label: string; hint: string }[] = [
  { id: 'ikev1', label: 'IKEv1 + XAuth (FortiClient default)', hint: 'Pre-shared key plus your user name and password. What a FortiGate dial-up tunnel for FortiClient uses.' },
  { id: 'ikev2', label: 'IKEv2 + EAP', hint: 'User name and password over IKEv2. The FortiGate tunnel must have EAP turned on.' },
  { id: 'l2tp', label: 'L2TP/IPsec', hint: 'Pre-shared key, then your user name and password over L2TP.' },
];

/**
 * What was typed or pasted into the gateway field: a bare host stays as it is; a portal address
 * ("https://vpn.example.com:10443/staff", "vpn.example.com:10443") also gives the port and the realm.
 */
export function splitGateway(raw: string): { gateway: string; port?: number; realm?: string } {
  const m = /^(?:https?:\/\/)?(\[[^\]]+\]|[^/:?#\s]+)(?::(\d{1,5}))?(\/[^?#]*)?/i.exec(raw.trim());
  if (!m || (!/^https?:\/\//i.test(raw.trim()) && !m[2] && !m[3])) return { gateway: raw };
  const realm = m[3]?.replace(/^\/+|\/+$/g, '');
  return { gateway: m[1].replace(/^\[|\]$/g, ''), port: m[2] ? Number(m[2]) : undefined, realm: realm && !realm.startsWith('remote') ? realm : undefined };
}

/** The form with a pasted portal address split into gateway, port and realm (on leaving the field, and on save). */
function applyGateway(f: ProfileInput): ProfileInput {
  const g = splitGateway(f.gateway);
  return { ...f, gateway: g.gateway, ...(g.port ? { port: g.port } : {}), ...(g.realm && f.type === 'ssl' ? { realm: g.realm } : {}) };
}

/** Add a profile (id null) or edit one. */
export function ProfileDialog() {
  const state = useUi((s) => s.profileDialog);
  if (!state) return null;
  return <ProfileForm key={state.id ?? 'new'} id={state.id} />;
}

/** A secret field: empty keeps what is saved, `clear` removes it, text replaces it. */
type Secret = { value: string; clear: boolean };

/** The engine's rule: '' clears, undefined keeps, a string sets. */
function secretField(s: Secret): string | undefined {
  return s.clear ? '' : s.value || undefined;
}

function ProfileForm({ id }: { id: string | null }) {
  const t = useT();
  const existing = useProfiles((s) => (id ? s.profiles.find((p) => p.id === id) : undefined));
  const backends = useEngine((s) => s.backends);
  const electron = getPlatform().kind === 'electron';
  const [f, setF] = useState<ProfileInput>(() => initial(existing));
  const [password, setPassword] = useState<Secret>({ value: '', clear: false });
  const [psk, setPsk] = useState<Secret>({ value: '', clear: false });
  const [routes, setRoutes] = useState((existing?.routes ?? []).join(', '));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [check, setCheck] = useState<GatewayCheck | null>(null);
  const [checking, setChecking] = useState(false);
  const close = () => useUi.getState().set({ profileDialog: null });
  const set = (patch: Partial<ProfileInput>) => setF((x) => ({ ...x, ...patch }));

  if (id && !existing) return null;
  const ssl = f.type === 'ssl';
  const ike = f.ike ?? 'ikev1';
  // FortiGate dial-up tunnels use a pre-shared key in every IPsec mode (IKEv2 as FortiClient does it, too).
  const needsPsk = !ssl;
  const supported = backends.ipsec.modes;

  const runCheck = async () => {
    setChecking(true);
    setCheck(null);
    try {
      const g = applyGateway(f);
      setCheck(await api.checkGateway(g.type, g.gateway.trim(), g.port));
    } catch (e) {
      setCheck({ ok: false, ms: -1, error: e instanceof Error ? e.message : String(e) });
    } finally {
      setChecking(false);
    }
  };

  const browseCert = async () => {
    const picked = await getPlatform().chooseFile('cert', f.clientCert || undefined);
    if (picked) set({ clientCert: picked });
  };

  const submit = async () => {
    setBusy(true);
    setError(null);
    const g = applyGateway(f);
    const input: ProfileInput = {
      ...g,
      name: g.name.trim() || g.gateway.trim(),
      gateway: g.gateway.trim(),
      username: f.username.trim(),
      routes: ssl ? [] : routes.split(/[\s,;]+/).filter(Boolean),
      password: secretField(password),
      psk: needsPsk ? secretField(psk) : undefined,
    };
    try {
      if (id) await api.updateProfile(id, input);
      else {
        const p = await api.addProfile(input);
        await api.select(p.id).catch(() => undefined);
      }
      close();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      title={id ? t('Edit profile') : t('Add profile')}
      icon={<KeyRound size={18} className="text-accent" />}
      width={620}
      onClose={close}
      onSubmit={() => void submit()}
      footer={
        <>
          <button className="btn" onClick={close}>
            {t('Cancel')}
          </button>
          <button className="btn btn-primary" disabled={busy || !f.gateway.trim()} onClick={() => void submit()}>
            {busy && <LoaderCircle size={16} className="spin" />} {t('Save')}
          </button>
        </>
      }
    >
      <div className="form">
        <Field label={t('Kind')}>
          <div className="segmented" role="radiogroup">
            {(['ssl', 'ipsec'] as VpnType[]).map((type) => (
              <button key={type} type="button" role="radio" aria-checked={f.type === type} className={f.type === type ? 'on' : ''} onClick={() => (set({ type }), setCheck(null))}>
                {t(type === 'ssl' ? 'SSL-VPN' : 'IPsec')}
              </button>
            ))}
          </div>
        </Field>
        <Field label={t('Name')} hint={t('Leave empty to use the gateway address.')}>
          <input className="input" value={f.name} autoFocus placeholder={t('Office')} onChange={(e) => set({ name: e.target.value })} />
        </Field>
        <div className="form-row">
          <Field label={t('Gateway')} hint={t('The FortiGate’s address, without https://')}>
            <input className="input mono-sm" dir="ltr" value={f.gateway} placeholder="vpn.example.com" spellCheck={false} onChange={(e) => (set({ gateway: e.target.value }), setCheck(null))} onBlur={() => setF(applyGateway)} />
          </Field>
          {ssl && (
            <Field label={t('Port')}>
              <input className="input narrow" type="number" dir="ltr" min={1} max={65535} value={f.port} onChange={(e) => set({ port: Math.max(1, Math.min(65535, Math.round(Number(e.target.value) || 443))) })} />
            </Field>
          )}
        </div>
        <div className="form-row">
          <Field label={t('User name')}>
            <input className="input" dir="ltr" value={f.username} spellCheck={false} autoComplete="off" onChange={(e) => set({ username: e.target.value })} />
          </Field>
          <Field
            label={t('Password')}
            hint={
              existing?.hasPassword && !password.clear ? (
                <button type="button" className="link-btn" onClick={() => setPassword({ value: '', clear: true })}>
                  {t('Clear saved password')}
                </button>
              ) : password.clear ? (
                t('The saved password is removed when you save.')
              ) : undefined
            }
          >
            <input
              className="input"
              type="password"
              dir="ltr"
              autoComplete="new-password"
              value={password.value}
              placeholder={existing?.hasPassword && !password.clear ? t('Saved') : t('Asked when connecting')}
              onChange={(e) => setPassword({ value: e.target.value, clear: false })}
            />
          </Field>
        </div>
        <label className="toggle-row">
          <input type="checkbox" className="switch" checked={f.savePassword} onChange={(e) => set({ savePassword: e.target.checked })} />
          <span>
            <span className="toggle-label">{t('Save password')}</span>
            <span className="field-hint">{t('Kept encrypted on this computer. Without it, FortiConnect asks each time.')}</span>
          </span>
        </label>

        {ssl ? (
          <>
            <Field label={t('Realm')} hint={t('Only if your address looks like https://vpn.example.com/realm.')}>
              <input className="input mono-sm" dir="ltr" value={f.realm ?? ''} spellCheck={false} onChange={(e) => set({ realm: e.target.value })} />
            </Field>
            <Field label={t('Trusted certificate')} hint={t('Pin the gateway’s certificate when it is self-signed. Check gateway shows it.')}>
              <div className="input-with-btn">
                <input className="input mono-sm" dir="ltr" value={f.trustedCert ?? ''} placeholder="pin-sha256:…" spellCheck={false} onChange={(e) => set({ trustedCert: e.target.value })} />
                <button type="button" className="btn" disabled={checking || !f.gateway.trim()} onClick={() => void runCheck()}>
                  {checking ? <LoaderCircle size={16} className="spin" /> : <Gauge size={16} />} {t('Check gateway')}
                </button>
              </div>
            </Field>
            <Field label={t('Client certificate')} hint={t('A PEM or PKCS#12 file, only if the FortiGate asks for one.')}>
              <div className="input-with-btn">
                <input className="input mono-sm" dir="ltr" value={f.clientCert ?? ''} spellCheck={false} onChange={(e) => set({ clientCert: e.target.value })} />
                {electron && (
                  <button type="button" className="btn" onClick={() => void browseCert()}>
                    <FolderOpen size={16} /> {t('Browse')}
                  </button>
                )}
              </div>
            </Field>
          </>
        ) : (
          <>
            <Field label={t('IKE mode')}>
              <div className="choice-list" role="radiogroup">
                {IKE_MODES.map((m) => {
                  const here = !supported || supported.includes(m.id);
                  return (
                    <label key={m.id} className={`choice${ike === m.id ? ' on' : ''}`}>
                      <input type="radio" name="ike-mode" checked={ike === m.id} onChange={() => set({ ike: m.id })} />
                      <span>
                        <span className="toggle-label">
                          {t(m.label)} {!here && <span className="muted">· {t('not on this computer')}</span>}
                        </span>
                        <span className="field-hint">{t(m.hint)}</span>
                      </span>
                    </label>
                  );
                })}
              </div>
            </Field>
            {supported && !supported.includes(ike) && (
              <div className="notice warning">
                {t('The IPsec client here ({kind}) can do: {modes}.', { kind: backends.ipsec.kind === 'ras' ? t('Windows') : 'strongSwan', modes: supported.map(ikeLabel).join(', ') })}
              </div>
            )}
            {needsPsk && (
              <Field
                label={t('Pre-shared key')}
                hint={
                  existing?.hasPsk && !psk.clear ? (
                    <button type="button" className="link-btn" onClick={() => setPsk({ value: '', clear: true })}>
                      {t('Clear saved key')}
                    </button>
                  ) : psk.clear ? (
                    t('The saved key is removed when you save.')
                  ) : undefined
                }
              >
                <input
                  className="input"
                  type="password"
                  dir="ltr"
                  autoComplete="new-password"
                  value={psk.value}
                  placeholder={existing?.hasPsk && !psk.clear ? t('Saved') : t('Asked when connecting')}
                  onChange={(e) => setPsk({ value: e.target.value, clear: false })}
                />
              </Field>
            )}
            {ike === 'ikev1' && (
              <label className="toggle-row">
                <input type="checkbox" className="switch" checked={!!f.aggressive} onChange={(e) => set({ aggressive: e.target.checked })} />
                <span>
                  <span className="toggle-label">{t('Aggressive mode')}</span>
                  <span className="field-hint">{t('Needed when the FortiGate tunnel matches a peer ID (local ID below).')}</span>
                </span>
              </label>
            )}
            {ike !== 'l2tp' && (
              <Field label={t('Local ID')} hint={t('The peer ID the FortiGate expects; empty uses your user name.')}>
                <input className="input mono-sm" dir="ltr" value={f.localId ?? ''} spellCheck={false} onChange={(e) => set({ localId: e.target.value })} />
              </Field>
            )}
            <Field label={t('Networks through the VPN')} hint={t('Separated by commas, like 10.0.0.0/8, 192.168.10.0/24. Empty sends all traffic through the VPN.')}>
              <textarea className="input textarea mono-sm" dir="ltr" rows={2} spellCheck={false} value={routes} onChange={(e) => setRoutes(e.target.value)} />
            </Field>
            <div className="input-with-btn">
              <button type="button" className="btn" disabled={checking || !f.gateway.trim()} onClick={() => void runCheck()}>
                {checking ? <LoaderCircle size={16} className="spin" /> : <Gauge size={16} />} {t('Check gateway')}
              </button>
            </div>
          </>
        )}

        {check && <CheckResult check={check} trusted={f.trustedCert} onTrust={(pin) => set({ trustedCert: pin })} />}
        {error && <div className="notice warning">{error}</div>}
      </div>
    </Dialog>
  );
}

function CheckResult({ check, trusted, onTrust }: { check: GatewayCheck; trusted?: string; onTrust: (pin: string) => void }) {
  const t = useT();
  if (!check.ok) return <div className="notice warning">{t('The gateway did not answer: {error}', { error: check.error ?? t('No answer') })}</div>;
  const pinned = !!check.certPin && trusted === check.certPin;
  return (
    <div className="info-card">
      <ShieldCheck size={18} className={check.certTrusted || pinned || !check.certPin ? 'text-success' : 'text-warning'} />
      <div className="flex-1">
        <strong>
          {t('The gateway answered')} <span className="tabular">({check.ms} ms)</span>
        </strong>
        {check.fortigate === false && <p className="muted">{t('It does not look like a FortiGate SSL-VPN portal.')}</p>}
        {check.certSubject && (
          <p className="muted selectable mono-sm" dir="ltr">
            {check.certSubject}
          </p>
        )}
        {check.certPin && (
          <>
            <p className="muted">{check.certTrusted ? t('This computer trusts its certificate.') : pinned ? t('Its certificate is pinned in this profile.') : t('This computer does not trust its certificate (self-signed or private CA).')}</p>
            <p className="muted selectable mono-sm" dir="ltr">
              {check.certPin}
            </p>
            {!check.certTrusted && !pinned && (
              <button type="button" className="btn btn-xs" onClick={() => onTrust(check.certPin!)}>
                {t('Trust this certificate')}
              </button>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function initial(p: Profile | undefined): ProfileInput {
  if (!p) return { name: '', type: 'ssl', gateway: '', port: 443, username: '', savePassword: true, realm: '', trustedCert: '', clientCert: '', ike: 'ikev1', aggressive: true, localId: '', routes: [] };
  return {
    name: p.name,
    type: p.type,
    gateway: p.gateway,
    port: p.port || 443,
    username: p.username,
    savePassword: p.savePassword,
    realm: p.realm ?? '',
    trustedCert: p.trustedCert ?? '',
    clientCert: p.clientCert ?? '',
    ike: p.ike ?? 'ikev1',
    aggressive: p.aggressive ?? false,
    localId: p.localId ?? '',
    routes: p.routes ?? [],
  };
}
