import { KeyRound, LoaderCircle, ShieldAlert, ShieldQuestion, Smartphone } from 'lucide-react';
import { useState } from 'react';
import type { Prompt, PromptKind } from '../../../../shared/protocol';
import { api } from '../../api/client';
import { attempt } from '../../app/commands';
import { useT } from '../../i18n';
import { useConnection } from '../../store/connection';
import { useProfiles } from '../../store/profiles';
import { Dialog, Field } from '../common/Dialog';

const TITLE: Record<PromptKind, string> = {
  password: 'Password for {name}',
  otp: 'Verification code for {name}',
  psk: 'Pre-shared key for {name}',
  cert: 'Untrusted certificate: {name}',
  admin: 'Administrator rights',
  text: '{name} asks',
};

const LABEL: Record<PromptKind, string> = {
  cert: 'Trust this certificate',
  password: 'VPN password',
  otp: 'Code from FortiToken, e-mail or SMS',
  psk: 'Pre-shared key',
  admin: 'Your computer password',
  text: 'Answer',
};

/** Whatever the VPN program asks while connecting (a FortiToken code, a password, a certificate to trust), as a dialog. */
export function PromptDialog() {
  const prompt = useConnection((s) => s.connection.prompt);
  if (!prompt) return null;
  // Keyed by id: a second question (a new code after a wrong one) starts with an empty field.
  return <PromptForm key={prompt.id} prompt={prompt} />;
}

function PromptForm({ prompt }: { prompt: Prompt }) {
  const t = useT();
  const profileId = useConnection((s) => s.connection.profileId);
  const name = useProfiles((s) => s.profiles.find((p) => p.id === profileId)?.name ?? 'FortiConnect');
  const [value, setValue] = useState('');
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const cert = prompt.kind === 'cert';
  const rememberable = prompt.kind === 'password' || prompt.kind === 'psk';

  const answer = async (v: string) => {
    setBusy(true);
    await attempt(() => api.answer(prompt.id, v, rememberable ? remember : undefined), 'Could not send the answer');
    setBusy(false);
  };
  // Closing the dialog means "not now": stop connecting instead of leaving the backend waiting forever.
  const cancel = () => (cert ? void answer('no') : void attempt(() => api.disconnect(), 'Could not disconnect'));
  const Icon = cert ? ShieldAlert : prompt.kind === 'otp' ? Smartphone : prompt.kind === 'admin' ? ShieldQuestion : KeyRound;

  return (
    <Dialog
      title={t(TITLE[prompt.kind], { name })}
      icon={<Icon size={18} className={cert ? 'text-warning' : 'text-accent'} />}
      width={480}
      onClose={cancel}
      onSubmit={cert ? undefined : () => value && void answer(value)}
      footer={
        cert ? (
          <>
            <button className="btn" disabled={busy} onClick={() => void answer('no')}>
              {t('Cancel')}
            </button>
            <button className="btn btn-primary" disabled={busy} onClick={() => void answer('yes')}>
              {busy && <LoaderCircle size={16} className="spin" />} {t('Trust and connect')}
            </button>
          </>
        ) : (
          <>
            <button className="btn" disabled={busy} onClick={cancel}>
              {t('Cancel')}
            </button>
            <button className="btn btn-primary" disabled={busy || !value} onClick={() => void answer(value)}>
              {busy && <LoaderCircle size={16} className="spin" />} {t('Continue')}
            </button>
          </>
        )
      }
    >
      <div className="form">
        {cert ? (
          <>
            <p>{t('The gateway’s certificate is not trusted by this computer. Trust it only if your administrator confirms this fingerprint.')}</p>
            <p className="muted" dir="ltr">
              {prompt.message}
            </p>
            {prompt.detail && (
              <p className="selectable mono-sm prompt-pin" dir="ltr">
                {prompt.detail}
              </p>
            )}
            <p className="muted">{t('FortiConnect remembers it for this profile.')}</p>
          </>
        ) : (
          <>
            {prompt.kind === 'admin' && <p className="muted">{t('Setting up the VPN needs administrator rights. FortiConnect passes your password to sudo and keeps it only in memory, for reconnecting, until it quits.')}</p>}
            <Field label={t(LABEL[prompt.kind])} hint={<span dir="ltr">{prompt.message}</span>}>
              <input
                className={`input${prompt.kind === 'otp' ? ' tabular prompt-code' : ''}`}
                type={prompt.kind === 'otp' || prompt.kind === 'text' ? 'text' : 'password'}
                inputMode={prompt.kind === 'otp' ? 'numeric' : undefined}
                autoComplete={prompt.kind === 'otp' ? 'one-time-code' : 'off'}
                dir="ltr"
                autoFocus
                value={value}
                onChange={(e) => setValue(e.target.value)}
              />
            </Field>
            {rememberable && (
              <label className="toggle-row">
                <input type="checkbox" className="switch" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
                <span>
                  <span className="toggle-label">{t('Remember')}</span>
                  <span className="field-hint">{t('Save it (encrypted) in this profile, so FortiConnect does not ask again.')}</span>
                </span>
              </label>
            )}
          </>
        )}
      </div>
    </Dialog>
  );
}
