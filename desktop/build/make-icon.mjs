// Renders the FortiConnect mark (same artwork as ui/public/favicon.svg and BrandMark in the UI: a shield with a lit
// keyhole on a navy tile) to icon.png, icon.ico, tray.png and tray-on.png (the tray icon while connected: a green keyhole), plus the connection badges (badge-*.png for the Windows taskbar,
// dock-*.png for the macOS Dock) without any image library, like Grabbit's: signed-distance shapes,
// 4x4 supersampling, a hand-written PNG encoder and an ICO that embeds PNGs.
import { mkdirSync, writeFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const mix = (a, b, t) => a.map((v, i) => v + (b[i] - v) * t);
const clamp01 = (t) => Math.max(0, Math.min(1, t));

const TILE_TOP = hex('#1f3b5c');
const TILE_BOTTOM = hex('#0a1626');
const SHIELD = hex('#dbe7f5');

function roundRect(x, y, x0, y0, x1, y1, r) {
  const cx = (x0 + x1) / 2;
  const cy = (y0 + y1) / 2;
  const qx = Math.abs(x - cx) - ((x1 - x0) / 2 - r);
  const qy = Math.abs(y - cy) - ((y1 - y0) / 2 - r);
  return Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - r;
}

function segment(x, y, ax, ay, bx, by, halfWidth) {
  const px = x - ax;
  const py = y - ay;
  const dx = bx - ax;
  const dy = by - ay;
  const h = clamp01((px * dx + py * dy) / (dx * dx + dy * dy));
  return Math.hypot(px - dx * h, py - dy * h) - halfWidth;
}

/** The shield's outline as a polygon: M16 6 L24 9 V15.5 C24 20.5 20.6 24.2 16 26 C11.4 24.2 8 20.5 8 15.5 V9 Z. */
function cubic(p0, p1, p2, p3, n) {
  const out = [];
  for (let i = 1; i <= n; i++) {
    const t = i / n;
    const u = 1 - t;
    out.push([0, 1].map((k) => u * u * u * p0[k] + 3 * u * u * t * p1[k] + 3 * u * t * t * p2[k] + t * t * t * p3[k]));
  }
  return out;
}
const SHIELD_PATH = [[16, 6], [24, 9], [24, 15.5], ...cubic([24, 15.5], [24, 20.5], [20.6, 24.2], [16, 26], 24), ...cubic([16, 26], [11.4, 24.2], [8, 20.5], [8, 15.5], 24), [8, 9]];

/** Signed distance to a closed polygon: negative inside. */
function polygon(x, y, pts) {
  let d = Infinity;
  let inside = false;
  for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
    const [ax, ay] = pts[j];
    const [bx, by] = pts[i];
    d = Math.min(d, segment(x, y, ax, ay, bx, by, 0));
    if (ay > y !== by > y && x < ((bx - ax) * (y - ay)) / (by - ay) + ax) inside = !inside;
  }
  return inside ? -d : d;
}

const shieldOutline = (x, y) => Math.abs(polygon(x, y, SHIELD_PATH)) - 1.1;
const keyhole = (x, y) => Math.min(Math.hypot(x - 16, y - 14.5) - 2.6, roundRect(x, y, 14.9, 15.5, 17.1, 20.5, 1));

/** Layers in the 32x32 artwork space: [distance fn, colour fn]. */
function layers(litA, litB) {
  const lit = (x, y) => mix(litA, litB, clamp01((x + y - 14) / 22));
  return [
    [(x, y) => roundRect(x, y, 0, 0, 32, 32, 7), (_x, y) => mix(TILE_TOP, TILE_BOTTOM, y / 32)],
    [shieldOutline, () => SHIELD],
    [keyhole, lit],
  ];
}

const NORMAL = layers(hex('#5eead4'), hex('#3b82f6'));
const CONNECTED = layers(hex('#86efac'), hex('#16a34a'));

/**
 * The connection badge: a dot (green with a tick when connected, amber while connecting, grey when not) centred at
 * (cx, cy) with radius r in the 32x32 artwork space, and a dark ring around it so it stands apart from what is under it.
 */
const BADGE = { on: hex('#22c55e'), busy: hex('#f59e0b'), off: hex('#8a919c') };
const WHITE = [255, 255, 255];
const RING = hex('#202020');

function badgeLayers(state, cx, cy, r, ring = 0) {
  const k = r / 13;
  const out = [];
  if (ring) out.push([(x, y) => Math.hypot(x - cx, y - cy) - (r + ring), () => RING]);
  out.push([(x, y) => Math.hypot(x - cx, y - cy) - r, () => BADGE[state]]);
  if (state === 'on') {
    const p = (dx, dy) => [cx + dx * k, cy + dy * k];
    const [ax, ay] = p(-6, 0.5);
    const [bx, by] = p(-1.5, 5);
    const [ex, ey] = p(6.5, -4.5);
    out.push([(x, y) => Math.min(segment(x, y, ax, ay, bx, by, 2 * k), segment(x, y, bx, by, ex, ey, 2 * k)), () => WHITE]);
  }
  return out;
}

/** Taskbar overlay: the badge alone, filling its square (Windows draws it over the icon's corner). */
const overlay = (state) => badgeLayers(state, 16, 16, 13.5, 2.5);
/** macOS Dock: the app icon with the badge in its lower corner, since the Dock has no overlay of its own. */
const docked = (state) => [...NORMAL, ...badgeLayers(state, 24.5, 24.5, 6.2, 1.3)];

function render(size, art) {
  const px = Buffer.alloc(size * size * 4);
  const S = 4;
  for (let j = 0; j < size; j++) {
    for (let i = 0; i < size; i++) {
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 0;
      for (let sj = 0; sj < S; sj++) {
        for (let si = 0; si < S; si++) {
          const x = ((i + (si + 0.5) / S) / size) * 32;
          const y = ((j + (sj + 0.5) / S) / size) * 32;
          let c = null;
          for (const [dist, colour] of art) if (dist(x, y) <= 0) c = colour(x, y);
          if (c) {
            r += c[0];
            g += c[1];
            b += c[2];
            a += 1;
          }
        }
      }
      const o = (j * size + i) * 4;
      if (a > 0) {
        px[o] = Math.round(r / a);
        px[o + 1] = Math.round(g / a);
        px[o + 2] = Math.round(b / a);
        px[o + 3] = Math.round((a / (S * S)) * 255);
      }
    }
  }
  return px;
}

const CRC = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const v of buf) c = CRC[(c ^ v) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size, art = NORMAL) {
  const rgba = render(size, art);
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

function ico(sizes) {
  const images = sizes.map((s) => ({ s, data: png(s) }));
  const header = Buffer.alloc(6 + images.length * 16);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = header.length;
  images.forEach(({ s, data }, i) => {
    const e = 6 + i * 16;
    header[e] = s >= 256 ? 0 : s;
    header[e + 1] = s >= 256 ? 0 : s;
    header.writeUInt16LE(1, e + 4); // planes
    header.writeUInt16LE(32, e + 6); // bpp
    header.writeUInt32LE(data.length, e + 8);
    header.writeUInt32LE(offset, e + 12);
    offset += data.length;
  });
  return Buffer.concat([header, ...images.map((i) => i.data)]);
}

mkdirSync(here, { recursive: true });
writeFileSync(join(here, 'icon.png'), png(512));
writeFileSync(join(here, 'tray.png'), png(32));
writeFileSync(join(here, 'tray-on.png'), png(32, CONNECTED));
writeFileSync(join(here, 'icon.ico'), ico([16, 24, 32, 48, 64, 128, 256]));
// Connection badges: 16 px overlays with @2x copies (Electron picks the sharper one on high-DPI screens), and Dock icons.
for (const state of ['on', 'busy', 'off']) {
  writeFileSync(join(here, `badge-${state}.png`), png(16, overlay(state)));
  writeFileSync(join(here, `badge-${state}@2x.png`), png(32, overlay(state)));
  writeFileSync(join(here, `dock-${state}.png`), png(512, docked(state)));
}
console.log('icons written to', here);
