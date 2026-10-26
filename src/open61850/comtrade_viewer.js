// Copyright 2026 Florent Carli
// SPDX-License-Identifier: Apache-2.0
//
// A COMTRADE viewer for a browser page, without any library: the .cfg and the .dat read (C37.111 1991, 1999 and
// 2013; ASCII, BINARY, BINARY32 and FLOAT32), the currents, the voltages and the other analog channels drawn in a
// panel each, the digital channels that are on or change under them, on a time axis from the trigger; a drag
// zooms in, a double click or Whole record shows it whole, a click holds the cursor (the arrow keys then move it by
// a sample, shift by a cycle), and at the cursor each channel's value, its RMS and its angle over the cycle ending
// there, the digital channels on there named in colour. A file of several streams (each analog channel's ccbm
// field, as a merging unit's svID) shows one at a time, the one with the largest current first. With the three
// phase currents and voltages, the six impedance loops on an R-X diagram, as a distance protection computes them,
// on the settings the page gives (k0, the line, the zones; none: k0 = 0). The page gives it a box:
//
//     const viewer = ComtradeViewer.create(document.getElementById("box"));
//     viewer.show(ComtradeViewer.parse(cfgText, datArrayBuffer), {name: "shot-12"});
//
// Python serves it (open61850.comtrade.viewer_script()) inside the page, so that a page stays one file. Its colours
// are the page's CSS variables, each with a fallback: --phase-a, --phase-b, --phase-c, --ink, --muted (or --mute),
// --grid (or --line), --critical (or --bad), --series (or --accent), --band.
"use strict";
const ComtradeViewer = (() => {
  const nf = (v, d = 0) => v === undefined || v === null || Number.isNaN(v) ? "-"
    : v.toLocaleString("en", {maximumFractionDigits: d, minimumFractionDigits: d});
  const esc = s => String(s).replace(/[&<>"]/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[c]));
  const css = (...names) => {
    const style = getComputedStyle(document.documentElement);
    for (const name of names) {
      if (!name.startsWith("--")) return name;  // the fallback
      const v = style.getPropertyValue(name).trim();
      if (v) return v;
    }
    return "#888";
  };

  // COMTRADE 1991, 1999 and 2013 (IEEE C37.111): the .cfg's text, the .dat in ASCII, BINARY, BINARY32 or FLOAT32.
  function parse(cfgText, datBuffer) {
    const lines = cfgText.split(/\r?\n/).map(l => l.trim());
    let at = 0;
    const next = () => { if (at >= lines.length) throw new Error("the .cfg ends too early"); return lines[at++].split(",").map(x => x.trim()); };
    const [station = "", device = "", rev = "1991"] = next();
    const counts = next();
    const na = parseInt(counts[1], 10), nd = parseInt(counts[2], 10);
    if (!(na >= 0 && nd >= 0)) throw new Error("not a COMTRADE .cfg (channel counts)");
    const analog = [], digital = [];
    for (let k = 0; k < na; k++) {
      const f = next();
      analog.push({id: f[1], ph: f[2], ccbm: f[3] || "", unit: f[4], a: parseFloat(f[5]) || 0, b: parseFloat(f[6]) || 0, ps: f[12] || ""});
    }
    for (let k = 0; k < nd; k++) {
      const f = next();
      digital.push({id: f[1], ph: f.length > 3 ? f[2] : "", ccbm: f.length > 4 ? f[3] : ""});
    }
    const frequency = parseFloat(next()[0]) || 50;
    const nrates = parseInt(next()[0], 10) || 0;
    const rates = [];
    for (let k = 0; k < Math.max(nrates, 1); k++) { const f = next(); rates.push({rate: parseFloat(f[0]), end: parseInt(f[1], 10)}); }
    const start = next(), trigger = next();
    const format = (next()[0] || "ASCII").toUpperCase();
    const timemult = rev === "1991" ? 1 : parseFloat((lines[at++] || "1").split(",")[0]) || 1;
    if (rev === "2013") at++;  // time_code, local_code
    const tmq = rev === "2013" ? (lines[at++] || "").split(",")[0] : "";
    // a date: dd/mm/yyyy (mm/dd/yyyy in 1991), then hh:mm:ss.ssssss; seconds from 1970, the microseconds kept apart
    const when = ([date, time]) => {
      const [p, q, y] = date.split("/").map(Number), [h, mi, sec] = time.split(":");
      const [day, month] = rev === "1991" ? [q, p] : [p, q];
      return {ms: Date.UTC(y, month - 1, day, +h, +mi, Math.floor(+sec)), fraction: +sec - Math.floor(+sec), text: `${date} ${time}`};
    };
    const t0 = when(start), tt = when(trigger);
    const triggerOffset = (tt.ms - t0.ms) / 1000 + tt.fraction - t0.fraction;
    const words = Math.ceil(nd / 16);
    const size = {BINARY: 2, BINARY32: 4, FLOAT32: 4}[format];
    let count, stamps, raw, bits;
    if (format === "ASCII") {
      const rows = new TextDecoder("latin1").decode(datBuffer).split(/\r?\n/).filter(l => l.trim()).map(l => l.split(","));
      count = rows.length;
      stamps = new Float64Array(count); raw = analog.map(() => new Float64Array(count)); bits = digital.map(() => new Uint8Array(count));
      rows.forEach((f, n) => {
        stamps[n] = parseFloat(f[1]);
        analog.forEach((c, k) => { const v = f[2 + k].trim(); raw[k][n] = v === "" || v === "99999" ? NaN : parseFloat(v); });
        digital.forEach((c, k) => { bits[k][n] = +f[2 + na + k] ? 1 : 0; });
      });
    } else if (size) {
      const record = 8 + size * na + 2 * words, data = new DataView(datBuffer);
      count = Math.floor(datBuffer.byteLength / record);
      stamps = new Float64Array(count); raw = analog.map(() => new Float64Array(count)); bits = digital.map(() => new Uint8Array(count));
      for (let n = 0; n < count; n++) {
        const o = n * record;
        stamps[n] = data.getUint32(o + 4, true);
        for (let k = 0; k < na; k++) {
          const p = o + 8 + size * k;
          raw[k][n] = format === "FLOAT32" ? data.getFloat32(p, true)
            : format === "BINARY32" ? (data.getInt32(p, true) === -2147483648 ? NaN : data.getInt32(p, true))
            : (data.getInt16(p, true) === -32768 ? NaN : data.getInt16(p, true));
        }
        for (let k = 0; k < nd; k++) bits[k][n] = (data.getUint16(o + 8 + size * na + 2 * (k >> 4), true) >> (k & 15)) & 1;
      }
    } else throw new Error(`data format ${format} not read here`);
    // time: from the sample rates when the file gives them, else from each sample's stamp
    const time = new Float64Array(count);
    if (rates[0].rate > 0) {
      let n = 0, t = 0;
      for (const r of rates) for (; n < Math.min(r.end, count); n++) { time[n] = t; t += 1 / r.rate; }
      for (; n < count; n++) time[n] = t, t += 1 / rates[rates.length - 1].rate;
    } else for (let n = 0; n < count; n++) time[n] = (stamps[n] - stamps[0]) * timemult * 1e-6;
    const values = analog.map((c, k) => raw[k].map(x => c.a * x + c.b));
    for (let n = 0; n < count; n++) time[n] -= triggerOffset;  // 0 at the trigger
    return {station, device, rev, frequency, rates, format, tmq, start: t0.text, trigger: tt.text, count, time, analog, values, digital, bits,
            rate: rates[0].rate > 0 ? rates[0].rate : count > 1 ? (count - 1) / (time[count - 1] - time[0]) : frequency * 32};
  }

  // a channel's phase, 0 to 2, from its phase field or the end of its name; -1 for none
  function phaseOf(c) {
    const ph = (c.ph || "").toUpperCase(), id = (c.id || "").toUpperCase();
    for (const [k, re] of [[0, /^(A|L1|R)$/], [1, /^(B|L2|S)$/], [2, /^(C|L3|T)$/]]) if (re.test(ph)) return k;
    for (const [k, re] of [[0, /(A|L1)$/], [1, /(B|L2)$/], [2, /(C|L3)$/]]) if (re.test(id)) return k;
    return -1;
  }
  const kindOf = c => /^(k?A|A)$/i.test(c.unit) ? "A" : /^(k?V|V)$/i.test(c.unit) ? "V" : "";
  function colorOf(c) {
    const ph = (c.ph || c.id || "").toUpperCase();
    return /A$|^A|L1/.test(ph) ? css("--phase-a", "#2a78d6") : /B$|^B|L2/.test(ph) ? css("--phase-b", "#eb6834")
      : /C$|^C|L3/.test(ph) ? css("--phase-c", "#1baf7a") : css("--ink-2", "--muted", "--mute", "#687385");
  }
  // the streams of a file: its analog channels' ccbm, in their order ("" for a file of one)
  const streamsOf = r => [...new Set(r.analog.map(c => c.ccbm))];
  // the fundamental of every analog channel at every sample, over the cycle ending there (NaN before a full valid
  // cycle), computed once a channel is first shown
  function phasorsOf(r, k) {
    r.phasors ??= [];
    if (r.phasors[k]) return r.phasors[k];
    const N = Math.round(r.rate / r.frequency), g = Math.SQRT2 / N, v = r.values[k];
    const cos = new Float64Array(N), sin = new Float64Array(N);
    for (let j = 0; j < N; j++) { cos[j] = Math.cos(2 * Math.PI * j / N); sin[j] = Math.sin(2 * Math.PI * j / N); }
    const re = new Float64Array(r.count).fill(NaN), im = new Float64Array(r.count).fill(NaN);
    for (let n = N - 1; n < r.count; n++) {
      let a = 0, b = 0;
      for (let j = 0; j < N; j++) { const x = v[n - N + 1 + j]; a += x * cos[j]; b -= x * sin[j]; }
      re[n] = g * a; im[n] = g * b;  // NaN when a sample of the cycle is missing
    }
    return (r.phasors[k] = {re, im});
  }
  function niceStep(span, target) {
    const raw = span / Math.max(1, target), p = Math.pow(10, Math.floor(Math.log10(raw)));
    return [1, 2, 5, 10].map(m => m * p).find(s => s >= raw) || 10 * p;
  }

  // --- impedances: the six loops as a distance protection computes them, on the settings the page gives ---------
  const cx = (re, im = 0) => ({re, im});
  const cadd = (a, b) => cx(a.re + b.re, a.im + b.im), csub = (a, b) => cx(a.re - b.re, a.im - b.im);
  const cmul = (a, b) => cx(a.re * b.re - a.im * b.im, a.re * b.im + a.im * b.re);
  const cdiv = (a, b) => { const d = b.re * b.re + b.im * b.im; return cx((a.re * b.re + a.im * b.im) / d, (a.im * b.re - a.re * b.im) / d); };
  const cabs = a => Math.hypot(a.re, a.im);
  const LOOP_NAMES = ["AG", "BG", "CG", "AB", "BC", "CA"];
  const LOOP_PHASES = {AG: [0], BG: [1], CG: [2], AB: [0, 1], BC: [1, 2], CA: [2, 0]};
  // each loop's colour, its first phase's: the page's variable, else the viewer's own
  const PHASE_COLOR = {"--phase-a": "#2a78d6", "--phase-b": "#eb6834", "--phase-c": "#1baf7a"};
  const LOOP_VAR = {AG: "--phase-a", BG: "--phase-b", CG: "--phase-c", AB: "--phase-a", BC: "--phase-b", CA: "--phase-c"};
  const LOOP_COLOR = Object.fromEntries(Object.entries(LOOP_VAR).map(([name, v]) => [name, `var(${v}, ${PHASE_COLOR[v]})`]));
  // the 120 degree operator and its square; a phase's negative sequence current over phase A's
  const A1 = cx(-0.5, Math.sqrt(3) / 2), A2 = cx(-0.5, -Math.sqrt(3) / 2), POWERS = [cx(1), A1, A2];
  // the settings the loops are drawn on: k0 = (Z0 - Z1) / 3 Z1, the line's Z1 (ohms, complex, or null), the zones
  // (open61850-protection's distance zones: name, x, r_pe, r_ph, tilt, shape, direction, load_r, load_angle), cot
  // of the line's angle, the least current a loop is drawn at, the direction's sector (degrees), the residual current
  // that polarizes an earth loop and the most it turns
  const NO_SETTINGS = {k0: cx(0), line: null, zones: [], cot: 0, minCurrent: 0, dirMin: -15, dirMax: 115, earthCurrent: Infinity, polarMax: 0};
  // a line's settings from its impedances (ohms): k0, its Z1, no zone
  const lineSettings = (r1, x1, r0, x0) => {
    const z1 = cx(r1, x1), z0 = cx(r0, x0);
    return {...NO_SETTINGS, k0: cdiv(csub(z0, z1), cmul(cx(3), z1)), line: z1, cot: x1 ? r1 / x1 : 0};
  };
  // the zones a loop impedance is in: the quadrilateral (or mho circle), the direction taken from the impedance
  // itself; the reactance line also turned by ``turn`` (radians, NaN for none) about the reach point
  function zonesOf(name, z, s, turn = NaN) {
    const earth = name.endsWith("G"), angle = Math.atan2(z.im, z.re) * 180 / Math.PI;
    const reverseAngle = angle > 0 ? angle - 180 : angle + 180;
    return s.zones.filter(zs => {
      const forward = zs.direction !== "reverse";
      const a = forward ? angle : reverseAngle;
      if (a < s.dirMin || a > s.dirMax) return false;
      const r = forward ? z.re : -z.re, x = forward ? z.im : -z.im;
      if (zs.load_r > 0 && r > zs.load_r && Math.abs(x) < r * Math.tan((zs.load_angle ?? 30) * Math.PI / 180)) return false;
      // a mho zone: its circle through the origin, the steady state (the relay's memory widens it while a fault lasts)
      if (zs.shape === "mho") return (zs.x * s.cot - r) * r + (zs.x - x) * x >= 0;
      const tilt = Math.tan((zs.tilt || 0) * Math.PI / 180), reach = earth ? zs.r_pe : zs.r_ph;
      if (!(x <= zs.x + r * tilt && Math.abs(r - x * s.cot) <= reach)) return false;
      if (!Number.isFinite(turn)) return true;
      const k = 1 - tilt * s.cot, point = cx(zs.x * s.cot / k, zs.x / k), t = (zs.tilt || 0) * Math.PI / 180;
      return cmul(cmul(csub(point, cx(r, x)), cx(Math.cos(turn), Math.sin(turn))), cx(Math.cos(t), -Math.sin(t))).im >= 0;
    }).map(zs => zs.name);
  }
  // the part of a polygon on the left of the ray at ``angle`` degrees from the origin (on its right with ``side`` -1)
  function clipRay(pts, angle, side) {
    const d = [Math.cos(angle * Math.PI / 180), Math.sin(angle * Math.PI / 180)];
    const at = p => side * (d[0] * p[1] - d[1] * p[0]), out = [];
    pts.forEach((p, i) => {
      const q = pts[(i + 1) % pts.length], a = at(p), b = at(q);
      if (a >= 0) out.push(p);
      if ((a >= 0) !== (b >= 0)) out.push([p[0] + a / (a - b) * (q[0] - p[0]), p[1] + a / (a - b) * (q[1] - p[1])]);
    });
    return out;
  }
  // a zone's quadrilateral and the corner its name goes by: closed ``bottom`` ohms below the R axis, and with ``cut``
  // by the direction's sector (reverse: its opposite), which is what closes it in the relay
  function zonePolygon(zs, s, bottom, cut) {
    const turn = ([r, x]) => [-r, -x];
    if (zs.shape === "mho") {
      // the circle through the origin and the reach point, the steady state; the direction does not close it
      const c = [zs.x * s.cot / 2, zs.x / 2], radius = Math.hypot(...c);
      const pts = Array.from({length: 72}, (_, k) => [c[0] + radius * Math.cos(k * Math.PI / 36), c[1] + radius * Math.sin(k * Math.PI / 36)]);
      const corner = [c[0] + radius, c[1]];
      return zs.direction === "reverse" ? {pts: pts.map(turn), corner: turn(corner)} : {pts, corner};
    }
    const t = Math.tan((zs.tilt || 0) * Math.PI / 180), k = 1 - t * s.cot;
    const reach = Math.max(zs.r_pe, zs.r_ph);
    let pts = [[(zs.x * s.cot - reach) / k], [(zs.x * s.cot + reach) / k]].map(([r]) => [r, zs.x + r * t]);
    pts.push([bottom * s.cot + reach, bottom], [bottom * s.cot - reach, bottom]);
    const corner = pts[1];
    if (cut) pts = clipRay(clipRay(pts, s.dirMin, 1), s.dirMax, -1);
    return zs.direction === "reverse" ? {pts: pts.map(turn), corner: turn(corner)} : {pts, corner};
  }
  // a zone's load area, which it leaves out: beyond load_r, within load_angle of the R axis, out to ``far`` ohms
  function loadArea(zs, far) {
    const t = Math.tan((zs.load_angle ?? 30) * Math.PI / 180), r0 = zs.load_r, r1 = Math.max(far, 2 * r0);
    const pts = [[r0, r0 * t], [r1, r1 * t], [r1, -r1 * t], [r0, -r0 * t]];
    return zs.direction === "reverse" ? pts.map(([r, x]) => [-r, -x]) : pts;
  }

  let styled = false;
  function style() {
    if (styled) return;
    styled = true;
    const s = document.createElement("style");
    s.textContent = `
.cv-bar { display:flex; flex-wrap:wrap; gap:8px 14px; align-items:center; margin:4px 0; font-size:12px; }
.cv-info { display:grid; grid-template-columns:max-content 1fr; gap:2px 12px; margin:4px 0 8px; font-size:12px; }
.cv-info dt { color:var(--muted, var(--mute, #687385)); } .cv-info dd { margin:0; }
.cv-body { display:grid; grid-template-columns:minmax(0, 1fr); gap:12px; }
@media (min-width:1100px) { .cv-body { grid-template-columns:minmax(0, 1fr) 440px; }
  .cv-side { position:sticky; top:8px; align-self:start; max-height:calc(100vh - 16px); overflow-y:auto; } }
.cv-side { font-size:12px; } .cv-side td, .cv-side th { padding-right:6px; text-align:left; }
.cv-side .num { text-align:right; font-variant-numeric:tabular-nums; white-space:nowrap; }
.cv-readout td:first-child:not(.cv-chips) { white-space:nowrap; }
.cv-wave { position:relative; touch-action:none; user-select:none; }
.cv-wave canvas { display:block; width:100%; cursor:crosshair; }
.cv-title { font-size:11px; margin:6px 0 0; display:flex; gap:10px; flex-wrap:wrap; }
.cv-hint { color:var(--muted, var(--mute, #687385)); }
.cv-swatch { display:inline-block; width:10px; height:3px; margin-right:4px; vertical-align:middle; border-radius:1px; }
.cv-chip { display:inline-block; padding:0 6px; margin:1px 2px; border-radius:8px; font-size:11px; border:1px solid currentColor; }
.cv-chip.on { color:var(--series, var(--accent, #2457c5)); } .cv-chip.trip { color:var(--critical, var(--bad, #c62828)); }
.cv-side table { width:100%; border-collapse:collapse; } .cv-side td.cv-chips { white-space:normal; }
.cv-side caption { text-align:left; padding-bottom:2px; }
.cv-rx-head { display:flex; flex-wrap:wrap; gap:6px 12px; align-items:center; margin-top:12px; }
.cv-rx-head h3 { margin:0; font-size:12px; text-transform:uppercase; letter-spacing:0.04em; }
.cv-rx svg { display:block; width:100%; max-width:440px; margin-top:4px; }
.cv-rx svg text { fill:var(--muted, var(--mute, #687385)); font-size:10px; font-variant-numeric:tabular-nums; }
.cv-rx svg text.cv-loop { fill:var(--ink, #1c2430); font-size:11px; }
.cv-loops label { display:inline-flex; gap:4px; align-items:center; white-space:nowrap; }
.cv-info details summary { cursor:pointer; } .cv-info pre { margin:2px 0 0; white-space:pre-wrap; font:inherit; }`;
    document.head.appendChild(s);
  }

  // A viewer in ``host``. Options: ``side``, an element put under the readout (a relay's impedances); ``onStream``,
  // called with the viewer once a record or another of its streams is shown; ``onDraw``, with the viewer and the
  // cursor's sample (or null) after each drawing; ``active``, whether the keys and the window's size are the
  // viewer's now (by default, while its box is shown); ``buttonClass``, the page's class for its buttons; ``hint``
  // false leaves out the line that says how to use it, which the page says itself; ``impedanceControls``, an
  // element put beside the impedances' title (a relay's choice of settings); ``settingsFor``, the settings of a
  // stream's loops, called as it is shown (by default the last given to show() or settings()).
  function create(host, options = {}) {
    style();
    host.innerHTML = `<div class="cv-bar"><label class="cv-stream" hidden>Stream <select></select></label>
        <label><input type="checkbox" class="cv-all"> Every digital channel</label>
        <button type="button" class="cv-reset ${esc(options.buttonClass || "")}">Whole record</button>
        <span class="cv-hint"${options.hint === false ? " hidden" : ""}>Hover to read the values, click to hold the cursor (the arrow keys move it by a sample, shift by a cycle), drag to zoom in, double click for the whole record.</span></div>
      <div class="cv-body"><div><dl class="cv-info"></dl><div class="cv-plots"></div></div><div class="cv-side"><table class="cv-readout"></table>
        <div class="cv-rx"><div class="cv-rx-head"><h3>Impedances</h3>
          <label>Zones <select class="cv-zones"><option value="direction">cut by the direction</option><option value="closed">closed below the R axis</option></select></label></div>
          <div class="cv-rx-plot"></div><table class="cv-loops"></table></div></div></div>`;
    const $ = sel => host.querySelector(sel);
    if (options.impedanceControls) $(".cv-rx-head").appendChild(options.impedanceControls);
    if (options.side) $(".cv-side").appendChild(options.side);
    try { const v = localStorage.getItem("rx-zones"); if (v) $(".cv-zones").value = v; } catch (e) { /* no storage here */ }
    const RIGHT = 8;  // the plots' right margin; the left one holds the digital channels' names, 84 to 260 px
    let LEFT = 84;
    // a digital channel's name as drawn: a GOOSE member's without the LLN0$GO$ that every one has
    const label = id => id.replace("/LLN0$GO$", "/");
    const viewer = {rec: null, name: "", stream: "", zoom: {from: 0, to: 0, cursor: null, held: false}, channels: [], iIdx: [], vIdx: [], hasLoops: false,
                    rx: NO_SETTINGS, loops: {}};
    const shownLoops = new Set(LOOP_NAMES);
    let given = NO_SETTINGS;  // the settings last given
    const zoom = viewer.zoom;
    let drag = null;
    const active = () => viewer.rec && (options.active ? options.active() : host.offsetParent !== null);

    viewer.indexAt = t => {  // the sample at or just before t
      const time = viewer.rec.time;
      let lo = 0, hi = viewer.rec.count - 1;
      if (t <= time[0]) return 0;
      if (t >= time[hi]) return hi;
      while (hi - lo > 1) { const mid = (lo + hi) >> 1; if (time[mid] <= t) lo = mid; else hi = mid; }
      return lo;
    };
    // the fundamental of channel k over the cycle ending at sample n: {re, im}, RMS
    viewer.phasor = (k, n) => { const p = phasorsOf(viewer.rec, k); return {re: p.re[n], im: p.im[n]}; };
    const fmtMs = t => `${nf(t * 1000, Math.abs(zoom.to - zoom.from) < 0.05 ? 2 : 1)} ms`;
    // a channel's name without its stream's, which the selector says (CCV_DEP4_MU01 Ia: Ia)
    const short = c => c.ccbm && c.id.startsWith(c.ccbm) && c.id.length > c.ccbm.length ? c.id.slice(c.ccbm.length).trim() : c.id;

    // the stream shown: its analog channels, its phase currents and voltages (each -1 when it has none)
    function choose(stream) {
      const r = viewer.rec;
      viewer.stream = stream;
      viewer.channels = r.analog.map((c, k) => k).filter(k => r.analog[k].ccbm === stream);
      const find = unit => [0, 1, 2].map(p => viewer.channels.find(k => kindOf(r.analog[k]) === unit && phaseOf(r.analog[k]) === p) ?? -1);
      viewer.iIdx = find("A"); viewer.vIdx = find("V");
      viewer.hasLoops = !viewer.iIdx.includes(-1) && !viewer.vIdx.includes(-1);
      computeLoops(options.settingsFor ? options.settingsFor(stream) || NO_SETTINGS : given);
      if (options.onStream) options.onStream(viewer);
    }
    // every loop's impedance and current at every sample, for the trajectories
    function computeLoops(s) {
      const rec = viewer.rec, at = (k, n) => { const p = viewer.phasor(k, n); return cx(p.re, p.im); };
      viewer.rx = s;
      viewer.loops = {};
      if (!viewer.hasLoops) return;
      for (const name of LOOP_NAMES) {
        const r = new Float64Array(rec.count).fill(NaN), x = new Float64Array(rec.count).fill(NaN), i = new Float64Array(rec.count).fill(NaN);
        const turn = new Float64Array(rec.count).fill(NaN);  // the loop's reactance line turn, radians
        const ph = LOOP_PHASES[name];
        for (let n = 0; n < rec.count; n++) {
          const I = viewer.iIdx.map(k => at(k, n)), V = viewer.vIdx.map(k => at(k, n));
          let current, volt;
          if (ph.length === 1) {
            const residual = cadd(cadd(I[0], I[1]), I[2]);
            current = cadd(I[ph[0]], cmul(s.k0, residual));
            volt = V[ph[0]];
            if (cabs(residual) >= s.earthCurrent) {  // the residual current polarizes it, clockwise only
              const p = cmul(current, cx(residual.re, -residual.im));
              turn[n] = Math.min(Math.max(Math.atan2(p.im, p.re), 0), s.polarMax);
            }
          } else {
            current = csub(I[ph[0]], I[ph[1]]);
            volt = csub(V[ph[0]], V[ph[1]]);
            // the pair's negative sequence current polarizes it, when above a tenth of the positive sequence's
            const i2 = cadd(cadd(I[0], cmul(A2, I[1])), cmul(A1, I[2])), i1 = cadd(cadd(I[0], cmul(A1, I[1])), cmul(A2, I[2]));
            if (cabs(i2) >= 0.1 * cabs(i1)) {
              const pair = cmul(csub(POWERS[ph[0]], POWERS[ph[1]]), i2), p = cmul(current, cx(pair.re, -pair.im));
              turn[n] = Math.min(Math.max(Math.atan2(p.im, p.re), 0), s.polarMax);
            }
          }
          const z = cdiv(volt, current);
          r[n] = z.re; x[n] = z.im; i[n] = cabs(current);
        }
        viewer.loops[name] = {r, x, i, turn};
      }
    }
    // the loops drawn on other settings (a relay's bay chosen)
    viewer.settings = s => { given = s || NO_SETTINGS; if (viewer.rec) { computeLoops(given); viewer.draw(); } };

    viewer.show = (r, {name = "", stream = null, info = [], settings = given} = {}) => {
      viewer.rec = r; viewer.name = name; given = settings || NO_SETTINGS;
      const streams = streamsOf(r);
      // by default the stream that carries the largest current: a fault's
      const peak = s => Math.max(0, ...r.analog.map((c, k) => k).filter(k => r.analog[k].ccbm === s && kindOf(r.analog[k]) === "A")
        .map(k => r.values[k].reduce((m, v) => Number.isNaN(v) ? m : Math.max(m, Math.abs(v)), 0)));
      const chosen = streams.includes(stream) ? stream : streams.reduce((a, b) => peak(b) > peak(a) ? b : a, streams[0] ?? "");
      $(".cv-stream").hidden = streams.length < 2;
      $(".cv-stream select").innerHTML = streams.map(s => `<option${s === chosen ? " selected" : ""}>${esc(s)}</option>`).join("");
      const quality = r.tmq === "" ? "" : r.tmq === "0" ? "locked to UTC" : `time quality ${r.tmq}`;
      $(".cv-info").innerHTML = [
        ["Station, device", esc(`${r.station}, ${r.device} (COMTRADE ${r.rev}, ${r.format})`)],
        ["First sample", esc(r.start)], ["Trigger", esc(`${r.trigger}${quality ? `, ${quality}` : ""}`)],
        ["Samples", esc(`${nf(r.count)} at ${nf(r.rate)} Hz, ${nf(r.count / r.rate * 1000, 1)} ms, ${r.frequency} Hz network`)],
        ...(streams.length > 1 ? [["Streams", esc(`${streams.length}, ${r.analog.length} analog channels, ${r.digital.length} digital`)]] : []),
        ...info,
      ].map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("");
      zoom.from = r.time[0]; zoom.to = r.time[r.count - 1]; zoom.cursor = null; zoom.held = false;
      choose(chosen);
      viewer.draw();
    };
    viewer.clear = () => {
      viewer.rec = null;
      const plots = $(".cv-plots");
      plots.innerHTML = ""; delete plots.dataset.layout;  // the next record makes its canvases again
      for (const sel of [".cv-readout", ".cv-rx-plot", ".cv-loops"]) $(sel).innerHTML = "";
    };

    // the panels: currents, voltages, other analog channels of the stream shown, then the digital channels
    function panels() {
      const r = viewer.rec, kind = c => kindOf(c) === "A" ? "Currents" : kindOf(c) === "V" ? "Voltages" : "Other";
      const groups = ["Currents", "Voltages", "Other"].map(title => ({title, channels: viewer.channels.filter(k => kind(r.analog[k]) === title)}))
        .filter(g => g.channels.length);
      const all = $(".cv-all").checked;
      const dig = r.digital.map((c, k) => k).filter(k => all || r.bits[k].some(b => b !== r.bits[k][0]));
      return {groups, dig};
    }

    viewer.draw = () => {
      const rec = viewer.rec;
      if (!rec) return;
      const plots = $(".cv-plots");
      const {groups, dig} = panels();
      const ink = css("--ink-2", "--ink", "#1c2430"), grid = css("--grid", "--line", "#e9ecf1"), muted = css("--muted", "--mute", "#687385");
      const critical = css("--critical", "--bad", "#c62828"), series = css("--series", "--accent", "#2457c5");
      const width = plots.clientWidth || 800, dpr = window.devicePixelRatio || 1;
      const measure = document.createElement("canvas").getContext("2d");
      measure.font = "10px system-ui, sans-serif";
      LEFT = Math.round(Math.min(260, Math.max(84, 12 + Math.max(0, ...dig.map(k => measure.measureText(label(rec.digital[k].id)).width)))));
      const plotW = Math.max(50, width - LEFT - RIGHT);
      const x = t => LEFT + (t - zoom.from) / (zoom.to - zoom.from) * plotW;
      const specs = groups.map(g => ({...g, height: 150})).concat(dig.length ? [{title: "Digital", digital: dig, height: 16 * dig.length + 22}] : []);
      const layout = specs.map(s => s.title + s.height).join();
      if (plots.dataset.layout !== layout) {
        plots.innerHTML = specs.map((s, i) => `<div class="cv-title" data-i="${i}"></div><div class="cv-wave"><canvas data-i="${i}"></canvas></div>`).join("");
        plots.dataset.layout = layout;
        for (const c of plots.querySelectorAll("canvas")) attach(c);
      }
      const i0 = Math.max(0, viewer.indexAt(zoom.from) - 1), i1 = Math.min(rec.count - 1, viewer.indexAt(zoom.to) + 1);
      const tStep = niceStep(zoom.to - zoom.from, plotW / 90);
      const cursor = zoom.cursor === null ? null : Math.min(Math.max(zoom.cursor, 0), rec.count - 1);
      specs.forEach((s, i) => {
        const canvas = plots.querySelectorAll("canvas")[i], title = plots.querySelectorAll(".cv-title")[i];
        canvas.width = Math.round(width * dpr); canvas.height = Math.round(s.height * dpr); canvas.style.height = `${s.height}px`;
        const g = canvas.getContext("2d");
        g.setTransform(dpr, 0, 0, dpr, 0, 0);
        g.font = "10px system-ui, sans-serif";
        const top = 6, bottom = s.height - 16;
        // time grid, 0 at the trigger
        g.strokeStyle = grid; g.fillStyle = muted; g.lineWidth = 1; g.textAlign = "center";
        for (let t = Math.ceil(zoom.from / tStep) * tStep; t <= zoom.to; t += tStep) {
          const px = Math.round(x(t)) + 0.5;
          g.beginPath(); g.moveTo(px, top); g.lineTo(px, bottom); g.stroke();
          g.fillText(nf(Math.abs(t) < tStep / 1000 ? 0 : t * 1000, tStep < 0.001 ? 2 : tStep < 0.01 ? 1 : 0), px, s.height - 4);
        }
        g.textAlign = "left"; g.fillText("ms", 4, s.height - 4);
        if (s.digital) {
          title.innerHTML = `<b>Digital</b><span class="cv-hint">${dig.length} of ${rec.digital.length} channels${$(".cv-all").checked ? "" : " (those that change)"}</span>`;
          s.digital.forEach((k, row) => {
            const y = top + row * 16, id = rec.digital[k].id;
            let name = label(id);  // too long still: its end, where GOOSE members differ
            while (name.length > 2 && g.measureText(name).width > LEFT - 8) name = "…" + name.slice(2);
            const color = /^Tr|\.Op$|TRIP/.test(id) ? critical : series;
            // at the cursor, the name of a channel on in its bar's colour, the others muted
            g.fillStyle = cursor === null ? ink : rec.bits[k][cursor] ? color : muted;
            g.textAlign = "right"; g.fillText(name, LEFT - 4, y + 11);
            g.fillStyle = color;
            let startAt = null;
            for (let n = i0; n <= i1 + 1; n++) {
              const on = n <= i1 && rec.bits[k][n];
              if (on && startAt === null) startAt = n;
              if (!on && startAt !== null) {
                const a = Math.max(LEFT, x(rec.time[startAt])), b = Math.min(LEFT + plotW, x(rec.time[Math.min(n, rec.count - 1)]));
                g.fillRect(a, y + 3, Math.max(1, b - a), 10);
                startAt = null;
              }
            }
          });
        } else {
          let lo = Infinity, hi = -Infinity;
          for (const k of s.channels) for (let n = i0; n <= i1; n++) { const v = rec.values[k][n]; if (v < lo) lo = v; if (v > hi) hi = v; }
          if (!(hi > lo)) { lo = (lo === Infinity ? 0 : lo) - 1; hi = lo + 2; }
          const pad = (hi - lo) * 0.06; lo -= pad; hi += pad;
          const kilo = Math.max(Math.abs(lo), Math.abs(hi)) >= 10000;
          const y = v => top + (hi - v) / (hi - lo) * (bottom - top);
          const vStep = niceStep(hi - lo, (bottom - top) / 35);
          g.textAlign = "right"; g.strokeStyle = grid; g.fillStyle = muted;
          for (let v = Math.ceil(lo / vStep) * vStep; v <= hi; v += vStep) {
            const py = Math.round(y(v)) + 0.5;
            g.beginPath(); g.moveTo(LEFT, py); g.lineTo(LEFT + plotW, py); g.stroke();
            const shown = Math.abs(v) < vStep / 1000 ? 0 : kilo ? v / 1000 : v;
            g.fillText(nf(shown, kilo && vStep < 1000 ? 1 : vStep < 1 ? 2 : 0), LEFT - 4, py + 3);
          }
          const unit = rec.analog[s.channels[0]].unit;
          title.innerHTML = `<b>${esc(s.title)}</b><span class="cv-hint">${kilo ? "k" : ""}${esc(unit)}</span>` + s.channels.map(k =>
            `<span><span class="cv-swatch" style="background:${colorOf(rec.analog[k])}"></span>${esc(short(rec.analog[k]))}</span>`).join("");
          g.save(); g.beginPath(); g.rect(LEFT, top, plotW, bottom - top); g.clip();
          s.channels.forEach(k => {
            const v = rec.values[k];
            g.strokeStyle = colorOf(rec.analog[k]); g.lineWidth = 1.2; g.beginPath();
            let pen = false;
            if (i1 - i0 < plotW * 2) {
              for (let n = i0; n <= i1; n++) {
                if (Number.isNaN(v[n])) { pen = false; continue; }
                pen ? g.lineTo(x(rec.time[n]), y(v[n])) : g.moveTo(x(rec.time[n]), y(v[n])); pen = true;
              }
            } else {  // more samples than pixels: each column's minimum and maximum
              let n = i0;
              for (let px = 0; px < plotW; px++) {
                const tEnd = zoom.from + (px + 1) / plotW * (zoom.to - zoom.from);
                let mn = Infinity, mx = -Infinity;
                for (; n <= i1 && rec.time[n] <= tEnd; n++) { if (v[n] < mn) mn = v[n]; if (v[n] > mx) mx = v[n]; }
                if (mn === Infinity) continue;
                if (!pen) { g.moveTo(LEFT + px, y(mn)); pen = true; } else g.lineTo(LEFT + px, y(mn));
                g.lineTo(LEFT + px, y(mx));
              }
            }
            g.stroke();
          });
          g.restore();
        }
        // the trigger, the zoom being drawn, the cursor
        g.strokeStyle = critical; g.setLineDash([4, 3]);
        if (0 >= zoom.from && 0 <= zoom.to) { g.beginPath(); g.moveTo(Math.round(x(0)) + 0.5, top); g.lineTo(Math.round(x(0)) + 0.5, bottom); g.stroke(); }
        g.setLineDash([]);
        if (drag && Math.abs(drag.x1 - drag.x0) > 4) {
          g.fillStyle = css("--band", "rgba(36, 87, 197, 0.12)");
          g.fillRect(Math.min(drag.x0, drag.x1), top, Math.abs(drag.x1 - drag.x0), bottom - top);
        }
        if (cursor !== null) {
          const px = Math.round(x(rec.time[cursor])) + 0.5;
          g.strokeStyle = css("--ink", "#1c2430"); g.lineWidth = zoom.held ? 1.5 : 1;
          g.beginPath(); g.moveTo(px, top); g.lineTo(px, bottom); g.stroke();
        }
      });
      readout(cursor);
      drawRx(cursor);
      if (options.onDraw) options.onDraw(viewer, cursor);
      fit();
    };

    // beside the curves, the side holds in its scrolling box's height (less the sticky margins): the R-X diagram
    // gives up what the rest needs, down to 300 px, so that the side does not scroll on its own
    function fit() {
      const side = $(".cv-side"), svg = $(".cv-rx-plot svg");
      side.style.maxHeight = "";
      if (svg) svg.style.width = svg.style.height = "";
      if (getComputedStyle(side).position !== "sticky") return;
      let box = side.parentElement;
      while (box && !/(auto|scroll|overlay)/.test(getComputedStyle(box).overflowY)) box = box.parentElement;
      const room = (box ? box.clientHeight : window.innerHeight) - 16;
      side.style.maxHeight = `${room}px`;
      const over = side.scrollHeight - room;
      if (svg && over > 0) {
        const size = Math.max(300, svg.getBoundingClientRect().height - over);
        svg.style.width = svg.style.height = `${size}px`;
      }
    }

    // at the cursor: each channel of the stream, its value, its RMS and its angle from the first voltage (else
    // current), over the cycle ending there
    // with or without a cursor, the table keeps its rows: the impedances under it stay put
    function readout(n) {
      const rec = viewer.rec, table = $(".cv-readout");
      const refK = viewer.channels.find(k => kindOf(rec.analog[k]) === "V") ?? viewer.channels.find(k => kindOf(rec.analog[k]) === "A");
      const at = k => { const p = viewer.phasor(k, n); return Number.isNaN(p.re) ? null : {mag: Math.hypot(p.re, p.im), ang: Math.atan2(p.im, p.re)}; };
      const ref = refK === undefined || n === null ? null : at(refK);
      const rows = viewer.channels.map(k => {
        const c = rec.analog[k], p = n === null ? null : at(k), v = n === null ? NaN : rec.values[k][n];
        let ang = p && ref && p.mag > 1e-9 ? (p.ang - ref.ang) * 180 / Math.PI : undefined;
        if (ang !== undefined) ang = ((ang + 540) % 360) - 180;
        return `<tr><td><span class="cv-swatch" style="background:${colorOf(c)}"></span>${esc(short(c))}</td><td class="num">${n === null ? "-" : nf(v, 1)} ${esc(c.unit)}</td>`
          + `<td class="num">${p ? nf(p.mag, 1) : "-"} ${esc(c.unit)}</td><td class="num">${ang === undefined ? "-" : nf(ang, 1) + "°"}</td></tr>`;
      });
      table.innerHTML = `<caption>${n === null ? "Move over the curves to read the values." : `At ${esc(fmtMs(rec.time[n]))} from the trigger (sample ${nf(n)})`}</caption>`
        + `<tr><th>Channel</th><th class="num">Value</th><th class="num">RMS</th><th class="num">Angle</th></tr>`
        + rows.join("");
    }

    // the R-X diagram: the zones and the line, each loop's trajectory over the zoomed window where its current is
    // enough, its point at the cursor; under it each loop's impedance, current and zones there
    function drawRx(n) {
      const rec = viewer.rec, box = $(".cv-rx-plot"), table = $(".cv-loops"), s = viewer.rx;
      if (!viewer.hasLoops) {
        box.innerHTML = "";
        table.innerHTML = `<tr><td class="cv-hint">The loops need the stream's three phase currents and voltages.</td></tr>`;
        return;
      }
      // the view: the zones and the line, square (the same ohms per pixel on both axes)
      const reachX = Math.max(1, ...s.zones.map(z => z.x), s.line ? s.line.im : 1);
      // cut by the direction, closed far enough below that the sector's rays close it first
      const cut = $(".cv-zones").value === "direction" && s.dirMax > s.dirMin && s.dirMax - s.dirMin <= 180;
      const bottom = cut ? -10 * (reachX + Math.max(0, ...s.zones.map(z => Math.max(z.r_pe ?? 0, z.r_ph ?? 0)))) : -0.15 * reachX;
      const polys = s.zones.map(zs => ({zs, ...zonePolygon(zs, s, bottom, cut)}));
      const all = polys.flatMap(p => p.pts).concat([[0, 0]], s.line ? [[s.line.re, s.line.im]] : []);
      // without zones: the line, two and a half times its reach each way (a load's impedance, far out, clipped);
      // without a line either, the loops at the cursor where their current is enough
      if (!s.zones.length && s.line) {
        const reach = 2.5 * cabs(s.line);
        all.push([-reach * 0.6, -reach * 0.6], [reach, reach]);
      } else if (!s.zones.length) for (const name of LOOP_NAMES) {
        const L = viewer.loops[name];
        if (n !== null && L.i[n] > Math.max(s.minCurrent, 1) && Math.abs(L.x[n]) < 1e4) all.push([L.r[n], L.x[n]]);
      }
      let r0 = Math.min(...all.map(p => p[0])), r1 = Math.max(...all.map(p => p[0])), x0 = Math.min(...all.map(p => p[1])), x1 = Math.max(...all.map(p => p[1]));
      const span = Math.max(r1 - r0, x1 - x0, 1) * 1.25, rc = (r0 + r1) / 2, xc = (x0 + x1) / 2;
      r0 = rc - span / 2; x1 = xc + span / 2;
      const W = 340, px = r => (r - r0) / span * W, py = x => (x1 - x) / span * W;
      const grid = "var(--grid, var(--line, #e9ecf1))", muted = "var(--muted, var(--mute, #687385))", axis = "var(--axis, var(--line, #c9cfd9))";
      let svg = `<svg viewBox="0 0 ${W} ${W}" height="${W}" role="img" aria-label="R-X diagram"><defs><clipPath id="cv-rx-clip"><rect width="${W}" height="${W}"/></clipPath></defs>`;
      const step = niceStep(span, 6);
      for (let v = Math.ceil(r0 / step) * step; v <= r0 + span; v += step)
        svg += `<line x1="${px(v)}" x2="${px(v)}" y1="0" y2="${W}" stroke="${grid}"/><text x="${px(v) + 2}" y="${W - 3}">${nf(v, step < 1 ? 1 : 0)}</text>`;
      for (let v = Math.ceil((x1 - span) / step) * step; v <= x1; v += step)
        svg += `<line y1="${py(v)}" y2="${py(v)}" x1="0" x2="${W}" stroke="${grid}"/>` + (py(v) > 14 ? `<text x="2" y="${py(v) - 2}">${nf(v, step < 1 ? 1 : 0)}</text>` : "");
      svg += `<line x1="${px(0)}" x2="${px(0)}" y1="0" y2="${W}" stroke="${axis}"/><line y1="${py(0)}" y2="${py(0)}" x1="0" x2="${W}" stroke="${axis}"/>`;
      svg += `<text x="${W - 4}" y="${py(0) - 3}" text-anchor="end">R Ω</text><text x="${px(0) + 3}" y="10">X Ω</text>`;
      if (cut && s.zones.length) {
        // the direction's rays: forward, and their opposites where a zone is reverse
        const angles = [s.dirMin, s.dirMax].concat(s.zones.some(z => z.direction === "reverse") ? [s.dirMin + 180, s.dirMax + 180] : []);
        svg += `<g clip-path="url(#cv-rx-clip)">` + angles.map(a => {
          const far = 3 * span, e = [far * Math.cos(a * Math.PI / 180), far * Math.sin(a * Math.PI / 180)];
          return `<line x1="${px(0)}" y1="${py(0)}" x2="${px(e[0])}" y2="${py(e[1])}" stroke="${muted}" stroke-dasharray="6 4"/>`;
        }).join("") + `</g>`;
      }
      for (const {zs, pts, corner} of polys) {
        svg += `<polygon points="${pts.map(([r, x]) => `${px(r)},${py(x)}`).join(" ")}" fill="var(--band, rgba(36, 87, 197, 0.12))" stroke="${muted}" stroke-width="1"/>`;
        svg += `<text x="${px(corner[0]) + 3}" y="${py(corner[1]) + 10}">${esc(zs.name)}</text>`;
      }
      if (s.line) svg += `<line x1="${px(0)}" y1="${py(0)}" x2="${px(s.line.re)}" y2="${py(s.line.im)}" stroke="var(--ink-2, var(--ink, #1c2430))" stroke-dasharray="5 3"><title>the line</title></line>`;
      const i0 = viewer.indexAt(zoom.from), i1 = viewer.indexAt(zoom.to), every = Math.max(1, Math.floor((i1 - i0) / 1500));
      svg += `<g clip-path="url(#cv-rx-clip)">`;
      const areas = new Set();
      for (const zs of s.zones) {
        if (!(zs.load_r > 0)) continue;
        const pts = loadArea(zs, Math.abs(rc) + 2 * span).map(([r, x]) => `${px(r).toFixed(1)},${py(x).toFixed(1)}`).join(" ");
        if (areas.has(pts)) continue;
        areas.add(pts);
        svg += `<polygon points="${pts}" fill="none" stroke="${muted}" stroke-dasharray="2 3"><title>load area of ${esc(zs.name)}</title></polygon>`;
      }
      for (const name of LOOP_NAMES) {
        if (!shownLoops.has(name)) continue;
        const L = viewer.loops[name];
        let d = "", pen = false;
        for (let k = i0; k <= i1; k += every) {
          const ok = L.i[k] >= Math.max(s.minCurrent, 1e-6) && Number.isFinite(L.r[k]) && Math.abs(L.r[k] - rc) < 4 * span && Math.abs(L.x[k] - xc) < 4 * span;
          if (!ok) { pen = false; continue; }
          d += `${pen ? "L" : "M"}${px(L.r[k]).toFixed(1)},${py(L.x[k]).toFixed(1)}`; pen = true;
        }
        const dash = name.endsWith("G") ? "" : ` stroke-dasharray="4 3"`;
        if (d) svg += `<path d="${d}" fill="none" stroke="${LOOP_COLOR[name]}" stroke-width="1.2" opacity="0.8"${dash}/>`;
        if (n !== null && L.i[n] >= s.minCurrent && Number.isFinite(L.r[n]))
          svg += `<circle cx="${px(L.r[n])}" cy="${py(L.x[n])}" r="4" fill="${LOOP_COLOR[name]}" stroke="var(--surface, var(--card, #fff))"/>`
            + `<text class="cv-loop" x="${px(L.r[n]) + 6}" y="${py(L.x[n]) - 4}">${name}</text>`;
      }
      svg += `</g></svg>`;
      box.innerHTML = svg;
      const rows = LOOP_NAMES.map(name => {
        const L = viewer.loops[name], has = n !== null && Number.isFinite(L.r[n]);
        const z = has ? cx(L.r[n], L.x[n]) : null, low = has && L.i[n] < s.minCurrent;
        const zones = z && !low ? zonesOf(name, z, s, L.turn[n]) : [];
        return `<tr${low ? ` style="color:${muted}"` : ""}><td><label><input type="checkbox" data-loop="${name}" ${shownLoops.has(name) ? "checked" : ""}>`
          + `<span class="cv-swatch" style="background:${css(LOOP_VAR[name], PHASE_COLOR[LOOP_VAR[name]])}"></span>${name}</label></td>`
          + `<td class="num">${z ? nf(z.re, 2) : "-"}</td><td class="num">${z ? nf(z.im, 2) : "-"}</td>`
          + `<td class="num">${z ? `${nf(Math.atan2(z.im, z.re) * 180 / Math.PI, 1)}°` : "-"}</td>`
          + `<td class="num">${has ? nf(L.i[n], 0) : "-"}</td><td class="cv-chips">${low ? '<span class="cv-hint">I below min</span>' : zones.map(x => `<span class="cv-chip trip">${esc(x)}</span>`).join(" ")}</td></tr>`;
      });
      table.innerHTML = `<tr><th>Loop</th><th class="num">R Ω</th><th class="num">X Ω</th><th class="num">Angle</th><th class="num">I A</th><th>${s.zones.length ? "Zones" : ""}</th></tr>` + rows.join("");
    }

    function attach(canvas) {
      const timeAt = ev => {
        const box = canvas.getBoundingClientRect(), plotW = box.width - LEFT - RIGHT;
        return zoom.from + (ev.clientX - box.left - LEFT) / plotW * (zoom.to - zoom.from);
      };
      canvas.addEventListener("pointerdown", ev => {
        const box = canvas.getBoundingClientRect();
        drag = {x0: ev.clientX - box.left, x1: ev.clientX - box.left, t0: timeAt(ev)};
        canvas.setPointerCapture(ev.pointerId);
      });
      canvas.addEventListener("pointermove", ev => {
        if (!viewer.rec) return;
        if (drag) drag.x1 = ev.clientX - canvas.getBoundingClientRect().left;
        if (!zoom.held || drag) zoom.cursor = viewer.indexAt(timeAt(ev));
        viewer.draw();
      });
      canvas.addEventListener("pointerup", ev => {
        if (!drag) return;
        const rec = viewer.rec, t1 = timeAt(ev), moved = Math.abs(drag.x1 - drag.x0) > 4;
        if (moved) {
          const a = Math.min(drag.t0, t1), b = Math.max(drag.t0, t1);
          if (b - a > 2 / rec.rate) { zoom.from = Math.max(rec.time[0], a); zoom.to = Math.min(rec.time[rec.count - 1], b); }
        } else { zoom.held = !zoom.held; zoom.cursor = viewer.indexAt(t1); }
        drag = null;
        viewer.draw();
      });
      canvas.addEventListener("dblclick", () => { viewer.whole(); });
    }
    viewer.whole = () => { if (viewer.rec) { zoom.from = viewer.rec.time[0]; zoom.to = viewer.rec.time[viewer.rec.count - 1]; viewer.draw(); } };
    document.addEventListener("keydown", ev => {
      const rec = viewer.rec;
      if (!active() || !zoom.held || !["ArrowLeft", "ArrowRight"].includes(ev.key)) return;
      if (ev.target.closest && ev.target.closest("input, select, textarea")) return;
      ev.preventDefault();
      zoom.cursor = Math.min(rec.count - 1, Math.max(0, zoom.cursor + (ev.key === "ArrowRight" ? 1 : -1) * (ev.shiftKey ? Math.round(rec.rate / rec.frequency) : 1)));
      if (rec.time[zoom.cursor] < zoom.from || rec.time[zoom.cursor] > zoom.to) {
        const span = zoom.to - zoom.from;
        zoom.from = Math.max(rec.time[0], rec.time[zoom.cursor] - span / 2); zoom.to = zoom.from + span;
      }
      viewer.draw();
    });
    $(".cv-reset").addEventListener("click", viewer.whole);
    $(".cv-all").addEventListener("change", () => viewer.draw());
    $(".cv-stream select").addEventListener("change", ev => { choose(ev.target.value); zoom.cursor = null; viewer.draw(); });
    $(".cv-loops").addEventListener("change", ev => {
      const name = ev.target.dataset.loop;
      if (!name) return;
      if (ev.target.checked) shownLoops.add(name); else shownLoops.delete(name);
      viewer.draw();
    });
    $(".cv-zones").addEventListener("change", ev => {
      try { localStorage.setItem("rx-zones", ev.target.value); } catch (e) { /* not remembered */ }
      viewer.draw();
    });
    window.addEventListener("resize", () => { if (active()) viewer.draw(); });
    if (window.matchMedia) window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { if (viewer.rec) viewer.draw(); });
    return viewer;
  }

  // A record from a zip of its .cfg, .dat (and .hdr): the files read out of the archive by the browser's own
  // DecompressionStream (deflate) or as stored. Its .hdr's text as ``header``.
  async function fromZip(buffer) {
    const data = new DataView(buffer), files = {};
    let end = buffer.byteLength - 22;
    while (end >= 0 && data.getUint32(end, true) !== 0x06054b50) end--;  // the end of the central directory
    if (end < 0) throw new Error("not a zip");
    let at = data.getUint32(end + 16, true);
    for (let k = data.getUint16(end + 10, true); k > 0; k--) {
      const method = data.getUint16(at + 10, true), size = data.getUint32(at + 20, true);
      const nameLength = data.getUint16(at + 28, true), extra = data.getUint16(at + 30, true), comment = data.getUint16(at + 32, true);
      const local = data.getUint32(at + 42, true), name = new TextDecoder().decode(new Uint8Array(buffer, at + 46, nameLength));
      const start = local + 30 + data.getUint16(local + 26, true) + data.getUint16(local + 28, true);
      const packed = new Uint8Array(buffer, start, size);
      files[name.split("/").pop().toLowerCase().replace(/^.*\./, "")] = method === 0 ? packed.slice().buffer
        : await new Response(new Blob([packed]).stream().pipeThrough(new DecompressionStream("deflate-raw"))).arrayBuffer();
      at += 46 + nameLength + extra + comment;
    }
    if (!files.cfg || !files.dat) throw new Error("a zip without a .cfg and a .dat");
    const record = parse(new TextDecoder("latin1").decode(files.cfg), files.dat);
    record.header = files.hdr ? new TextDecoder().decode(files.hdr) : "";
    return record;
  }

  return {parse, fromZip, create, phaseOf, colorOf, lineSettings, NO_SETTINGS};
})();
