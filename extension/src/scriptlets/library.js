// NullRoute scriptlets — run in the page's MAIN world at document_start.
//
// Each function neutralises one specific behaviour (an anti-adblock probe, an
// ad-config object, a popunder) instead of blocking a whole script, which is
// what breaks sites when tracking is bundled into first-party code.
//
// Semantics follow uBlock Origin's scriptlets of the same name so existing
// filter lists work unchanged. Arguments come from filter lists and are only
// ever used as property paths or patterns — never evaluated as code.
//
// This file is concatenated with generated data by scripts/build.mjs; it
// defines __nullrouteScriptlets(data) and nothing else globally.

/* eslint-disable no-new-func */
function __nullrouteScriptlets(DATA) {
  'use strict';
  // Capture natives before any page script can tamper with them.
  const defineProperty = Object.defineProperty;
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const fnToString = Function.prototype.toString;
  const ReflectApply = Reflect.apply;
  const RegExpCtor = RegExp;
  const magic = 'nullroute-' + Math.random().toString(36).slice(2);

  // Hide our intentional ReferenceErrors from the page's error handlers/console.
  try {
    window.addEventListener('error', (e) => {
      if (String(e.message || '').includes(magic)) e.preventDefault();
    }, true);
  } catch { /* ignore */ }

  function patternToRegex(pattern, flags) {
    if (pattern === '' || pattern === undefined) return /^/;
    const m = /^\/(.+)\/([gimsuy]*)$/.exec(pattern);
    if (m) {
      try { return new RegExpCtor(m[1], m[2] || flags); } catch { return null; }
    }
    return new RegExpCtor(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), flags);
  }

  /** "!foo" means "does not match foo". Returns a predicate or null if invalid. */
  function needleTester(raw) {
    let not = false;
    let pattern = raw || '';
    if (pattern.startsWith('!')) { not = true; pattern = pattern.slice(1); }
    const re = patternToRegex(pattern);
    if (!re) return null;
    return (s) => re.test(s) !== not;
  }

  function stringify(fn) {
    if (typeof fn === 'function') {
      try { return ReflectApply(fnToString, fn, []); } catch { return ''; }
    }
    return String(fn);
  }

  /**
   * Walks "a.b.c" from window. When an intermediate object doesn't exist yet,
   * traps its assignment so the trap is installed as soon as the page creates it.
   */
  function onChain(chain, install) {
    const walk = (owner, path) => {
      const pos = path.indexOf('.');
      if (pos === -1) { install(owner, path); return; }
      const prop = path.slice(0, pos);
      const rest = path.slice(pos + 1);
      let value = owner[prop];
      if (value instanceof Object) { walk(value, rest); return; }
      const desc = getOwnPropertyDescriptor(owner, prop);
      if (desc && desc.set !== undefined) return; // already trapped by someone
      try {
        defineProperty(owner, prop, {
          configurable: true,
          get() { return value; },
          set(v) { value = v; if (v instanceof Object) walk(v, rest); },
        });
      } catch { /* non-configurable; give up quietly */ }
    };
    walk(window, chain);
  }

  const abort = () => { throw new ReferenceError(magic); };

  // ---------------------------------------------------------------- scriptlets
  const S = {
    'abort-on-property-read'(chain) {
      if (!chain) return;
      onChain(chain, (owner, prop) => {
        const desc = getOwnPropertyDescriptor(owner, prop);
        if (desc && desc.get === abort) return;
        defineProperty(owner, prop, { configurable: true, get: abort, set() {} });
      });
    },

    'abort-on-property-write'(chain) {
      if (!chain) return;
      onChain(chain, (owner, prop) => {
        try { delete owner[prop]; } catch { /* ignore */ }
        defineProperty(owner, prop, { configurable: true, set: abort });
      });
    },

    'abort-current-script'(chain, needle = '') {
      if (!chain) return;
      const matches = needleTester(needle);
      if (!matches) return;
      const ourScript = document.currentScript;
      const validate = () => {
        const e = document.currentScript;
        if (!(e instanceof HTMLScriptElement) || e === ourScript) return;
        const text = e.src || e.textContent || '';
        if (needle !== '' && !matches(text)) return;
        abort();
      };
      onChain(chain, (owner, prop) => {
        const desc = getOwnPropertyDescriptor(owner, prop);
        let value = owner[prop];
        const getter = desc && desc.get;
        const setter = desc && desc.set;
        try {
          defineProperty(owner, prop, {
            configurable: true,
            get() { validate(); return getter ? ReflectApply(getter, this, []) : value; },
            set(v) { validate(); if (setter) ReflectApply(setter, this, [v]); else value = v; },
          });
        } catch { /* ignore */ }
      });
    },

    'set-constant'(chain, raw) {
      if (!chain) return;
      const constants = {
        undefined: undefined, false: false, true: true, null: null,
        '': '', emptyStr: '', noopFunc: function () {}, trueFunc: () => true, falseFunc: () => false,
        emptyArr: [], '[]': [], emptyObj: {}, '{}': {}, '-1': -1, yes: 'yes', no: 'no',
      };
      let value;
      if (Object.prototype.hasOwnProperty.call(constants, raw)) {
        value = constants[raw];
      } else if (/^\d+$/.test(raw) && Number(raw) <= 0x7fff) {
        value = Number(raw);
      } else {
        return; // unknown value: refuse rather than guess
      }
      onChain(chain, (owner, prop) => {
        try {
          defineProperty(owner, prop, {
            configurable: false,
            get() { return value; },
            set() { /* ignore page writes */ },
          });
        } catch { /* ignore */ }
      });
    },

    'addEventListener-defuser'(type = '', pattern = '') {
      const reType = patternToRegex(type);
      const rePattern = patternToRegex(pattern);
      if (!reType || !rePattern) return;
      const proto = EventTarget.prototype;
      proto.addEventListener = new Proxy(proto.addEventListener, {
        apply(target, thisArg, args) {
          const [evType, handler] = args;
          if (reType.test(String(evType)) && rePattern.test(stringify(handler))) return undefined;
          return ReflectApply(target, thisArg, args);
        },
      });
    },

    'no-setTimeout-if'(needle = '', delay = '') {
      return wrapTimer('setTimeout', needle, delay);
    },

    'no-setInterval-if'(needle = '', delay = '') {
      return wrapTimer('setInterval', needle, delay);
    },

    'no-window-open-if'(pattern = '') {
      const matches = needleTester(pattern);
      if (!matches) return;
      const decoy = () => new Proxy({ closed: false, opener: window }, {
        get(t, p) { return p in t ? t[p] : function () {}; },
        set() { return true; },
      });
      window.open = new Proxy(window.open, {
        apply(target, thisArg, args) {
          if (matches(String(args[0] ?? ''))) return decoy();
          return ReflectApply(target, thisArg, args);
        },
      });
    },

    'json-prune'(rawPrune = '', rawNeedles = '') {
      const prunePaths = rawPrune.split(/ +/).filter(Boolean);
      const needlePaths = rawNeedles.split(/ +/).filter(Boolean);
      if (!prunePaths.length) return;
      const prune = (obj) => {
        if (!obj || typeof obj !== 'object') return obj;
        if (needlePaths.length && !needlePaths.every((p) => hasPath(obj, p))) return obj;
        for (const p of prunePaths) deletePath(obj, p.split('.'));
        return obj;
      };
      const origParse = JSON.parse;
      JSON.parse = new Proxy(origParse, {
        apply(target, thisArg, args) { return prune(ReflectApply(target, thisArg, args)); },
      });
      const origJson = Response.prototype.json;
      Response.prototype.json = new Proxy(origJson, {
        apply(target, thisArg, args) { return ReflectApply(target, thisArg, args).then(prune); },
      });
    },
  };

  function wrapTimer(name, needle, delay) {
    const matches = needleTester(needle);
    if (!matches) return;
    let delayNot = false;
    let d = String(delay || '');
    if (d.startsWith('!')) { delayNot = true; d = d.slice(1); }
    const wantDelay = d === '' ? null : Number(d);
    window[name] = new Proxy(window[name], {
      apply(target, thisArg, args) {
        const code = stringify(args[0]);
        const ms = Number(args[1]) || 0;
        const delayOk = wantDelay === null || ((ms === wantDelay) !== delayNot);
        if (matches(code) && delayOk) args[0] = function () {};
        return ReflectApply(target, thisArg, args);
      },
    });
  }

  // "a.b" / "a.[].b" (every array element or object value at that level)
  function hasPath(obj, path) {
    let cur = [obj];
    for (const key of path.split('.')) {
      const next = [];
      for (const o of cur) {
        if (!o || typeof o !== 'object') continue;
        if (key === '[]') next.push(...Object.values(o));
        else if (key in o) next.push(o[key]);
      }
      if (!next.length) return false;
      cur = next;
    }
    return true;
  }

  function deletePath(obj, keys) {
    if (!obj || typeof obj !== 'object') return;
    const [key, ...rest] = keys;
    if (key === '[]') { for (const v of Object.values(obj)) deletePath(v, rest); return; }
    if (!rest.length) { try { delete obj[key]; } catch { /* ignore */ } return; }
    deletePath(obj[key], rest);
  }

  // ---------------------------------------------------------------- dispatch
  const host = location.hostname;
  if (!host) return;
  const parts = host.split('.');
  const chain = parts.map((_, i) => parts.slice(i).join('.'));
  const disabled = new Set();
  for (const d of chain) for (const k of DATA.disabled[d] || []) disabled.add(k);
  if (disabled.has('*')) return;
  const seen = new Set();
  for (const d of chain) {
    for (const [name, ...args] of DATA.byDomain[d] || []) {
      const key = [name, ...args].join('|');
      if (seen.has(key) || disabled.has(key)) continue;
      seen.add(key);
      const fn = S[name];
      if (!fn) continue;
      try { fn(...args); } catch { /* one bad rule must not stop the rest */ }
    }
  }
}
