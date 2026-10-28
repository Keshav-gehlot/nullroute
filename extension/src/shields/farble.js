// Fingerprinting protection ("farbling"), injected into the page's MAIN world
// at document_start on sites where it is enabled.
//
// Canvas and audio fingerprints work because the same drawing produces the
// same pixels on the same machine. We perturb what scripts can *read back*
// (never what is drawn on screen) with low-amplitude noise:
//
//   * The seed is random per page load, so a fingerprint can't be linked
//     across visits or sites.
//   * Within a page the noise is a pure function of (seed, content), so
//     rendering the same canvas twice gives identical results. Per-call random
//     noise is easy to detect that way (IMC 2025), and detected noise gets
//     discarded by fingerprinting libraries.
//
// Wrapped functions are Proxies around the natives, so Function.prototype
// .toString still reports "[native code]".
(() => {
  'use strict';
  const seed = crypto.getRandomValues(new Uint32Array(1))[0];
  const ReflectApply = Reflect.apply;

  function mulberry32(a) {
    return () => {
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // FNV-1a over a bounded sample of the data: content-dependent, O(1) for big canvases.
  function hash(data, extra) {
    let h = (2166136261 ^ extra) >>> 0;
    const step = Math.max(1, Math.floor(data.length / 8192));
    for (let i = 0; i < data.length; i += step) {
      h ^= data[i] & 0xff;
      h = Math.imul(h, 16777619);
    }
    return h >>> 0;
  }

  /** Flips the low bit of one colour channel in ~1.5% of pixels. In place. */
  function farblePixels(data, width, height) {
    const pixels = data.length >> 2;
    if (!pixels) return;
    const rnd = mulberry32(seed ^ hash(data, (width << 16) ^ height));
    const count = Math.max(1, Math.floor(pixels * 0.015));
    for (let k = 0; k < count; k++) {
      const p = (Math.floor(rnd() * pixels) << 2) + Math.floor(rnd() * 3);
      data[p] ^= 1;
    }
  }

  function wrap(proto, name, handler) {
    const orig = proto?.[name];
    if (typeof orig !== 'function') return;
    Object.defineProperty(proto, name, {
      ...Object.getOwnPropertyDescriptor(proto, name),
      value: new Proxy(orig, { apply: (target, thisArg, args) => handler(target, thisArg, args) }),
    });
  }

  // ---- 2D canvas readback -----------------------------------------------------
  const C2D = window.CanvasRenderingContext2D?.prototype;
  const origGetImageData = C2D?.getImageData;
  const origPutImageData = C2D?.putImageData;
  const origDrawImage = C2D?.drawImage;
  const origGetContext = HTMLCanvasElement.prototype.getContext;
  const origCreateElement = Document.prototype.createElement;

  wrap(C2D, 'getImageData', (target, ctx, args) => {
    const img = ReflectApply(target, ctx, args);
    farblePixels(img.data, img.width, img.height);
    return img;
  });

  /** A farbled copy of the canvas, so the page's own canvas is never modified. */
  function farbledCopy(canvas) {
    const { width, height } = canvas;
    if (!width || !height || width * height > 16_000_000) return null;
    const copy = ReflectApply(origCreateElement, document, ['canvas']);
    copy.width = width;
    copy.height = height;
    const ctx = ReflectApply(origGetContext, copy, ['2d']);
    if (!ctx) return null;
    ReflectApply(origDrawImage, ctx, [canvas, 0, 0]);
    const img = ReflectApply(origGetImageData, ctx, [0, 0, width, height]);
    farblePixels(img.data, width, height);
    ReflectApply(origPutImageData, ctx, [img, 0, 0]);
    return copy;
  }

  wrap(HTMLCanvasElement.prototype, 'toDataURL', (target, canvas, args) => {
    const copy = farbledCopy(canvas);
    return ReflectApply(target, copy || canvas, args);
  });
  wrap(HTMLCanvasElement.prototype, 'toBlob', (target, canvas, args) => {
    const copy = farbledCopy(canvas);
    return ReflectApply(target, copy || canvas, args);
  });

  // ---- Web Audio ------------------------------------------------------------------
  const farbledBuffers = new WeakSet();
  wrap(window.AudioBuffer?.prototype, 'getChannelData', (target, buffer, args) => {
    const data = ReflectApply(target, buffer, args);
    if (!farbledBuffers.has(data)) {
      farbledBuffers.add(data);
      const rnd = mulberry32(seed ^ hash(new Uint8Array(data.buffer, data.byteOffset, Math.min(data.byteLength, 65536)), data.length));
      // Inaudible (~-140 dB) jitter on a sparse subset of samples.
      for (let i = 0; i < data.length; i += 97) data[i] += (rnd() - 0.5) * 2e-7;
    }
    return data;
  });

  // ---- Hardware concurrency ---------------------------------------------------------
  // Report a plausible core count between 2 and the real value, fixed per page.
  const navProto = Navigator.prototype;
  const hcDesc = Object.getOwnPropertyDescriptor(navProto, 'hardwareConcurrency');
  if (hcDesc?.get) {
    const real = ReflectApply(hcDesc.get, navigator, []);
    const fake = real > 2 ? 2 + Math.floor(mulberry32(seed)() * (real - 1)) : real;
    Object.defineProperty(navProto, 'hardwareConcurrency', {
      ...hcDesc,
      get: new Proxy(hcDesc.get, { apply: () => fake }),
    });
  }
})();
