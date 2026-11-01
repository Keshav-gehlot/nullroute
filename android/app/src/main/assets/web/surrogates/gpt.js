// NullRoute surrogate for Google Publisher Tag (gpt.js). Runs queued callbacks
// against a do-nothing googletag so page code and detectors keep working.
(function () {
  'use strict';
  var noop = function () {};
  function chain(obj, names) {
    names.forEach(function (n) { obj[n] = function () { return obj; }; });
    return obj;
  }
  var slots = [];
  function Slot(path, size, div) {
    this.path = path; this.div = div;
    chain(this, ['addService', 'clearCategoryExclusions', 'clearTargeting', 'defineSizeMapping', 'set',
      'setCategoryExclusion', 'setClickUrl', 'setCollapseEmptyDiv', 'setConfig', 'setForceSafeFrame',
      'setSafeFrameConfig', 'setTargeting', 'updateTargetingFromMap']);
  }
  Slot.prototype.getSlotElementId = function () { return this.div; };
  Slot.prototype.getAdUnitPath = function () { return this.path; };
  Slot.prototype.getTargeting = function () { return []; };
  Slot.prototype.getTargetingKeys = function () { return []; };
  Slot.prototype.getResponseInformation = function () { return null; };
  Slot.prototype.getSizes = function () { return []; };
  Slot.prototype.get = function () { return null; };

  var listeners = {};
  var pubads = chain({}, ['addEventListener', 'clear', 'clearCategoryExclusions', 'clearTagForChildDirectedTreatment',
    'clearTargeting', 'collapseEmptyDivs', 'defineOutOfPagePassback', 'definePassback', 'disableInitialLoad',
    'display', 'enableAsyncRendering', 'enableLazyLoad', 'enableSingleRequest', 'enableSyncRendering',
    'enableVideoAds', 'refresh', 'removeEventListener', 'set', 'setCategoryExclusion', 'setCentering',
    'setCookieOptions', 'setForceSafeFrame', 'setLocation', 'setPrivacySettings', 'setPublisherProvidedId',
    'setRequestNonPersonalizedAds', 'setSafeFrameConfig', 'setTagForChildDirectedTreatment', 'setTargeting',
    'setVideoContent', 'updateCorrelator']);
  pubads.addEventListener = function (type, cb) { (listeners[type] = listeners[type] || []).push(cb); return pubads; };
  pubads.getSlots = function () { return slots; };
  pubads.getTargeting = function () { return []; };
  pubads.getTargetingKeys = function () { return []; };
  pubads.isInitialLoadDisabled = function () { return false; };
  pubads.refresh = function () {
    // Tell listeners every slot rendered empty, as GPT does when no ad fills.
    (listeners.slotRenderEnded || []).forEach(function (cb) {
      slots.forEach(function (s) { try { cb({ slot: s, isEmpty: true, size: null }); } catch (e) {} });
    });
    return pubads;
  };

  var cmd = (window.googletag && window.googletag.cmd) || [];
  var gt = {
    apiReady: true,
    pubadsReady: true,
    cmd: { push: function () { for (var i = 0; i < arguments.length; i++) try { arguments[i](); } catch (e) {} return 0; } },
    pubads: function () { return pubads; },
    companionAds: function () { return chain({}, ['addEventListener', 'enableSyncLoading', 'setRefreshUnfilledSlots']); },
    content: function () { return chain({}, ['addEventListener', 'setContent']); },
    defineSlot: function (path, size, div) { var s = new Slot(path, size, div); slots.push(s); return s; },
    defineOutOfPageSlot: function (path, div) { var s = new Slot(path, [], div); slots.push(s); return s; },
    destroySlots: function () { slots.length = 0; return true; },
    disablePublisherConsole: noop,
    display: function () { pubads.refresh(); },
    enableServices: noop,
    getVersion: function () { return '0'; },
    openConsole: noop,
    setAdIframeTitle: noop,
    setConfig: noop,
    sizeMapping: function () {
      var m = { addSize: function () { return m; }, build: function () { return []; } };
      return m;
    },
    secureSignalProviders: { push: noop },
  };
  window.googletag = gt;
  for (var i = 0; i < cmd.length; i++) try { cmd[i](); } catch (e) {}
})();
