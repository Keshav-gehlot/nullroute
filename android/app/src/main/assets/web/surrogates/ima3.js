// NullRoute surrogate for the Google IMA SDK (imasdk.googleapis.com/js/sdkloader/ima3.js).
// Video players (JW Player, Video.js, Brightcove, ...) find a working SDK; every ad
// request fails with "no ads", which players handle by playing the content.
(function () {
  'use strict';
  var noop = function () {};
  function Emitter() { this.l = {}; }
  Emitter.prototype.addEventListener = function (types, cb) {
    [].concat(types).forEach(function (t) { (this.l[t] = this.l[t] || []).push(cb); }, this);
  };
  Emitter.prototype.removeEventListener = function (types, cb) {
    [].concat(types).forEach(function (t) { this.l[t] = (this.l[t] || []).filter(function (f) { return f !== cb; }); }, this);
  };
  Emitter.prototype.emit = function (type, ev) {
    (this.l[type] || []).slice().forEach(function (cb) { try { cb(ev); } catch (e) {} });
  };

  function AdError(code, message) { this.code = code; this.message = message; }
  AdError.prototype.getErrorCode = function () { return this.code; };
  AdError.prototype.getVastErrorCode = function () { return this.code; };
  AdError.prototype.getMessage = function () { return this.message; };
  AdError.prototype.getInnerError = function () { return null; };
  AdError.prototype.getType = function () { return 'adLoadError'; };
  AdError.prototype.toString = function () { return 'AdError ' + this.code + ': ' + this.message; };
  AdError.ErrorCode = { VAST_EMPTY_RESPONSE: 1009, UNKNOWN_ERROR: 900 };
  AdError.Type = { AD_LOAD: 'adLoadError', AD_PLAY: 'adPlayError' };

  function AdErrorEvent(error, userRequestContext) { this.error = error; this.ctx = userRequestContext; }
  AdErrorEvent.prototype.getError = function () { return this.error; };
  AdErrorEvent.prototype.getUserRequestContext = function () { return this.ctx || {}; };
  AdErrorEvent.Type = { AD_ERROR: 'adError' };

  function ImaSdkSettings() {}
  ['setAutoPlayAdBreaks', 'setCompanionBackfill', 'setCookiesEnabled', 'setDisableCustomPlaybackForIOS10Plus',
   'setFeatureFlags', 'setLocale', 'setNumRedirects', 'setPlayerType', 'setPlayerVersion', 'setPpid',
   'setSessionId', 'setVpaidAllowed', 'setVpaidMode'].forEach(function (m) { ImaSdkSettings.prototype[m] = noop; });
  ImaSdkSettings.prototype.getLocale = function () { return 'en'; };
  ImaSdkSettings.prototype.getNumRedirects = function () { return 4; };
  ImaSdkSettings.prototype.getPlayerType = function () { return ''; };
  ImaSdkSettings.prototype.getPlayerVersion = function () { return ''; };
  ImaSdkSettings.prototype.isCookiesEnabled = function () { return false; };
  ImaSdkSettings.prototype.isVpaidAllowed = function () { return false; };
  ImaSdkSettings.VpaidMode = { DISABLED: 0, ENABLED: 1, INSECURE: 2 };
  ImaSdkSettings.CompanionBackfillMode = { ALWAYS: 'always', ON_MASTER_AD: 'on_master_ad' };
  var settings = new ImaSdkSettings();

  function AdDisplayContainer() {}
  AdDisplayContainer.prototype.initialize = noop;
  AdDisplayContainer.prototype.destroy = noop;

  function AdsRequest() {}
  AdsRequest.prototype.setAdWillAutoPlay = noop;
  AdsRequest.prototype.setAdWillPlayMuted = noop;
  AdsRequest.prototype.setContinuousPlayback = noop;

  function AdsLoader() { Emitter.call(this); }
  AdsLoader.prototype = Object.create(Emitter.prototype);
  AdsLoader.prototype.contentComplete = noop;
  AdsLoader.prototype.destroy = noop;
  AdsLoader.prototype.getSettings = function () { return settings; };
  AdsLoader.prototype.getVersion = function () { return '3.0.0'; };
  AdsLoader.prototype.requestAds = function (request, userRequestContext) {
    var self = this;
    setTimeout(function () {
      self.emit(AdErrorEvent.Type.AD_ERROR,
        new AdErrorEvent(new AdError(1009, 'The VAST response document is empty.'), userRequestContext));
    }, 0);
  };

  function AdsManagerLoadedEvent() {}
  AdsManagerLoadedEvent.Type = { ADS_MANAGER_LOADED: 'adsManagerLoaded' };
  function AdsRenderingSettings() {}
  function AdEvent() {}
  AdEvent.Type = {
    AD_BREAK_READY: 'adBreakReady', AD_METADATA: 'adMetadata', ALL_ADS_COMPLETED: 'allAdsCompleted',
    CLICK: 'click', COMPLETE: 'complete', CONTENT_PAUSE_REQUESTED: 'contentPauseRequested',
    CONTENT_RESUME_REQUESTED: 'contentResumeRequested', LOADED: 'loaded', PAUSED: 'pause',
    RESUMED: 'resume', SKIPPED: 'skip', STARTED: 'start', USER_CLOSE: 'userClose',
  };

  window.google = window.google || {};
  window.google.ima = {
    AdDisplayContainer: AdDisplayContainer, AdError: AdError, AdErrorEvent: AdErrorEvent, AdEvent: AdEvent,
    AdsLoader: AdsLoader, AdsManagerLoadedEvent: AdsManagerLoadedEvent, AdsRenderingSettings: AdsRenderingSettings,
    AdsRequest: AdsRequest, ImaSdkSettings: ImaSdkSettings, settings: settings,
    UiElements: { AD_ATTRIBUTION: 'adAttribution', COUNTDOWN: 'countdown' },
    ViewMode: { FULLSCREEN: 'fullscreen', NORMAL: 'normal' },
    VERSION: '3.0.0', OmidAccessMode: { DOMAIN: 'domain', FULL: 'full', LIMITED: 'limited' },
  };
})();
