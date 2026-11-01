// NullRoute surrogate for pagead2.googlesyndication.com/pagead/js/adsbygoogle.js.
// Pages (and ad-blocker detectors) see a loaded AdSense; no ad is ever requested.
(function () {
  'use strict';
  var queue = window.adsbygoogle;
  var noop = function () {};
  var stub = {
    loaded: true,
    push: function (slot) {
      // Mark the slot as "done" the way AdSense does, so layout code doesn't wait forever.
      var ins = document.querySelectorAll('ins.adsbygoogle:not([data-adsbygoogle-status])');
      for (var i = 0; i < ins.length; i++) {
        ins[i].setAttribute('data-adsbygoogle-status', 'done');
        ins[i].setAttribute('data-ad-status', 'unfilled');
      }
      if (slot && typeof slot.params === 'object' && typeof slot.params.google_ad_loaded === 'function') noop();
    },
    requestNonPersonalizedAds: 0,
    pauseAdRequests: 0,
  };
  if (Array.isArray(queue)) for (var i = 0; i < queue.length; i++) stub.push(queue[i]);
  window.adsbygoogle = stub;
})();
