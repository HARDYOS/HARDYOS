// HardyOS editor page: starts the OnlyOffice editor with the config hardyd
// signed for this person and file. The config travels in a data attribute
// (base64 JSON), so this file is the page's only script besides api.js.
(function () {
  "use strict";
  var holder = document.getElementById("hardyos-editor");
  if (!holder) return;
  function fail(msg) {
    var p = holder.querySelector(".loading");
    if (p) p.textContent = msg;
  }
  var cfg;
  try {
    var bin = atob(holder.getAttribute("data-config") || "");
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    cfg = JSON.parse(new TextDecoder().decode(bytes));
  } catch (e) {
    fail("This editor link is damaged. Open the document again.");
    return;
  }
  if (typeof DocsAPI === "undefined") {
    fail("The office suite isn't answering. Try again in a minute.");
    return;
  }
  cfg.events = {
    onAppReady: function () {
      var p = holder.querySelector(".loading");
      if (p) p.remove();
    },
    onError: function (ev) {
      fail("The editor stopped: " + ((ev && ev.data && ev.data.errorDescription) || "unknown error"));
    },
  };
  // eslint-disable-next-line no-new
  new DocsAPI.DocEditor("hardyos-placeholder", cfg);
})();
