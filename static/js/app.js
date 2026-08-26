/* ==========================================================================
   Sherlock Web — frontend application
   Vanilla JS, no build step. Sections:
     state · dom · utils · toasts & modal · tabs & sidebar · site picker
     quick scan · investigation renderers · investigation run · graph
     export · watchlist · alerts · history · init
   The API contract (fetch URLs, SSE event names, payload shapes) is
   unchanged from the original single-file app.
   ========================================================================== */
(function () {
  "use strict";

  /* ============================ dom ============================ */
  var els = {
    usernames: document.getElementById("usernames"),
    timeout: document.getElementById("timeout"),
    nsfw: document.getElementById("nsfw"),
    sitePickerBtn: document.getElementById("sitePickerBtn"),
    sitePickerLabel: document.getElementById("sitePickerLabel"),
    sitePicker: document.getElementById("sitePicker"),
    siteFilter: document.getElementById("siteFilter"),
    siteList: document.getElementById("siteList"),
    selectAllFiltered: document.getElementById("selectAllFiltered"),
    clearSites: document.getElementById("clearSites"),
    startBtn: document.getElementById("startBtn"),
    stopBtn: document.getElementById("stopBtn"),
    overallBar: document.getElementById("overallBar"),
    overallFill: document.getElementById("overallFill"),
    overallText: document.getElementById("overallText"),
    elapsedTime: document.getElementById("elapsedTime"),
    runFound: document.getElementById("runFound"),
    exportBar: document.getElementById("exportBar"),
    results: document.getElementById("results"),
    csvBtn: document.getElementById("csvBtn"),
    jsonBtn: document.getElementById("jsonBtn"),
    rerunBtn: document.getElementById("rerunBtn"),
    dossierBtn: document.getElementById("dossierBtn"),
    graphBtn: document.getElementById("graphBtn"),
    watchBtn: document.getElementById("watchBtn"),
    watchInterval: document.getElementById("watchInterval"),
    clearBtn: document.getElementById("clearBtn"),
    tabQuick: document.getElementById("tabQuick"),
    tabInv: document.getElementById("tabInv"),
    quickForm: document.getElementById("quickForm"),
    invForm: document.getElementById("invForm"),
    invName: document.getElementById("invName"),
    invUsernames: document.getElementById("invUsernames"),
    invEmail: document.getElementById("invEmail"),
    invPhone: document.getElementById("invPhone"),
    invDomain: document.getElementById("invDomain"),
    invLocation: document.getElementById("invLocation"),
    invVariants: document.getElementById("invVariants"),
    invThorough: document.getElementById("invThorough"),
    invTimeout: document.getElementById("invTimeout"),
    invNsfw: document.getElementById("invNsfw"),
    invStartBtn: document.getElementById("invStartBtn"),
    invStopBtn: document.getElementById("invStopBtn"),
    graphPanel: document.getElementById("graphPanel"),
    graphPngBtn: document.getElementById("graphPngBtn"),
    graphSearch: document.getElementById("graphSearch"),
    graphLayout: document.getElementById("graphLayout"),
    graphClusterBtn: document.getElementById("graphClusterBtn"),
    graphChangesBtn: document.getElementById("graphChangesBtn"),
    graphStats: document.getElementById("graphStats"),
    graphCsvBtn: document.getElementById("graphCsvBtn"),
    graphGraphmlBtn: document.getElementById("graphGraphmlBtn"),
    graphFsBtn: document.getElementById("graphFsBtn"),
    graphHelpBtn: document.getElementById("graphHelpBtn"),
    graphHelp: document.getElementById("graphHelp"),
    cyNav: document.getElementById("cyNav"),
    graphWrap: document.getElementById("graphWrap"),
    graphFocusChip: document.getElementById("graphFocusChip"),
    graphFocusClose: document.getElementById("graphFocusClose"),
    graphCtx: document.getElementById("graphCtx"),
    graphFallback: document.getElementById("graphFallback"),
    cy: document.getElementById("cy"),
    confSlider: document.getElementById("confSlider"),
    confSliderVal: document.getElementById("confSliderVal"),
    nodeConfSlider: document.getElementById("nodeConfSlider"),
    nodeConfSliderVal: document.getElementById("nodeConfSliderVal"),
    graphFitBtn: document.getElementById("graphFitBtn"),
    graphLabelsBtn: document.getElementById("graphLabelsBtn"),
    graphZoomInBtn: document.getElementById("graphZoomInBtn"),
    graphZoomOutBtn: document.getElementById("graphZoomOutBtn"),
    nodePanel: document.getElementById("nodePanel"),
    tlBar: document.getElementById("timelineBar"),
    tlPlayBtn: document.getElementById("tlPlayBtn"),
    tlScrub: document.getElementById("tlScrub"),
    tlDate: document.getElementById("tlDate"),
    nodePanelBody: document.getElementById("nodePanelBody"),
    nodePanelClose: document.getElementById("nodePanelClose"),
    bellBtn: document.getElementById("bellBtn"),
    alertBadge: document.getElementById("alertBadge"),
    alertsDrop: document.getElementById("alertsDrop"),
    alertsList: document.getElementById("alertsList"),
    markSeenBtn: document.getElementById("markSeenBtn"),
    watchLabel: document.getElementById("watchLabel"),
    watchName: document.getElementById("watchName"),
    watchUsernames: document.getElementById("watchUsernames"),
    watchEmail: document.getElementById("watchEmail"),
    watchNewInterval: document.getElementById("watchNewInterval"),
    watchCreateBtn: document.getElementById("watchCreateBtn"),
    watchList: document.getElementById("watchList"),
    allAlertsList: document.getElementById("allAlertsList"),
    historyPage: document.getElementById("historyPage"),
    menuBtn: document.getElementById("menuBtn"),
    sidebar: document.getElementById("sidebar"),
    sidebarOverlay: document.getElementById("sidebarOverlay"),
    statusPill: document.getElementById("statusPill"),
    statusPillText: document.getElementById("statusPillText"),
    toastWrap: document.getElementById("toastWrap"),
    modalWrap: document.getElementById("modalWrap"),
    modalTitle: document.getElementById("modalTitle"),
    modalBody: document.getElementById("modalBody"),
    modalConfirm: document.getElementById("modalConfirm"),
    modalCancel: document.getElementById("modalCancel")
  };

  /* ============================ state ============================ */
  var allSites = [];          // [{name, nsfw}]
  var selectedSites = {};     // name -> true
  var currentRun = [];        // collected results of the live/loaded run (for export)
  var es = null;              // active quick-scan EventSource
  var invEs = null;           // active investigation EventSource
  var cards = {};             // username -> DOM refs (quick scan)
  var invRows = {};           // "username|normsite" -> {el, badgesEl, data}
  var invCards = {};          // section key -> card refs
  var currentInvId = null;    // investigation id (live or loaded)
  var currentInvInputs = null;
  var holeheCounts = { hits: 0, checked: 0 };
  var runStartedAt = null;    // ms epoch of the current run start
  var elapsedTimer = null;
  var foundTotal = 0;         // total found rows in the current view

  var EMPTY_STATE_HTML =
    '<div class="empty-state">' +
      '<div class="hero">' +
        '<span class="hero-eyebrow"><span class="hero-eyebrow-dot" aria-hidden="true"></span>OSINT investigation console</span>' +
        '<h2 class="hero-title">One clue in.<span class="hero-accent">A full identity out.</span></h2>' +
        '<p class="hero-lead">Give the panel on the left a name, username, email, phone, or domain. Sherlock Web fans out across engines and public data sources, verifies what it finds, and correlates it into one confidence-scored picture.</p>' +
      "</div>" +
      '<div class="cap-grid" aria-label="What Sherlock Web checks">' +
        '<div class="cap-card"><span class="cap-ic" aria-hidden="true"><svg viewBox="0 0 20 20" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="6.2" height="6.2" rx="1.4"/><rect x="10.8" y="3" width="6.2" height="6.2" rx="1.4"/><rect x="3" y="10.8" width="6.2" height="6.2" rx="1.4"/><rect x="10.8" y="10.8" width="6.2" height="6.2" rx="1.4"/></svg></span><div class="cap-body"><span class="cap-t">Accounts across engines</span><span class="cap-d">Sherlock, Maigret &amp; WhatsMyName — cross-checked and de-duplicated.</span></div></div>' +
        '<div class="cap-card"><span class="cap-ic" aria-hidden="true"><svg viewBox="0 0 20 20" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="4.5" width="15" height="11" rx="1.8"/><path d="M3 6l7 5 7-5"/></svg></span><div class="cap-body"><span class="cap-t">Email exposure</span><span class="cap-d">Gravatar profiles plus where the address is registered.</span></div></div>' +
        '<div class="cap-card"><span class="cap-ic" aria-hidden="true"><svg viewBox="0 0 20 20" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="2.5" width="8" height="15" rx="1.8"/><line x1="9" y1="15" x2="11" y2="15"/></svg></span><div class="cap-body"><span class="cap-t">Phone intelligence</span><span class="cap-d">Validity, region, carrier and line type — fully offline.</span></div></div>' +
        '<div class="cap-card"><span class="cap-ic" aria-hidden="true"><svg viewBox="0 0 20 20" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="10" r="7.5"/><path d="M2.5 10h15"/><path d="M10 2.5c2 2.4 3 5 3 7.5s-1 5.1-3 7.5c-2-2.4-3-5-3-7.5s1-5.1 3-7.5z"/></svg></span><div class="cap-body"><span class="cap-t">Domain recon</span><span class="cap-d">DNS, RDAP registration and subdomains from CT logs.</span></div></div>' +
        '<div class="cap-card"><span class="cap-ic" aria-hidden="true"><svg viewBox="0 0 20 20" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M10 2.5l6 2.2v4.3c0 3.7-2.5 6.7-6 8-3.5-1.3-6-4.3-6-8V4.7z"/><path d="M7.5 10l1.7 1.7L13 8"/></svg></span><div class="cap-body"><span class="cap-t">Data-broker exposure</span><span class="cap-d">People-search footprint with direct opt-out links.</span></div></div>' +
        '<div class="cap-card"><span class="cap-ic" aria-hidden="true"><svg viewBox="0 0 20 20" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="5" cy="6" r="2"/><circle cx="15" cy="6" r="2"/><circle cx="10" cy="15" r="2"/><path d="M6.6 7.4l2.5 6M13.4 7.4l-2.5 6M6.9 6h6.2"/></svg></span><div class="cap-body"><span class="cap-t">Identity graph</span><span class="cap-d">Correlated, confidence-scored entities on one canvas.</span></div></div>' +
      "</div>" +
    "</div>";

  /* ============================ utils ============================ */
  function normSite(n) { return String(n).toLowerCase().replace(/[^a-z0-9]/g, ""); }

  // "YYYY-MM-DD HH:MM:SS" (server-local) -> "5m ago" style relative time.
  // Falls back to the raw string when the timestamp can't be parsed.
  function relTime(ts) {
    if (!ts) return "never";
    var t = Date.parse(String(ts).replace(" ", "T"));
    if (isNaN(t)) return String(ts);
    var s = Math.max(0, Math.floor((Date.now() - t) / 1000));
    if (s < 45) return "just now";
    var m = Math.floor(s / 60);
    if (m < 60) return m + "m ago";
    var h = Math.floor(m / 60);
    if (h < 24) return h + "h ago";
    var d = Math.floor(h / 24);
    if (d < 30) return d + "d ago";
    return String(ts).slice(0, 10);
  }

  function fmtElapsed(ms) {
    var s = Math.floor(ms / 1000);
    var m = Math.floor(s / 60);
    return m + ":" + String(s % 60).padStart(2, "0");
  }

  function startElapsed() {
    runStartedAt = Date.now();
    els.elapsedTime.textContent = "0:00";
    clearInterval(elapsedTimer);
    elapsedTimer = setInterval(function () {
      els.elapsedTime.textContent = fmtElapsed(Date.now() - runStartedAt);
    }, 1000);
  }

  function stopElapsed() {
    clearInterval(elapsedTimer);
    elapsedTimer = null;
  }

  function bumpFound(n) {
    foundTotal += (n || 1);
    els.runFound.textContent = String(foundTotal);
  }

  function setStatus(state) { // "online" | "offline" | "connecting"
    els.statusPill.classList.toggle("online", state === "online");
    els.statusPill.classList.toggle("offline", state === "offline");
    els.statusPillText.textContent = state;
  }

  /* skeleton loaders shown until the first real content streams in */
  function showSkeletons() {
    removeSkeletons();
    var frag = document.createDocumentFragment();
    for (var i = 0; i < 2; i++) {
      var c = document.createElement("div");
      c.className = "skel-card";
      c.setAttribute("aria-hidden", "true");
      c.innerHTML =
        '<div class="skel-line skel-w-40"></div>' +
        '<div class="skel-line skel-w-90"></div>' +
        '<div class="skel-line skel-w-70"></div>';
      frag.appendChild(c);
    }
    els.results.appendChild(frag);
  }

  function removeSkeletons() {
    els.results.querySelectorAll(".skel-card").forEach(function (el) { el.remove(); });
  }

  /* ============================ toasts & modal ============================ */
  function toast(msg, type) {
    var el = document.createElement("div");
    el.className = "toast " + (type || "info");
    el.textContent = msg;
    els.toastWrap.appendChild(el);
    setTimeout(function () {
      el.classList.add("leaving");
      setTimeout(function () { el.remove(); }, 260);
    }, 4200);
  }

  var modalOnConfirm = null;
  function confirmModal(title, body, confirmLabel, onConfirm) {
    els.modalTitle.textContent = title;
    els.modalBody.textContent = body;
    els.modalConfirm.textContent = confirmLabel || "Confirm";
    modalOnConfirm = onConfirm;
    els.modalWrap.hidden = false;
    els.modalConfirm.focus();
  }
  function closeModal() {
    els.modalWrap.hidden = true;
    modalOnConfirm = null;
  }
  els.modalConfirm.addEventListener("click", function () {
    var fn = modalOnConfirm;
    closeModal();
    if (fn) fn();
  });
  els.modalCancel.addEventListener("click", closeModal);
  els.modalWrap.addEventListener("click", function (e) {
    if (e.target === els.modalWrap) closeModal();
  });

  /* ============================ tabs & sidebar ============================ */
  var tabEls = {
    investigate: document.getElementById("tabInvestigate"),
    watchlist: document.getElementById("tabWatchlist"),
    history: document.getElementById("tabHistory"),
    health: document.getElementById("tabHealth"),
    casegraph: document.getElementById("tabCasegraph"),
    godseye: document.getElementById("tabGodseye")
  };

  /* topbar contextual title/subtitle per section */
  var SECTION_META = {
    investigate: { title: "Investigate", sub: "One clue in → a full identity out" },
    watchlist: { title: "Watchlist", sub: "Continuous monitoring with change alerts" },
    history: { title: "History", sub: "Reload any past investigation or scan" },
    health: { title: "Source Health", sub: "Adaptive routing, reliability & circuit breakers" },
    casegraph: { title: "Case graph", sub: "The investigation as a live entity graph" },
    godseye: { title: "God's Eye View", sub: "Live geospatial intelligence on a 3D globe" }
  };
  var sectionTitleEl = document.getElementById("sectionTitle");
  var sectionSubEl = document.getElementById("sectionSub");
  function setSectionMeta(tab) {
    var m = SECTION_META[tab];
    if (!m) return;
    if (sectionTitleEl) sectionTitleEl.textContent = m.title;
    if (sectionSubEl) sectionSubEl.textContent = m.sub;
  }

  function closeSidebar() {
    els.sidebar.classList.remove("open");
    els.sidebarOverlay.classList.remove("open");
    els.sidebarOverlay.hidden = true;
    els.menuBtn.setAttribute("aria-expanded", "false");
  }

  els.menuBtn.addEventListener("click", function () {
    var open = !els.sidebar.classList.contains("open");
    els.sidebar.classList.toggle("open", open);
    els.sidebarOverlay.hidden = !open;
    els.sidebarOverlay.classList.toggle("open", open);
    els.menuBtn.setAttribute("aria-expanded", String(open));
  });
  els.sidebarOverlay.addEventListener("click", closeSidebar);

  document.querySelectorAll(".app-tab").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var tab = btn.getAttribute("data-tab");
      document.querySelectorAll(".app-tab").forEach(function (b) {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      Object.keys(tabEls).forEach(function (k) {
        tabEls[k].classList.toggle("active", k === tab);
      });
      setSectionMeta(tab);
      if (tab === "watchlist") { loadWatchlist(); loadAllAlerts(); }
      if (tab === "history") { loadHistory(); }
      if (tab === "health") { loadHealthSources(); }
      if (tab === "casegraph") { openCaseGraph(); }
      if (tab === "godseye") { openGodseye(); }
      closeSidebar();
    });
  });
  function switchTab(tab) {
    document.querySelector('.app-tab[data-tab="' + tab + '"]').click();
  }

  /* ============ God's Eye View (embedded geospatial workspace) ============ */
  // The full app runs as its own service; we embed it when reachable, else show
  // setup instructions. Keys live in that app, never here.
  var gevFrameUrl = null;
  function openGodseye() {
    var frame = document.getElementById("gevFrame");
    var setup = document.getElementById("gevSetup");
    var statusEl = document.getElementById("gevStatus");
    var urlEl = document.getElementById("gevUrl");
    var openEl = document.getElementById("gevOpen");
    function showSetup(msg, cls) {
      if (frame) frame.hidden = true;
      if (setup) setup.style.display = "flex";
      if (statusEl) {
        statusEl.textContent = msg;
        statusEl.className = "gev-status" + (cls ? " " + cls : "");
      }
    }
    if (statusEl) { statusEl.textContent = "Checking for a running instance…"; statusEl.className = "gev-status"; }
    fetch("/api/godseye/status").then(function (r) { return r.json(); })
      .then(function (s) {
        if (urlEl) urlEl.textContent = s.url;
        if (openEl) openEl.href = s.url;
        if (s.reachable && frame) {
          if (gevFrameUrl !== s.url) { frame.src = s.url; gevFrameUrl = s.url; }
          frame.hidden = false;
          if (setup) setup.style.display = "none";
        } else {
          showSetup("Not running at " + s.url + " — start it with ./scripts/godseye.sh, then recheck.", "down");
        }
      })
      .catch(function () { showSetup("Could not reach the status check.", "down"); });
  }
  (function () {
    var rc = document.getElementById("gevRecheck");
    if (rc) rc.addEventListener("click", openGodseye);
  })();

  /* ==================== adaptive routing / source health ==================== */
  var ERROR_LABELS = {
    timeout: "timeouts", dns: "DNS failures", tls: "TLS errors",
    conn_reset: "connection resets", http_429: "rate-limited",
    http_403_waf: "WAF-blocked", http_5xx: "server errors (5xx)",
    detector_stale: "stale detectors", unknown: "unknown errors"
  };

  function breakdownText(d) {
    var bd = (d && d.error_breakdown) || {};
    var total = 0;
    Object.keys(bd).forEach(function (k) { total += bd[k]; });
    if (!total) return "";
    var parts = Object.keys(bd).map(function (k) {
      return bd[k] + " " + (ERROR_LABELS[k] || k);
    });
    return total + " errors: " + parts.join(", ");
  }

  function degradedText(d) {
    return (d && d.degraded_sources)
      ? d.degraded_sources + " degraded source(s) skipped (circuit open)" : "";
  }

  function noteSkippedDegraded(d) {
    var names = (d.sites || []).map(function (s) { return s.site; });
    toast("Skipping " + d.count + " degraded source(s) (circuit open): " +
          names.slice(0, 5).join(", ") + (names.length > 5 ? "…" : ""));
  }

  function loadHealthSources() {
    var sum = document.getElementById("healthSummary");
    var list = document.getElementById("healthList");
    fetch("/api/health/sources").then(function (r) { return r.json(); }).then(function (d) {
      if (!d.available) {
        sum.textContent = "Source health unavailable — routing is disabled (database error).";
        list.innerHTML = "";
        return;
      }
      var a = d.aggregate || {};
      sum.textContent = (a.sites_tracked || 0) + " sources tracked · " +
        (a.observations || 0) + " observations · " +
        Math.round((a.overall_failure_rate || 0) * 100) + "% overall failure rate · " +
        (a.circuits_open || 0) + " circuit(s) open";
      if (!d.sites || !d.sites.length) {
        list.innerHTML = '<div class="hint">No source observations yet.</div>';
        return;
      }
      list.innerHTML = "";
      d.sites.forEach(function (s) {
        var row = document.createElement("div");
        row.className = "hrow";
        var circuitCls = s.circuit === "open" ? "circuit-open"
          : (s.circuit === "half-open" ? "circuit-half" : "circuit-closed");
        var circuitTxt = s.circuit === "open"
          ? "open · " + Math.max(1, Math.ceil(s.cooldown_remaining_s / 60)) + "m left"
          : s.circuit;
        row.innerHTML =
          '<span class="site"></span>' +
          '<span class="engine"></span>' +
          '<span class="badge ' + circuitCls + '"></span>' +
          '<span class="cls"></span>' +
          '<span class="meta"></span>';
        row.querySelector(".site").textContent = s.site;
        row.querySelector(".engine").textContent = s.engine;
        row.querySelector(".badge").textContent = circuitTxt;
        row.querySelector(".cls").textContent =
          s.dominant_error ? (ERROR_LABELS[s.dominant_error] || s.dominant_error) : "";
        row.querySelector(".meta").textContent =
          Math.round((s.failure_rate || 0) * 100) + "% fail · " + s.observations + " obs" +
          (s.ewma_latency_ms != null ? " · " + Math.round(s.ewma_latency_ms) + "ms" : "");
        list.appendChild(row);
      });
    }).catch(function () {
      sum.textContent = "Failed to load source health.";
    });
  }

  /* global Esc handling: close whatever floating layer is open */
  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    if (!els.modalWrap.hidden) { closeModal(); return; }
    if (els.nodePanel.classList.contains("open")) {
      els.nodePanel.classList.remove("open");
      if (cy) cy.elements().removeClass("hl dimmed");
      return;
    }
    if (els.alertsDrop.classList.contains("open")) {
      els.alertsDrop.classList.remove("open");
      els.bellBtn.setAttribute("aria-expanded", "false");
      return;
    }
    if (els.sitePicker.classList.contains("open")) {
      els.sitePicker.classList.remove("open");
      els.sitePickerBtn.setAttribute("aria-expanded", "false");
      return;
    }
    if (els.sidebar.classList.contains("open")) closeSidebar();
  });

  /* ============================ site picker ============================ */
  function updatePickerLabel() {
    var n = Object.keys(selectedSites).length;
    els.sitePickerLabel.textContent = n === 0 ? "All sites" : n + " site" + (n > 1 ? "s" : "") + " selected";
  }

  function renderSiteList(filter) {
    filter = (filter || "").toLowerCase();
    els.siteList.innerHTML = "";
    allSites.forEach(function (s) {
      if (filter && s.name.toLowerCase().indexOf(filter) === -1) return;
      var row = document.createElement("label");
      row.className = "site-item";
      var cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = !!selectedSites[s.name];
      cb.addEventListener("change", function () {
        if (cb.checked) selectedSites[s.name] = true; else delete selectedSites[s.name];
        updatePickerLabel();
      });
      row.appendChild(cb);
      row.appendChild(document.createTextNode(s.name));
      if (s.nsfw) {
        var tag = document.createElement("span");
        tag.className = "nsfw-tag";
        tag.textContent = "nsfw";
        row.appendChild(tag);
      }
      els.siteList.appendChild(row);
    });
  }

  els.sitePickerBtn.addEventListener("click", function () {
    var open = els.sitePicker.classList.toggle("open");
    els.sitePickerBtn.setAttribute("aria-expanded", String(open));
  });
  document.addEventListener("click", function (e) {
    if (!els.sitePicker.contains(e.target) && e.target !== els.sitePickerBtn && !els.sitePickerBtn.contains(e.target)) {
      els.sitePicker.classList.remove("open");
      els.sitePickerBtn.setAttribute("aria-expanded", "false");
    }
  });
  els.siteFilter.addEventListener("input", function () { renderSiteList(els.siteFilter.value); });
  els.selectAllFiltered.addEventListener("click", function () {
    var filter = els.siteFilter.value.toLowerCase();
    allSites.forEach(function (s) {
      if (!filter || s.name.toLowerCase().indexOf(filter) !== -1) selectedSites[s.name] = true;
    });
    renderSiteList(filter);
    updatePickerLabel();
  });
  els.clearSites.addEventListener("click", function () {
    selectedSites = {};
    renderSiteList(els.siteFilter.value);
    updatePickerLabel();
  });

  fetch("/api/sites").then(function (r) { return r.json(); }).then(function (sites) {
    allSites = sites;
    renderSiteList("");
    setStatus("online");
  }).catch(function () {
    setStatus("offline");
    toast("Failed to load site list", "error");
  });

  /* ============================ mode sub-tabs (Investigate) ============================ */
  els.tabQuick.addEventListener("click", function () {
    els.tabQuick.classList.add("active");
    els.tabQuick.setAttribute("aria-selected", "true");
    els.tabInv.classList.remove("active");
    els.tabInv.setAttribute("aria-selected", "false");
    els.quickForm.style.display = "";
    els.invForm.style.display = "none";
  });
  els.tabInv.addEventListener("click", function () {
    els.tabInv.classList.add("active");
    els.tabInv.setAttribute("aria-selected", "true");
    els.tabQuick.classList.remove("active");
    els.tabQuick.setAttribute("aria-selected", "false");
    els.invForm.style.display = "";
    els.quickForm.style.display = "none";
  });

  /* ============================ shared result helpers ============================ */
  function clearResults() {
    els.results.innerHTML = "";
    cards = {};
    invRows = {};
    invCards = {};
    currentRun = [];
    currentInvId = null;
    currentInvInputs = null;
    foundTotal = 0;
    els.runFound.textContent = "0";
    els.exportBar.style.display = "none";
    els.rerunBtn.style.display = "none";
    els.dossierBtn.style.display = "none";
    els.graphBtn.style.display = "none";
    els.watchBtn.style.display = "none";
    els.graphPanel.style.display = "none";
  }

  function resetInvestigationUI() {
    clearResults();
    holeheCounts = { hits: 0, checked: 0 };
    els.overallBar.style.display = "block";
    els.overallFill.style.width = "0%";
    showSkeletons();
  }

  /* ============================ quick-scan result cards ============================ */
  function getCard(username) {
    if (cards[username]) return cards[username];
    removeSkeletons();
    var card = document.createElement("div");
    card.className = "user-card";
    card.innerHTML =
      '<div class="user-head">' +
        "<h2></h2>" +
        '<span class="badge scanning">scanning</span>' +
        '<span class="badge found">0 found</span>' +
        '<span class="badge err" style="display:none">0 errors</span>' +
        '<div class="mini-progress progress-track"><div class="progress-fill"></div></div>' +
      "</div>" +
      '<div class="result-rows"></div>';
    card.querySelector("h2").textContent = username;
    els.results.appendChild(card);
    var refs = {
      root: card,
      scanning: card.querySelector(".badge.scanning"),
      found: card.querySelector(".badge.found"),
      err: card.querySelector(".badge.err"),
      fill: card.querySelector(".progress-fill"),
      rows: card.querySelector(".result-rows"),
      foundCount: 0,
      errCount: 0
    };
    cards[username] = refs;
    return refs;
  }

  function addFoundRow(username, site, url, queryTime, silent) {
    var c = getCard(username);
    var row = document.createElement("div");
    row.className = "rrow";
    var siteSpan = document.createElement("span");
    siteSpan.className = "site";
    siteSpan.textContent = site;
    var a = document.createElement("a");
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = url;
    row.appendChild(siteSpan);
    row.appendChild(a);
    if (queryTime != null) {
      var qt = document.createElement("span");
      qt.className = "qt";
      qt.textContent = Number(queryTime).toFixed(2) + "s";
      row.appendChild(qt);
    }
    c.rows.appendChild(row);
    c.foundCount++;
    c.found.textContent = c.foundCount + " hit" + (c.foundCount > 1 ? "s" : "");
    bumpFound();
    if (!silent) currentRun.push({ username: username, site: site, url: url, status: "found" });
  }

  function addErrorRow(username, site, status, context) {
    var c = getCard(username);
    var row = document.createElement("div");
    row.className = "rrow error";
    var siteSpan = document.createElement("span");
    siteSpan.className = "site";
    siteSpan.textContent = site;
    var st = document.createElement("span");
    st.className = "status";
    st.textContent = status + (context ? " — " + context : "");
    row.appendChild(siteSpan);
    row.appendChild(st);
    c.rows.appendChild(row);
    c.errCount++;
    c.err.style.display = "";
    c.err.textContent = c.errCount + " error" + (c.errCount > 1 ? "s" : "");
    currentRun.push({ username: username, site: site, url: "", status: status, context: context || "" });
  }

  /* ---------- overall progress (quick scan) ---------- */
  var totalUsers = 0, doneUsers = 0, totalSitesPerUser = 0, checkedCurrent = 0;
  function updateOverall() {
    var per = totalSitesPerUser || 1;
    var pct = totalUsers ? ((doneUsers * per + checkedCurrent) / (totalUsers * per)) * 100 : 0;
    els.overallFill.style.width = Math.min(100, pct).toFixed(1) + "%";
    els.overallText.textContent = "User " + Math.min(doneUsers + 1, totalUsers) + " of " + totalUsers +
      " — " + checkedCurrent + "/" + totalSitesPerUser + " sites checked";
  }

  /* ============================ quick scan ============================ */
  function setRunning(running) {
    els.startBtn.disabled = running;
    els.stopBtn.style.display = running ? "block" : "none";
    els.overallBar.classList.toggle("is-running", running);
    if (running) startElapsed(); else stopElapsed();
  }

  function stopStream() {
    if (es) { es.close(); es = null; }
    setRunning(false);
    Object.keys(cards).forEach(function (u) {
      if (cards[u].scanning.textContent === "scanning") cards[u].scanning.textContent = "stopped";
    });
  }

  els.stopBtn.addEventListener("click", function () {
    stopStream();
    els.overallText.textContent = "Stopped.";
  });

  els.startBtn.addEventListener("click", function () {
    var raw = els.usernames.value.trim();
    if (!raw) { toast("Enter at least one username", "error"); return; }

    stopStream();
    stopInvestigation();
    resetInvestigationUI();
    els.overallText.textContent = "Starting…";

    var params = new URLSearchParams();
    params.set("usernames", raw);
    params.set("timeout", els.timeout.value || "10");
    params.set("nsfw", els.nsfw.checked ? "true" : "false");
    var sel = Object.keys(selectedSites);
    if (sel.length) params.set("sites", sel.join(","));

    es = new EventSource("/api/search/stream?" + params.toString());
    setRunning(true);

    es.addEventListener("meta", function (e) {
      var d = JSON.parse(e.data);
      totalUsers = d.usernames.length;
      totalSitesPerUser = d.sites_total;
      doneUsers = 0; checkedCurrent = 0;
      updateOverall();
    });

    es.addEventListener("user_start", function (e) {
      var d = JSON.parse(e.data);
      checkedCurrent = 0;
      var c = getCard(d.username);
      c.scanning.textContent = "scanning";
      updateOverall();
    });

    es.addEventListener("found", function (e) {
      var d = JSON.parse(e.data);
      addFoundRow(d.username, d.site, d.url, d.query_time);
      els.exportBar.style.display = "flex";
    });

    es.addEventListener("error", function (e) {
      var d = JSON.parse(e.data);
      addErrorRow(d.username, d.site, d.status, d.context);
    });

    es.addEventListener("progress", function (e) {
      var d = JSON.parse(e.data);
      checkedCurrent = d.checked;
      totalSitesPerUser = d.total;
      var c = getCard(d.username);
      c.fill.style.width = ((d.checked / d.total) * 100).toFixed(1) + "%";
      updateOverall();
    });

    es.addEventListener("user_done", function (e) {
      var d = JSON.parse(e.data);
      doneUsers++;
      var c = getCard(d.username);
      c.scanning.textContent = "done";
      c.fill.style.width = "100%";
      updateOverall();
      loadHistory();
    });

    es.addEventListener("fatal", function (e) {
      var d = JSON.parse(e.data);
      toast("Scan failed: " + d.message, "error");
      stopStream();
    });

    es.addEventListener("skipped_degraded", function (e) {
      noteSkippedDegraded(JSON.parse(e.data));
    });

    es.addEventListener("retry", function (e) {
      var d = JSON.parse(e.data);
      if (d.username && cards[d.username]) {
        cards[d.username].scanning.textContent = "retrying…";
      }
    });

    es.addEventListener("done", function (e) {
      var d = e.data ? JSON.parse(e.data) : {};
      var msg = "All scans complete.";
      var bd = breakdownText(d);
      if (bd) msg += " " + bd + ".";
      var dg = degradedText(d);
      if (dg) msg += " " + dg + ".";
      els.overallText.textContent = msg;
      if (es) { es.close(); es = null; }
      setRunning(false);
      loadHistory();
    });

    es.onerror = function () {
      if (es && es.readyState === EventSource.CLOSED) {
        setRunning(false);
      }
    };
  });

  /* ============================ investigation renderers ============================ */
  function sectionKeyFor(d) {
    if (d.source === "name") return "name:" + (d.from_name || "");
    if (d.source === "variant" || d.variant_of) return "variants:" + d.variant_of;
    return "base:" + d.username;
  }

  function invSection(key, title, badgeText) {
    if (invCards[key]) return invCards[key];
    removeSkeletons();
    var head = document.createElement("div");
    head.className = "section-head";
    head.textContent = title;
    els.results.appendChild(head);
    // Name candidates are speculative — handles that merely exist and may belong
    // to a different person. Say so, prominently, right under the heading.
    if (key.indexOf("name:") === 0) {
      var caveat = document.createElement("div");
      caveat.className = "section-caveat";
      caveat.textContent = "Speculative — guessed handles that exist somewhere; " +
        "many belong to other people. Trust the per-row verdicts, not the count.";
      els.results.appendChild(caveat);
    }
    var card = document.createElement("div");
    card.className = "user-card";
    card.innerHTML =
      '<div class="user-head"><h2></h2><span class="badge scanning">running</span>' +
      '<span class="badge hits">0 hits</span>' +
      '<span class="dim" style="font-size:11px;margin-left:auto"></span></div>' +
      '<div class="result-rows"></div>';
    card.querySelector("h2").textContent = badgeText || title;
    els.results.appendChild(card);
    var refs = {
      head: head, root: card,
      status: card.querySelector(".badge.scanning"),
      found: card.querySelector(".badge.hits"),
      note: card.querySelector(".user-head .dim"),
      rows: card.querySelector(".result-rows"),
      foundCount: 0
    };
    invCards[key] = refs;
    return refs;
  }

  function sectionFor(d) {
    if (d.source === "name") {
      return invSection("name:" + (d.from_name || ""),
        "Name candidates — " + (d.from_name || ""), "name candidates");
    }
    if (d.source === "variant" || d.variant_of) {
      return invSection("variants:" + d.variant_of,
        "Variants of " + d.variant_of, d.variant_of);
    }
    return invSection("base:" + d.username, "Username: " + d.username, d.username);
  }

  function engineBadges(container, engines) {
    container.innerHTML = "";
    (engines || []).forEach(function (e) {
      var b = document.createElement("span");
      b.className = "engine-badge " + e;
      b.textContent = e;
      container.appendChild(b);
    });
  }

  function addInvFoundRow(d) {
    var key = d.username + "|" + normSite(d.site);
    var c = sectionFor(d);
    if (invRows[key]) return; // duplicate event, ignore

    var row = document.createElement("div");
    row.className = "rrow";
    var siteSpan = document.createElement("span");
    siteSpan.className = "site";
    siteSpan.textContent = d.site;
    if (d.source === "variant" || d.variant_of) {
      var vt = document.createElement("span");
      vt.className = "variant-tag";
      vt.textContent = d.username;
      siteSpan.appendChild(vt);
    } else if (d.source === "name") {
      var nt = document.createElement("span");
      nt.className = "variant-tag";
      nt.textContent = d.candidate || d.username;
      siteSpan.appendChild(nt);
    }
    var main = document.createElement("div");
    main.className = "rmain";
    var a = document.createElement("a");
    a.href = d.url; a.target = "_blank"; a.rel = "noopener noreferrer";
    a.textContent = d.url;
    var badges = document.createElement("span");
    badges.className = "badges";
    engineBadges(badges, d.engines);
    main.appendChild(a);
    main.appendChild(badges);
    row.appendChild(siteSpan);
    row.appendChild(main);
    c.rows.appendChild(row);
    c.foundCount++;
    c.found.textContent = c.foundCount + " hit" + (c.foundCount > 1 ? "s" : "");
    bumpFound();

    var entry = { username: d.username, site: d.site, url: d.url,
                  status: "found", engines: (d.engines || []).slice(),
                  source: d.source || "base",
                  variant_of: d.variant_of || "",
                  from_name: d.from_name || "",
                  candidate: d.candidate || "",
                  verification: "",
                  display_name: "", bio: "", avatar: "" };
    invRows[key] = { el: row, badgesEl: badges, data: entry };
    currentRun.push(entry);
    els.exportBar.style.display = "flex";
  }

  function mergeInvRow(d) {
    var key = d.username + "|" + normSite(d.site);
    var r = invRows[key];
    if (!r) return;
    r.data.engines = d.engines.slice();
    engineBadges(r.badgesEl, d.engines);
  }

  var VERIFY_LABELS = {
    confirmed: { cls: "confirmed", text: "✓ confirmed" },
    unconfirmed: { cls: "unconfirmed", text: "? unconfirmed lead" },
    likely_false_positive: { cls: "false", text: "⚠ likely false positive" },
    // "blocked" and "never checked" are NOT weak findings — they are absences
    // of evidence, and must read differently from anything we actually examined.
    indeterminate: { cls: "indeterminate", text: "⃠ blocked — can't tell" },
    not_examined: { cls: "unverified", text: "· not examined" },
    unverified: { cls: "unverified", text: "· not examined" }
  };

  // Approximate a row's confidence from its verdict when the server number
  // isn't at hand (e.g. a reloaded run). Live runs send the real value.
  function rowConfFromStatus(status) {
    if (status === "confirmed") return 80;
    if (status === "unconfirmed") return 35;
    if (status === "likely_false_positive") return 5;
    if (status === "indeterminate") return 18;
    return 15; // not examined
  }
  // Platform dates arrive in mixed shapes (ISO-8601, "Dec 27, 2016", or a unix
  // epoch). Render a stable YYYY-MM-DD, or pass the value through unchanged.
  function shortDate(v) {
    if (v == null || v === "") return "";
    if (typeof v === "number" || /^\d{9,13}$/.test(String(v))) {
      var n = Number(v);
      if (n < 1e12) n *= 1000;               // seconds -> ms
      var du = new Date(n);
      if (!isNaN(du.getTime())) return du.toISOString().slice(0, 10);
    }
    var d = new Date(v);
    return isNaN(d.getTime()) ? String(v).slice(0, 10) : d.toISOString().slice(0, 10);
  }

  function rowConfBand(conf) {
    if (conf >= 65) return "conf-high";
    if (conf >= 35) return "conf-med";
    return "conf-low";
  }
  function applyRowConfidence(r, conf) {
    if (conf == null || isNaN(conf)) return;
    conf = Math.round(conf);
    r.el.dataset.conf = String(conf);
    r.data.confidence = conf;
    var chip = r.el.querySelector(".row-conf");
    if (!chip) {
      chip = document.createElement("span");
      chip.className = "row-conf";
      r.el.querySelector(".rmain").appendChild(chip);
    }
    chip.className = "row-conf " + rowConfBand(conf);
    chip.textContent = conf + "%";
    chip.title = "confidence this is the subject's account";
  }

  // A row we never fetched has no confidence — printing a number for it invents
  // evidence that does not exist. Show an em-dash instead, and sort it to the
  // bottom without pretending to have measured anything.
  function applyRowUnknownConfidence(r) {
    r.el.dataset.conf = "0";
    r.data.confidence = null;
    var chip = r.el.querySelector(".row-conf");
    if (!chip) {
      chip = document.createElement("span");
      chip.className = "row-conf";
      r.el.querySelector(".rmain").appendChild(chip);
    }
    chip.className = "row-conf conf-none";
    chip.textContent = "—";
    chip.title = "not examined — no confidence can be stated";
  }

  // After a run (or a reload) completes: any row that never got a verdict is an
  // unverified lead — label it, then re-rank each card so the strongest matches
  // sit on top and the noise sinks. Nothing is hidden.
  function finalizeAccuracy() {
    Object.keys(invRows).forEach(function (k) {
      var r = invRows[k];
      if (r.data.verification) return;
      setVerifyBadge(r, { status: "not_examined",
        signals: ["not fetched — no evidence either way for this row"] });
      if (!r.el.dataset.conf) applyRowUnknownConfidence(r);
    });
    Object.keys(invCards).forEach(function (key) {
      var rowsEl = invCards[key].rows;
      if (!rowsEl) return;
      var rows = Array.prototype.slice.call(rowsEl.querySelectorAll(".rrow"));
      rows.sort(function (a, b) {
        return parseInt(b.dataset.conf || "0", 10) - parseInt(a.dataset.conf || "0", 10);
      });
      rows.forEach(function (el) { rowsEl.appendChild(el); });
    });
  }

  function setVerifyBadge(r, v) {
    if (!v || !v.status) return;
    var meta = VERIFY_LABELS[v.status];
    if (!meta) return;
    r.data.verification = v.status;
    r.el.classList.toggle("fp", v.status === "likely_false_positive");
    var badge = r.el.querySelector(".verify-badge");
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "verify-badge";
      var main = r.el.querySelector(".rmain");
      var enrich = main.querySelector(".enrich");
      main.insertBefore(badge, enrich || null);
    }
    badge.className = "verify-badge " + meta.cls;
    badge.textContent = meta.text;
    if (v.signals && v.signals.length) badge.title = v.signals.join("; ");
  }

  function enrichInvRow(d) {
    var key = d.username + "|" + normSite(d.site);
    var r = invRows[key];
    if (!r) return;
    if (d.verification) setVerifyBadge(r, d.verification);
    var vstatus = (d.verification || {}).status;
    if (vstatus === "not_examined") {
      applyRowUnknownConfidence(r);
    } else {
      applyRowConfidence(r, (typeof d.confidence === "number")
        ? d.confidence : rowConfFromStatus(vstatus));
    }
    // Account age / last activity, straight from the platform's own API. In a
    // time-critical case this is often the single most decisive fact, so it
    // goes on the row rather than being buried in the payload.
    if (d.temporal && !r.el.querySelector(".row-temporal")) {
      var bits = [];
      if (d.temporal.created_at) bits.push("created " + shortDate(d.temporal.created_at));
      var last = d.temporal.last_activity || d.temporal.last_post
              || d.temporal.indexed_at || d.temporal.last_profile_update;
      if (last) bits.push("active " + shortDate(last));
      if (bits.length) {
        var t = document.createElement("div");
        t.className = "row-temporal";
        t.textContent = "⏱ " + bits.join(" · ");
        r.el.querySelector(".rmain").appendChild(t);
        r.data.created_at = d.temporal.created_at || "";
        r.data.last_activity = last || "";
      }
    }
    var enr = d.enrichment || {};
    var img = enr.jsonld_image || enr.og_image;
    var name = enr.jsonld_name || enr.og_title || enr.title;
    var bio = enr.jsonld_description || enr.og_description;
    if (img) r.data.avatar = img;
    if (name) r.data.display_name = name;
    if (bio) r.data.bio = bio;
    if (!img && !name && !bio) return;
    var div = document.createElement("div");
    div.className = "enrich";
    if (img) {
      var im = document.createElement("img");
      im.src = img; im.alt = ""; im.loading = "lazy";
      im.onerror = function () { im.style.display = "none"; };
      div.appendChild(im);
    }
    var txt = document.createElement("div");
    if (name) {
      var n = document.createElement("div");
      n.className = "e-name"; n.textContent = name;
      txt.appendChild(n);
    }
    if (bio) {
      var b = document.createElement("div");
      b.className = "e-bio";
      b.textContent = bio.length > 140 ? bio.slice(0, 137) + "…" : bio;
      txt.appendChild(b);
    }
    div.appendChild(txt);
    r.el.querySelector(".rmain").appendChild(div);
  }

  function addInvErrorRow(d) {
    var c = sectionFor(d);
    var row = document.createElement("div");
    row.className = "rrow error";
    var s = document.createElement("span");
    s.className = "site"; s.textContent = d.site;
    var st = document.createElement("span");
    st.className = "status";
    st.textContent = "[" + d.engine + "] " + d.status + (d.context ? " — " + d.context : "");
    row.appendChild(s); row.appendChild(st);
    c.rows.appendChild(row);
  }

  function renderGravatar(email, profile) {
    var c = invSection("email", "Email pivot", email);
    var row = document.createElement("div");
    row.className = "rrow";
    var main = document.createElement("div");
    main.className = "rmain";
    if (!profile) {
      main.innerHTML = '<span class="dim">Gravatar: no public profile</span>';
    } else {
      var div = document.createElement("div");
      div.className = "enrich";
      if (profile.avatar_url) {
        var im = document.createElement("img");
        im.src = profile.avatar_url; im.alt = "";
        im.onerror = function () { im.style.display = "none"; };
        div.appendChild(im);
      }
      var txt = document.createElement("div");
      var n = document.createElement("div");
      n.className = "e-name";
      n.textContent = profile.display_name || profile.full_name || "Gravatar profile";
      txt.appendChild(n);
      if (profile.about) {
        var b = document.createElement("div");
        b.className = "e-bio"; b.textContent = profile.about;
        txt.appendChild(b);
      }
      if (profile.profile_url) {
        var a = document.createElement("a");
        a.href = profile.profile_url; a.target = "_blank";
        a.rel = "noopener noreferrer"; a.textContent = profile.profile_url;
        txt.appendChild(a);
      }
      (profile.accounts || []).forEach(function (acc) {
        if (!acc.url) return;
        var la = document.createElement("a");
        la.href = acc.url; la.target = "_blank"; la.rel = "noopener noreferrer";
        la.style.marginRight = "8px";
        la.textContent = acc.name || acc.domain;
        txt.appendChild(la);
      });
      div.appendChild(txt);
      main.appendChild(div);
    }
    row.appendChild(main);
    c.rows.appendChild(row);
  }

  function addHoleheRow(d) {
    var c = invSection("email", "Email pivot", d.email || "email");
    holeheCounts.checked++;
    if (d.exists) holeheCounts.hits++;
    c.note.textContent = holeheCounts.hits + " hits / " + holeheCounts.checked + " checks";
    if (!d.exists && !d.error) return;  // keep the list to positives + errors
    var row = document.createElement("div");
    row.className = "rrow";
    var s = document.createElement("span");
    s.className = "site " + (d.exists ? "email-hit" : "email-miss");
    s.textContent = d.site || "?";
    var main = document.createElement("div");
    main.className = "rmain";
    var st = document.createElement("div");
    st.className = d.exists ? "email-hit" : "email-miss";
    st.textContent = d.exists ? ("registered" + (d.domain ? " — " + d.domain : ""))
                              : (d.error ? "error: " + d.error : (d.rate_limit ? "rate limited" : ""));
    main.appendChild(st);
    // Masked recovery trail some reset flows leak — a partial lead that can tie
    // this account to another email/phone (never a full profile, so labelled so).
    if (d.exists && (d.email_recovery || d.phone_number)) {
      var rec = document.createElement("div");
      rec.className = "recovery-hint";
      var bits = [];
      if (d.email_recovery) bits.push("recovery email " + d.email_recovery);
      if (d.phone_number) bits.push("recovery phone " + d.phone_number);
      rec.appendChild(document.createTextNode("↳ " + bits.join(" · ")));
      if (d.corroborates_phone) {
        var b = document.createElement("span");
        b.className = "trail-badge";
        b.textContent = "matches subject phone";
        rec.appendChild(document.createTextNode(" "));
        rec.appendChild(b);
      }
      main.appendChild(rec);
    }
    row.appendChild(s); row.appendChild(main);
    c.rows.appendChild(row);
  }

  // Sub-heading inside a result card (used by the phone section's blocks).
  function phoneSubhead(text) {
    var h = document.createElement("div");
    h.className = "phone-subhead";
    h.textContent = text;
    return h;
  }

  // Ensure (and return) the streamed "Registered platforms" container in the
  // phone section, so live phone_account events and a reloaded p.accounts land
  // in the same place — above the reverse-lookup and footprint blocks.
  function ensurePhoneAccounts() {
    var c = invSection("phone", "Phone intelligence", "phone");
    var wrap = c.rows.querySelector(".phone-accounts");
    if (!wrap) {
      var head = phoneSubhead("Registered platforms");
      head.style.display = "none";
      wrap = document.createElement("div");
      wrap.className = "phone-accounts";
      wrap._head = head;
      // Insert before the reverse-lookup/footprint blocks if they already exist.
      var anchor = c.rows.querySelector(".phone-links-block");
      c.rows.insertBefore(head, anchor);
      c.rows.insertBefore(wrap, anchor);
    }
    return wrap;
  }

  function phoneAccountRow(a) {
    var row = document.createElement("div");
    row.className = "rrow";
    var s = document.createElement("span");
    s.className = "site " + (a.exists ? "email-hit" : "email-miss");
    s.textContent = a.site || "?";
    var st = document.createElement("span");
    st.className = a.exists ? "email-hit" : "email-miss";
    st.textContent = a.exists
      ? ("registered" + (a.domain ? " — " + a.domain : ""))
      : (a.error ? "error: " + a.error
                 : (a.rate_limit ? "rate limited" : "not registered"));
    row.appendChild(s); row.appendChild(st);
    return row;
  }

  // Live phone_account events (mirror of addHoleheRow): show positives + errors.
  function addPhoneAccountRow(d) {
    if (!d.exists && !d.error) return;
    var wrap = ensurePhoneAccounts();
    if (wrap._head) wrap._head.style.display = "";
    wrap.appendChild(phoneAccountRow(d));
  }

  function renderPhoneIntel(p) {
    var c = invSection("phone", "Phone intelligence", "phone");
    c.status.textContent = "done";
    c.found.style.display = "none";
    var dl = document.createElement("dl");
    dl.className = "phone-grid";
    function addRow(k, v, cls) {
      if (v === null || v === undefined || v === "") return;
      var dt = document.createElement("dt"); dt.textContent = k;
      var dd = document.createElement("dd"); dd.textContent = String(v);
      if (cls) dd.className = cls;
      dl.appendChild(dt); dl.appendChild(dd);
    }
    if (p.error) {
      addRow("Error", p.error, "phone-invalid");
      c.rows.appendChild(dl);
      return;
    }
    addRow("Valid", p.valid ? "yes" : (p.possible ? "possible, not valid" : "no"),
           p.valid ? "phone-valid" : "phone-invalid");
    addRow("E.164", p.e164);
    addRow("International", p.international);
    addRow("Country", p.country);
    addRow("Region", p.region);
    if (p.assumed_region) addRow("Assumed region", p.assumed_region + " — no country code given; prefix + for other regions");
    addRow("Location", p.location);
    addRow("Carrier", p.carrier);
    addRow("Line type", p.line_type);
    addRow("Timezones", (p.timezones || []).join(", "));
    addRow("Note", p.note);
    c.rows.appendChild(dl);

    // Registered platforms (reloaded runs carry them on p.accounts; live runs
    // stream them via addPhoneAccountRow into the same container).
    ensurePhoneAccounts();
    (p.accounts || []).forEach(addPhoneAccountRow);

    // Reverse-phone lookup links (people-search brokers — manual leads).
    var rev = p.reverse_lookup || [];
    if (rev.length) {
      var rblock = document.createElement("div");
      rblock.className = "phone-links-block";
      rblock.appendChild(phoneSubhead("Reverse-phone lookup"));
      var rhint = document.createElement("div");
      rhint.className = "hint";
      rhint.textContent = "Direct reverse-phone searches on people-search brokers — " +
        "where a name/address may be listed. Manual leads to review; each links its opt-out.";
      rblock.appendChild(rhint);
      rev.forEach(function (b) {
        var row = document.createElement("div");
        row.className = "brow";
        var name = document.createElement("span");
        name.className = "site"; name.textContent = b.name;
        var links = document.createElement("span");
        links.className = "brow-links";
        if (b.search_url) {
          var sl = document.createElement("a");
          sl.href = b.search_url; sl.target = "_blank"; sl.rel = "noopener noreferrer";
          sl.textContent = "reverse lookup"; links.appendChild(sl);
        }
        if (b.optout_url) {
          var ol = document.createElement("a");
          ol.href = b.optout_url; ol.target = "_blank"; ol.rel = "noopener noreferrer";
          ol.textContent = "opt out"; links.appendChild(ol);
        }
        row.appendChild(name); row.appendChild(links);
        rblock.appendChild(row);
      });
      c.rows.appendChild(rblock);
    }

    // Footprint leads (search dorks, spam DBs, messaging presence).
    var fp = p.footprint || [];
    if (fp.length) {
      var fblock = document.createElement("div");
      fblock.className = "phone-links-block";
      fblock.appendChild(phoneSubhead("Footprint leads"));
      var flist = document.createElement("div");
      flist.className = "phone-links";
      fp.forEach(function (f) {
        var a = document.createElement("a");
        a.className = "phone-link phone-link-" + (f.kind || "search");
        a.href = f.url; a.target = "_blank"; a.rel = "noopener noreferrer";
        a.textContent = f.label;
        flist.appendChild(a);
      });
      fblock.appendChild(flist);
      c.rows.appendChild(fblock);
    }
  }

  function renderDomainIntel(d) {
    if (!d || !d.domain) return;
    var c = invSection("domain", "Domain intelligence", d.domain);
    c.status.textContent = "done";
    c.found.style.display = "none";
    c.rows.innerHTML = "";
    var dns = d.dns || {}, rdap = d.rdap || {};
    var dl = document.createElement("dl");
    dl.className = "phone-grid";
    function addRow(k, v) {
      if (v === null || v === undefined || v === "" ||
          (Array.isArray(v) && !v.length)) return;
      var dt = document.createElement("dt"); dt.textContent = k;
      var dd = document.createElement("dd");
      dd.textContent = Array.isArray(v) ? v.join(", ") : String(v);
      dl.appendChild(dt); dl.appendChild(dd);
    }
    if (d.error) { addRow("Error", d.error); c.rows.appendChild(dl); return; }
    addRow("Registrar", rdap.registrar);
    addRow("Registered", rdap.registered);
    addRow("Expires", rdap.expires);
    addRow("Nameservers", (rdap.nameservers && rdap.nameservers.length)
                          ? rdap.nameservers : dns.NS);
    addRow("A", dns.A);
    addRow("AAAA", dns.AAAA);
    addRow("MX", dns.MX);
    addRow("TXT", (dns.TXT || []).slice(0, 6));
    addRow("Subdomains", d.subdomain_count);
    c.rows.appendChild(dl);
    if (d.subdomains && d.subdomains.length) {
      var sub = document.createElement("div");
      sub.className = "dim";
      sub.style.padding = "6px 16px";
      sub.textContent = d.subdomains.slice(0, 40).join(", ") +
        (d.subdomains.length > 40 ? " …" : "");
      c.rows.appendChild(sub);
    }
  }

  var BROKER_STATUS = {
    listed: { cls: "b-listed", label: "listed" },
    blocked: { cls: "b-blocked", label: "blocked (check manually)" },
    not_found: { cls: "b-none", label: "not found" },
    manual: { cls: "b-manual", label: "opt out" }
  };

  function renderBrokerExposure(d) {
    if (!d || !d.brokers) return;
    var c = invSection("brokers", "Data-broker exposure", d.name || "brokers");
    c.status.textContent = "done";
    c.found.style.display = "none";
    c.rows.innerHTML = "";
    var s = d.summary || {};
    var head = document.createElement("div");
    head.className = "dim";
    head.style.padding = "2px 16px 8px";
    head.innerHTML = (s.total || 0) + " brokers · " + (s.listed || 0) +
      " listed · " + (s.blocked || 0) + " blocked · " +
      '<a href="' + d.drop_portal + '" target="_blank" rel="noopener noreferrer">' +
      "remove from 500+ via California DROP portal &#8599;</a>";
    c.rows.appendChild(head);
    // strong signals first: listed, then blocked, then the rest
    var order = { listed: 0, blocked: 1, manual: 2, not_found: 3 };
    var sorted = (d.brokers || []).slice().sort(function (a, b) {
      return (order[a.status] || 9) - (order[b.status] || 9);
    });
    sorted.forEach(function (b) {
      var meta = BROKER_STATUS[b.status] || BROKER_STATUS.manual;
      var row = document.createElement("div");
      row.className = "brow";
      var name = document.createElement("span");
      name.className = "site"; name.textContent = b.name;
      var cat = document.createElement("span");
      cat.className = "engine"; cat.textContent = b.category || "";
      var badge = document.createElement("span");
      badge.className = "badge " + meta.cls; badge.textContent = meta.label;
      var links = document.createElement("span");
      links.className = "brow-links";
      if (b.search_url) {
        var sl = document.createElement("a");
        sl.href = b.search_url; sl.target = "_blank"; sl.rel = "noopener noreferrer";
        sl.textContent = "search"; links.appendChild(sl);
      }
      var ol = document.createElement("a");
      ol.href = b.optout_url; ol.target = "_blank"; ol.rel = "noopener noreferrer";
      ol.textContent = "opt out"; links.appendChild(ol);
      row.appendChild(name); row.appendChild(cat);
      row.appendChild(badge); row.appendChild(links);
      c.rows.appendChild(row);
    });
  }

  function renderCorrelation(clusters) {
    var c = invSection("correlation", "Correlation", "clusters");
    c.status.textContent = "done";
    c.found.style.display = "none";
    if (!clusters || !clusters.length) {
      c.rows.innerHTML = '<div class="rrow"><span class="dim">No cross-account correlations found.</span></div>';
      return;
    }
    clusters.forEach(function (cl) {
      var card = document.createElement("div");
      card.className = "cluster-card";
      var top = document.createElement("div");
      var track = document.createElement("span");
      track.className = "conf-track";
      var fill = document.createElement("span");
      fill.className = "conf-fill";
      fill.style.width = Math.min(100, cl.confidence) + "%";
      track.appendChild(fill);
      top.appendChild(track);
      var lbl = document.createElement("b");
      lbl.textContent = " " + cl.confidence + "% confidence";
      top.appendChild(lbl);
      card.appendChild(top);
      var ul = document.createElement("ul");
      (cl.members || []).forEach(function (m) {
        var li = document.createElement("li");
        var a = document.createElement("a");
        a.href = m.url; a.target = "_blank"; a.rel = "noopener noreferrer";
        a.textContent = m.site + " — " + m.url;
        li.appendChild(a);
        ul.appendChild(li);
      });
      card.appendChild(ul);
      (cl.links || []).forEach(function (l) {
        var r = document.createElement("div");
        r.className = "rationale";
        r.textContent = "↔ " + l.rationale;
        card.appendChild(r);
      });
      c.rows.appendChild(card);
    });
  }

  /* ============================ investigation run ============================ */
  function setInvRunning(running) {
    els.invStartBtn.disabled = running;
    els.invStopBtn.style.display = running ? "block" : "none";
    els.overallBar.classList.toggle("is-running", running);
    if (running) startElapsed(); else stopElapsed();
  }

  function stopInvestigation() {
    if (invEs) { invEs.close(); invEs = null; }
    setInvRunning(false);
  }

  els.invStopBtn.addEventListener("click", function () {
    stopInvestigation();
    els.overallText.textContent = "Stopped.";
    Object.keys(invCards).forEach(function (k) {
      if (invCards[k].status.textContent === "running") invCards[k].status.textContent = "stopped";
    });
  });

  function enableInvestigationActions(id, inputs) {
    currentInvId = id;
    if (inputs) currentInvInputs = inputs;
    // Reveal the action bar even for runs with no account rows (domain- or
    // phone-only investigations still have a graph, dossier and re-run).
    els.exportBar.style.display = "flex";
    els.rerunBtn.style.display = "";
    els.dossierBtn.style.display = "";
    els.graphBtn.style.display = "";
    els.watchBtn.style.display = "";
  }

  function startRerun(sourceId) {
    if (!sourceId) { toast("No investigation to re-run", "error"); return; }
    els.overallText.textContent = "Re-running investigation…";
    fetch("/api/investigate/" + sourceId + "/rerun", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (resp) {
        if (resp.error) { toast(resp.error, "error"); return; }
        switchTab("investigate");
        stopStream();
        stopInvestigation();
        resetInvestigationUI();
        if (resp.inputs) {
          currentInvInputs = {
            name: resp.inputs.name || "",
            usernames: resp.inputs.usernames || [],
            email: resp.inputs.email || ""
          };
        }
        openInvestigationStream(resp.investigation_id, {});
      }).catch(function () { toast("Re-run failed", "error"); });
  }

  els.invStartBtn.addEventListener("click", function () {
    var payload = {
      name: els.invName.value.trim(),
      usernames: els.invUsernames.value.trim(),
      email: els.invEmail.value.trim(),
      phone: els.invPhone.value.trim(),
      domain: els.invDomain.value.trim(),
      location: els.invLocation.value.trim(),
      variants: els.invVariants.checked,
      thorough: els.invThorough.checked,
      timeout: parseInt(els.invTimeout.value || "10", 10)
    };
    if (!payload.name && !payload.usernames && !payload.email && !payload.phone && !payload.domain) {
      toast("Give at least one clue: name, username, email, phone, or domain", "error");
      return;
    }

    stopStream();
    stopInvestigation();
    resetInvestigationUI();
    els.overallText.textContent = "Creating investigation…";

    fetch("/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (r) {
      return r.json().catch(function () {
        return { error: "server returned HTTP " + r.status };
      });
    }).then(function (resp) {
      if (resp.error) {
        toast(resp.error, "error");
        els.overallText.textContent = "Could not start: " + resp.error;
        return;
      }
      var invId = resp.investigation_id;
      currentInvInputs = {
        name: payload.name || "",
        usernames: payload.usernames ? payload.usernames.split(/[,\n]+/).map(function (s) { return s.trim(); }).filter(Boolean) : [],
        email: payload.email || ""
      };
      openInvestigationStream(invId, payload);
    }).catch(function () {
      var msg = "Can't reach the server — is it still running? Reload the page and try again.";
      toast(msg, "error");
      els.overallText.textContent = msg;
    });
  });

  function openInvestigationStream(invId, payload) {
    var params = new URLSearchParams();
    params.set("nsfw", els.invNsfw.checked ? "true" : "false");
    invEs = new EventSource("/api/investigate/" + invId + "/stream?" + params.toString());
    setInvRunning(true);
    els.overallText.textContent = "Investigation #" + invId + " running…";

    invEs.addEventListener("meta", function (e) {
      var d = JSON.parse(e.data);
      var bits = [];
      if (d.sherlock_sites) bits.push(d.sherlock_sites + " sherlock sites");
      if (d.maigret_sites) bits.push(d.maigret_sites + " maigret sites");
      if (d.whatsmyname_sites) bits.push(d.whatsmyname_sites + " whatsmyname sites");
      if (d.candidates) bits.push(d.candidates + " name candidates × " + d.candidate_sites + " sites");
      if (d.email) bits.push("email pivot");
      if (d.phone) bits.push("phone intel");
      if (d.domain) bits.push("domain: " + d.domain);
      els.overallText.textContent = "Investigation #" + invId + ": " + bits.join(" · ");
    });
    invEs.addEventListener("candidates", function (e) {
      var d = JSON.parse(e.data);
      var c = sectionFor({ source: "name", from_name: d.name, username: d.name });
      c.note.textContent = d.candidates.length + " candidates: " + d.candidates.slice(0, 8).join(", ") + (d.candidates.length > 8 ? "…" : "");
    });
    invEs.addEventListener("found", function (e) { addInvFoundRow(JSON.parse(e.data)); });
    invEs.addEventListener("merged", function (e) { mergeInvRow(JSON.parse(e.data)); });
    invEs.addEventListener("error", function (e) { addInvErrorRow(JSON.parse(e.data)); });
    invEs.addEventListener("progress", function (e) {
      var d = JSON.parse(e.data);
      var c = invCards[sectionKeyFor(d)];
      if (c) c.note.textContent = d.engine + " " + d.checked + "/" + d.total;
    });
    invEs.addEventListener("engine_done", function (e) {
      var d = JSON.parse(e.data);
      var c = invCards[sectionKeyFor(d)];
      if (c) c.status.textContent = "scanning";
    });
    invEs.addEventListener("engine_error", function (e) {
      var d = JSON.parse(e.data);
      toast(d.engine + " engine error: " + d.message, "error");
    });
    invEs.addEventListener("phase", function (e) {
      var d = JSON.parse(e.data);
      if (d.phase === "enriching")
        els.overallText.textContent = "Enriching up to " + d.targets + " profiles…";
    });
    invEs.addEventListener("enriched", function (e) { enrichInvRow(JSON.parse(e.data)); });
    invEs.addEventListener("email", function (e) {
      var d = JSON.parse(e.data);
      if (d.source === "gravatar") renderGravatar(d.email, d.profile);
      else if (d.source === "holehe") addHoleheRow(d);
    });
    invEs.addEventListener("phone_intel", function (e) {
      renderPhoneIntel(JSON.parse(e.data));
    });
    invEs.addEventListener("phone_account", function (e) {
      addPhoneAccountRow(JSON.parse(e.data));
    });
    invEs.addEventListener("domain_intel", function (e) {
      renderDomainIntel(JSON.parse(e.data));
    });
    invEs.addEventListener("broker_exposure", function (e) {
      renderBrokerExposure(JSON.parse(e.data));
    });
    invEs.addEventListener("correlation", function (e) {
      renderCorrelation(JSON.parse(e.data).clusters);
    });
    invEs.addEventListener("saved", function (e) {
      var d = JSON.parse(e.data);
      enableInvestigationActions(d.investigation_id);
    });
    invEs.addEventListener("fatal", function (e) {
      toast("Investigation failed: " + JSON.parse(e.data).message, "error");
      stopInvestigation();
    });
    invEs.addEventListener("skipped_degraded", function (e) {
      noteSkippedDegraded(JSON.parse(e.data));
    });
    invEs.addEventListener("retry", function (e) {
      var d = JSON.parse(e.data);
      var c = invCards[sectionKeyFor(d)];
      if (c) c.status.textContent = "retrying…";
    });
    invEs.addEventListener("done", function (e) {
      var d = JSON.parse(e.data);
      finalizeAccuracy();
      var hits = (d.hits != null) ? d.hits : (d.found + d.leads + d.flagged);
      var msg = "Investigation complete — " + d.found + " confirmed, " +
        (d.leads || 0) + " unconfirmed leads, " + (d.flagged || 0) +
        " likely false positives, " + (d.not_examined || 0) + " not examined, " +
        (d.indeterminate || 0) + " blocked (of " + hits + " raw hits). " +
        d.clusters + " clusters, " + d.email_hits + " email hits.";
      var bd = breakdownText(d);
      if (bd) msg += " " + bd + ".";
      var dg = degradedText(d);
      if (dg) msg += " " + dg + ".";
      els.overallText.textContent = msg;
      els.overallFill.style.width = "100%";
      Object.keys(invCards).forEach(function (k) {
        invCards[k].status.textContent = "done";
      });
      enableInvestigationActions(invId);
      stopInvestigation();
      loadHistory();
    });
    invEs.onerror = function () {
      if (invEs && invEs.readyState === EventSource.CLOSED) setInvRunning(false);
    };
  }

  els.rerunBtn.addEventListener("click", function () {
    startRerun(currentInvId);
  });

  els.dossierBtn.addEventListener("click", function () {
    if (currentInvId) window.open("/api/investigate/" + currentInvId + "/report", "_blank");
  });

  els.watchBtn.addEventListener("click", function () {
    if (!currentInvInputs) { toast("No investigation inputs to watch", "error"); return; }
    var inputs = {};
    if (currentInvInputs.name) inputs.name = currentInvInputs.name;
    if (currentInvInputs.usernames && currentInvInputs.usernames.length) inputs.usernames = currentInvInputs.usernames;
    if (currentInvInputs.email) inputs.email = currentInvInputs.email;
    if (!inputs.name && !inputs.usernames && !inputs.email) {
      toast("Nothing watchable (phone-only investigations can't be monitored)", "error");
      return;
    }
    var label = currentInvInputs.name ||
      (currentInvInputs.usernames || []).join(", ") || currentInvInputs.email;
    fetch("/api/watchlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        label: label,
        inputs: inputs,
        interval_hours: parseInt(els.watchInterval.value, 10)
      })
    }).then(function (r) { return r.json(); }).then(function (resp) {
      if (resp.error) { toast(resp.error, "error"); return; }
      toast("Watch created — monitoring “" + resp.label + "” " +
            els.watchInterval.options[els.watchInterval.selectedIndex].text, "success");
      loadWatchlist();
    }).catch(function () { toast("Failed to create watch", "error"); });
  });

  /* ============================ identity graph ============================ */
  var cy = null;
  var graphData = null;
  var graphLabelsOn = true;
  var fcoseRegistered = false;
  var selNode = null;   // first of a possible two-click path trace

  var NODE_COLORS = {
    person: "#e8eee6",
    handle: "#e0a63d",
    account: "#9aa79a",
    email: "#e0a63d",
    phone: "#5aa9c9",
    registration: "#7d8a9c",
    domain: "#b18cff",
    ip: "#f778ba",
    nameserver: "#6e7681"
  };

  // Node-type → toolbar chip group. Chips hide whole groups at once.
  function typeGroup(t) {
    if (t === "account") return "account";
    if (t === "handle") return "handle";
    if (t === "email" || t === "phone" || t === "registration") return "contact";
    return "infra"; // person, domain, ip, nameserver
  }

  // Age band from an ISO creation date. 0 = new (<6 mo), 1 = mid (<2 y),
  // 2 = old, -1 = unknown (no ring). Rings are neutral greys on purpose:
  // age is context, not a verdict.
  function ageBand(iso) {
    if (!iso) return -1;
    var t = Date.parse(iso);
    if (isNaN(t)) return -1;
    var days = (Date.now() - t) / 86400000;
    if (days < 183) return 0;
    if (days < 730) return 1;
    return 2;
  }
  var AGE_STYLE = [
    { color: "#e0a63d", padding: 7 },   // new — amber ring (fresh accounts deserve attention)
    { color: "#9aa79a", padding: 4 },   // mid
    { color: "#3d463d", padding: 2 }    // old — barely there
  ];

  // Timeline state: sorted ISO dates of dated nodes; scrub position 0..1000.
  var tlState = { dates: [], minT: 0, maxT: 1, playing: false, raf: null };

  function confidenceBand(conf) {
    if (conf >= 70) return { label: "High", cls: "conf-high" };
    if (conf >= 40) return { label: "Medium", cls: "conf-med" };
    return { label: "Low", cls: "conf-low" };
  }

  function nodeColor(n) {
    if (n.type === "account") {
      // Colour by verification only. Two engines agreeing that a handle EXISTS
      // is not evidence about WHOSE it is, so it must not read as "confirmed".
      var v = n.verification || (n.data || {}).verification;
      if (v === "likely_false_positive") return "#f0615d";  // flagged red
      if (v === "confirmed") return "#4cc38a";               // confirmed green
      if (v === "unconfirmed") return "#e6ab3e";             // lead amber
      if ((n.data || {}).source === "name") return "#e6ab3e"; // speculative amber
      return "#7d8a9c";                                       // unverified grey
    }
    return NODE_COLORS[n.type] || "#7d8a9c";
  }

  function nodeSize(n) {
    if (n.type === "person") return 46;
    if (n.type === "handle") return 34;   // pivots sit between person and contacts
    if (n.type === "email" || n.type === "phone") return 30;
    return 16 + Math.round((n.confidence || 40) * 0.22);
  }

  // Which toolbar chips are on. Keys: account / handle / contact / infra.
  var typeVis = { account: true, handle: true, contact: true, infra: true };

  function nodeVisible(n) {
    // Confidence slider only gates accounts (inputs/facts are always shown).
    if (n.data("type") === "account" &&
        (n.data("confidence") || 0) < parseInt(els.nodeConfSlider.value, 10)) {
      return false;
    }
    if (!typeVis[typeGroup(n.data("type"))]) return false;
    if (tlState.playing || parseInt(els.tlScrub.value, 10) < 1000) {
      // Timeline window: dated nodes appear once created; undated nodes are
      // baseline and fade out while scrubbing (they return at the far end).
      var d = n.data("created_at");
      if (d) {
        if (Date.parse(d) > tlCursor()) return false;
      } else if (parseInt(els.tlScrub.value, 10) < 1000) {
        return false;
      }
    }
    return true;
  }

  function tlCursor() {
    var v = parseInt(els.tlScrub.value, 10);
    return tlState.minT + (tlState.maxT - tlState.minT) * (v / 1000);
  }

  function applyGraphFilters() {
    if (!cy) return;
    var edgeMin = parseInt(els.confSlider.value, 10);
    els.confSliderVal.textContent = edgeMin + "%";
    els.nodeConfSliderVal.textContent = parseInt(els.nodeConfSlider.value, 10) + "%";
    var vis = {};
    cy.batch(function () {
      cy.nodes().forEach(function (n) {
        var ok = nodeVisible(n);
        vis[n.id()] = ok;
        n.style("display", ok ? "element" : "none");
      });
      cy.edges().forEach(function (e) {
        var show = (e.data("confidence") || 0) >= edgeMin &&
          vis[e.data("source")] && vis[e.data("target")];
        e.style("display", show ? "element" : "none");
      });
    });
    updateTlReadout();
  }

  // Backwards-compatible alias (renderGraph calls applyEdgeFilter once built).
  var applyEdgeFilter = applyGraphFilters;

  // ---- timeline scrubber -------------------------------------------------
  function setupTimeline(data) {
    tlState.dates = data.nodes.map(function (n) { return n.created_at; })
      .filter(function (d) { return d && !isNaN(Date.parse(d)); })
      .map(function (d) { return Date.parse(d); })
      .sort(function (a, b) { return a - b; });
    // Fewer than three dated sources is not a story — hide the control
    // rather than play a nearly empty film.
    els.tlBar.hidden = tlState.dates.length < 3;
    if (els.tlBar.hidden) return;
    tlState.minT = tlState.dates[0];
    tlState.maxT = Date.now();
    els.tlScrub.value = "1000";
    stopTimelinePlay();
  }

  function updateTlReadout() {
    if (els.tlBar.hidden) return;
    var t = tlCursor();
    els.tlDate.textContent = new Date(t).toISOString().slice(0, 7);
    els.tlPlayBtn.innerHTML = tlState.playing ? "&#10074;&#10074;" : "&#9654;";
  }

  function stopTimelinePlay() {
    tlState.playing = false;
    if (tlState.raf) cancelAnimationFrame(tlState.raf);
    tlState.raf = null;
    updateTlReadout();
  }

  els.tlScrub.addEventListener("input", function () {
    stopTimelinePlay();
    applyGraphFilters();
  });

  els.tlPlayBtn.addEventListener("click", function () {
    if (tlState.playing) { stopTimelinePlay(); return; }
    tlState.playing = true;
    var start = null, dur = 12000, from = parseInt(els.tlScrub.value, 10);
    if (from >= 1000) { from = 0; }
    function step(ts) {
      if (!tlState.playing) return;
      if (!start) start = ts;
      var k = Math.min(1, from + ((ts - start) / dur) * 1000);
      els.tlScrub.value = String(Math.round(k));
      applyGraphFilters();
      if (k >= 1000) { stopTimelinePlay(); return; }
      tlState.raf = requestAnimationFrame(step);
    }
    tlState.raf = requestAnimationFrame(step);
  });

  // ---- type chips ----------------------------------------------------------
  Array.prototype.forEach.call(
    document.querySelectorAll(".gchip[data-gtype]"), function (chip) {
    chip.addEventListener("click", function () {
      var g = chip.getAttribute("data-gtype");
      typeVis[g] = !typeVis[g];
      chip.classList.toggle("active", typeVis[g]);
      chip.setAttribute("aria-pressed", String(typeVis[g]));
      applyGraphFilters();
    });
  });

  // ---- PNG export -----------------------------------------------------------
  els.graphPngBtn.addEventListener("click", function () {
    if (!cy) return;
    var png = cy.png({ bg: "#0a0c0a", full: true, scale: 2 });
    var a = document.createElement("a");
    a.href = png;
    a.download = "signals-ops-graph.png";
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast("Graph exported as PNG", "success");
  });

  // ---- search ----------------------------------------------------------------
  var searchTimer = null;
  els.graphSearch.addEventListener("input", function () {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(applySearchDim, 120);
  });
  els.graphSearch.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") {
      els.graphSearch.value = "";
      applySearchDim();
    } else if (ev.key === "Enter") {
      var q = els.graphSearch.value.trim().toLowerCase();
      if (!q || !cy) return;
      var hit = cy.nodes().filter(function (n) {
        if (n.style("display") === "none") return false;
        var d = n.data();
        var hay = ((d.label || "") + " " + (d.sublabel || "") + " " +
          ((d.data || {}).category || "")).toLowerCase();
        return hay.indexOf(q) !== -1;
      })[0];
      if (hit) {
        cy.animate({ center: { eles: hit }, zoom: Math.max(cy.zoom(), 1.1) },
                   { duration: 250 });
        hit.trigger("tap");
      } else {
        toast("No node matches “" + q + "”", "error");
      }
    }
  });

  function applySearchDim() {
    if (!cy) return;
    var q = els.graphSearch.value.trim().toLowerCase();
    if (!q) {
      cy.nodes().removeClass("srch-out");
      return;
    }
    cy.batch(function () {
      cy.nodes().forEach(function (n) {
        if (n.style("display") === "none") return;
        var d = n.data();
        var hay = ((d.label || "") + " " + (d.sublabel || "") + " " +
          ((d.data || {}).category || "")).toLowerCase();
        n.removeClass("srch-out");
        if (hay.indexOf(q) === -1) n.addClass("srch-out");
      });
    });
  }

  els.confSlider.addEventListener("input", applyGraphFilters);
  els.nodeConfSlider.addEventListener("input", applyGraphFilters);

  els.graphFitBtn.addEventListener("click", function () {
    if (cy) cy.fit(null, 40);
  });

  // Zoom around the graph's visual center so the framing stays stable.
  function zoomGraph(factor) {
    if (!cy) return;
    cy.zoom({
      level: cy.zoom() * factor,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  }
  els.graphZoomInBtn.addEventListener("click", function () { zoomGraph(1.3); });
  els.graphZoomOutBtn.addEventListener("click", function () { zoomGraph(1 / 1.3); });

  els.graphLabelsBtn.addEventListener("click", function () {
    graphLabelsOn = !graphLabelsOn;
    els.graphLabelsBtn.setAttribute("aria-pressed", String(graphLabelsOn));
    if (cy) {
      cy.style()
        .selector("node")
        .style("label", graphLabelsOn ? "data(labelText)" : "")
        .update();
    }
  });

  function showNodePanel(n, note) {
    var d = n.data();
    // Tint the drawer (top border, type dot, avatar ring) to match the node.
    els.nodePanel.style.setProperty("--np-accent", d.color || "#5ea0ff");
    var body = els.nodePanelBody;
    body.innerHTML = "";
    if (d.avatar) {
      var img = document.createElement("img");
      img.src = d.avatar; img.alt = "";
      img.onerror = function () { img.style.display = "none"; };
      body.appendChild(img);
    }
    var h = document.createElement("h3");
    h.textContent = d.label || d.id;
    body.appendChild(h);
    var t = document.createElement("div");
    t.className = "np-type";
    t.textContent = d.type + (d.sublabel ? " · " + d.sublabel : "");
    body.appendChild(t);
    if (d.confidence != null) {
      var band = confidenceBand(d.confidence);
      var chip = document.createElement("span");
      chip.className = "conf-band " + band.cls;
      chip.textContent = band.label + " confidence · " + d.confidence + "%";
      body.appendChild(chip);
    }
    if (note) {
      var pnote = document.createElement("span");
      pnote.className = "conf-band conf-med";
      pnote.textContent = note;
      body.appendChild(pnote);
    }

    function addField(k, v, isLink) {
      if (v === null || v === undefined || v === "") return;
      var row = document.createElement("div");
      row.className = "np-row";
      var key = document.createElement("div");
      key.className = "k"; key.textContent = k;
      var val = document.createElement("div");
      if (isLink) {
        var a = document.createElement("a");
        a.href = v; a.target = "_blank"; a.rel = "noopener noreferrer";
        a.textContent = v;
        val.appendChild(a);
      } else {
        val.textContent = typeof v === "object" ? JSON.stringify(v) : String(v);
      }
      row.appendChild(key); row.appendChild(val);
      body.appendChild(row);
    }

    addField("profile", d.url, true);
    addField("engines", (d.engines || []).join(", "));
    addField("created", d.created_at ? String(d.created_at).slice(0, 10) : null);
    var data = d.data || {};
    Object.keys(data).forEach(function (k) {
      if (data[k] === null || data[k] === undefined || data[k] === "") return;
      if (k === "gravatar" && typeof data[k] === "object") {
        var g = data[k] || {};
        addField("gravatar name", g.display_name || g.full_name);
        addField("gravatar", g.profile_url, true);
        addField("gravatar bio", g.about);
        addField("location", g.location);
        return;
      }
      addField(k.replace(/_/g, " "), data[k]);
    });
    // incident edges
    var inc = n.connectedEdges().map(function (e) {
      return (e.data("source") === n.id() ? "→ " : "← ") +
        (e.data("source") === n.id() ? e.target().data("label") : e.source().data("label")) +
        " (" + e.data("confidence") + "%: " + (e.data("rationale") || "") + ")";
    });
    if (inc.length) addField("links", inc.join("\n"));

    // investigator note (persisted per investigation)
    var notes = loadNotes();
    var nwrap = document.createElement("div");
    nwrap.className = "np-note";
    var nlabel = document.createElement("div");
    nlabel.className = "k";
    nlabel.textContent = "note";
    var nta = document.createElement("textarea");
    nta.value = notes[n.id()] || "";
    nta.placeholder = "Investigator note for this entity…";
    nta.rows = 3;
    var nsave = document.createElement("button");
    nsave.type = "button";
    nsave.className = "btn btn-ghost btn-sm";
    nsave.textContent = "Save note";
    nsave.addEventListener("click", function () {
      saveNote(n.id(), nta.value);
      toast(nta.value.trim() ? "Note saved" : "Note cleared", "success");
    });
    nwrap.appendChild(nlabel);
    nwrap.appendChild(nta);
    nwrap.appendChild(nsave);
    body.appendChild(nwrap);

    els.nodePanel.classList.add("open");
  }

  els.nodePanelClose.addEventListener("click", function () {
    els.nodePanel.classList.remove("open");
    if (cy) cy.elements().removeClass("hl dimmed");
  });

  function renderGraph(data) {
    graphData = data;
    els.graphPanel.style.display = "block";
    if (typeof cytoscape === "undefined") {
      els.graphFallback.style.display = "block";
      return;
    }
    if (!fcoseRegistered && typeof window.cytoscapeFcose !== "undefined" &&
        typeof window.coseBase !== "undefined" &&
        typeof window.layoutBase !== "undefined") {
      try { cytoscape.use(window.cytoscapeFcose); fcoseRegistered = true; }
      catch (e) { /* fall back to cose below */ }
    }
    var elements = [];
    var notes = loadNotes();
    data.nodes.forEach(function (n) {
      if (dismissedIds[n.id]) return;   // hidden via right-click this session
      var nd = {
        id: n.id, type: n.type, label: n.label, sublabel: n.sublabel || "",
        url: n.url || "",
        confidence: n.confidence, engines: n.engines || [],
        created_at: n.created_at || null,
        data: n.data || {},
        color: nodeColor(n), size: nodeSize(n),
        labelText: n.label + (n.sublabel ? "\n" + n.sublabel : "")
      };
      // Only set `avatar` when there is a real URL. An empty string still
      // matches the `node[avatar]` style rule, and cytoscape then throws
      // parsing "" as a background-image — which silently killed the graph.
      if (n.avatar) nd.avatar = n.avatar;
      var el = { data: nd, classes: "g-" + typeGroup(n.type) };
      // Run-diff markers from the baseline scan.
      if (nd.data.is_new) el.classes += " is-new";
      if (nd.data.gone) { el.classes += " gone-node"; nd.labelText += "\n[GONE]"; }
      if (notes[nd.id]) el.classes += " noted";
      // Age ring (underlay): neutral encoding — amber = fresh account,
      // greys = older. Undated nodes get no ring.
      var band = ageBand(nd.created_at);
      if (band >= 0) {
        el.data.ageBand = band;
        el.classes += " aged";
      }
      elements.push(el);
    });
    data.edges.forEach(function (e) {
      elements.push({ data: {
        id: e.id, source: e.source, target: e.target,
        confidence: e.confidence, rationale: e.rationale
      }});
    });
    if (cy) { cy.destroy(); cy = null; }
    selNode = null;
    hideGraphCtx();
    els.graphFocusChip.hidden = true;
    var lname = els.graphLayout.value;
    if (lname === "fcose" && !fcoseRegistered) lname = "cose";
    cy = cytoscape({
      container: els.cy,
      elements: elements,
      wheelSensitivity: 0.3,
      style: [
        { selector: "node", style: {
          "background-color": "data(color)",
          "width": "data(size)", "height": "data(size)",
          "label": "data(labelText)",
          "color": "#e8eee6", "font-size": 9, "line-height": 1.3,
          "font-family": "'JetBrains Mono', ui-monospace, monospace",
          "min-zoomed-font-size": 7,
          "text-wrap": "wrap", "text-max-width": "110px",
          "text-valign": "bottom", "text-margin-y": 5,
          "text-background-color": "#0a0c0a", "text-background-opacity": 0.82,
          "text-background-padding": 3, "text-background-shape": "roundrectangle",
          "border-width": 1.5, "border-color": "data(color)", "border-opacity": 0.55,
          "background-opacity": 0.95,
          "transition-property": "border-width, border-color, opacity",
          "transition-duration": 120
        }},
        // Age rings: an underlay halo whose colour/size encodes account age.
        { selector: "node.aged", style: {
          "underlay-color": "mapData(ageBand, 0, 2, #e0a63d, #3d463d)",
          "underlay-padding": "mapData(ageBand, 0, 2, 7px, 2px)",
          "underlay-opacity": 0.5
        }},
        // Contact identifiers read as tags; domains as hexagons; IPs as diamonds.
        { selector: 'node[type="email"]', style: { "shape": "round-rectangle" } },
        { selector: 'node[type="phone"]', style: { "shape": "round-rectangle" } },
        { selector: 'node[type="registration"]', style: { "shape": "round-rectangle" } },
        { selector: 'node[type="nameserver"]', style: { "shape": "round-rectangle" } },
        { selector: 'node[type="domain"]', style: { "shape": "hexagon" } },
        { selector: 'node[type="ip"]', style: { "shape": "diamond" } },
        // Handle pivots: square, amber outline — the reuse signal.
        { selector: 'node[type="handle"]', style: {
          "shape": "cut-rectangle", "border-width": 2,
          "border-color": "#e0a63d", "border-opacity": 0.9
        }},
        { selector: 'node[type="person"]', style: {
          "border-width": 3, "border-color": "#e8eee6", "border-opacity": 1,
          "font-size": 12, "font-weight": "bold"
        }},
        { selector: "node[avatar]", style: {
          "background-image": "data(avatar)",
          "background-fit": "cover", "background-clip": "node",
          "background-image-crossorigin": "anonymous"
        }},
        { selector: "edge", style: {
          "width": "mapData(confidence, 0, 100, 1, 4.5)",
          "line-color": "#26302a", "curve-style": "bezier",
          "opacity": 0.85,
          "label": "data(confidence)", "font-size": 8, "color": "#9aa79a",
          "min-zoomed-font-size": 8,
          "font-family": "'JetBrains Mono', ui-monospace, monospace",
          "text-rotation": "autorotate",
          "text-background-color": "#0a0c0a", "text-background-opacity": 0.75,
          "text-background-padding": 1
        }},
        { selector: "edge[confidence >= 60]", style: { "line-color": "#57d96a" } },
        { selector: "edge[confidence < 40]", style: { "line-style": "dashed", "opacity": 0.6 } },
        { selector: "node:selected", style: { "border-color": "#ffffff", "border-width": 3, "border-opacity": 1 } },
        { selector: "node.hl", style: { "border-color": "#e8eee6", "border-width": 3, "border-opacity": 1 } },
        { selector: "edge.hl", style: { "line-color": "#e0a63d", "opacity": 1, "width": 3 } },
        { selector: ".dimmed", style: { "opacity": 0.12 } },
        { selector: ".srch-out", style: { "opacity": 0.15 } },
        // run-diff markers
        { selector: "node.is-new", style: {
          "border-color": "#57d96a", "border-width": 3, "border-opacity": 1,
          "color": "#57d96a"
        }},
        { selector: "node.gone-node", style: {
          "border-style": "dashed", "border-color": "#e05a4e",
          "background-color": "#e05a4e", "background-opacity": 0.35,
          "color": "#e05a4e"
        }},
        // annotated nodes get an amber label tick via ✎ suffix (see saveNote)
        { selector: 'node[type = "catparent"]', style: {
          "shape": "round-rectangle",
          "background-opacity": 0.04,
          "border-width": 1, "border-color": "#2a352a", "border-opacity": 0.8,
          "color": "#5f6b5f", "font-size": 10,
          "text-valign": "top", "text-margin-y": -4,
          "text-background-opacity": 0
        }}
      ],
      layout: {
        name: lname,
        animate: true, animationDuration: 800,
        nodeRepulsion: 12000, idealEdgeLength: 100, gravity: 0.35,
        padding: 40,
        // concentric options
        concentric: function (n) { return n.data("confidence") || 40; },
        levelWidth: function () { return 25; },
        // breadthfirst options
        roots: "#person", directed: false
      }
    });
    initNavigator();
    updateGraphStats();
    var hasDiff = data.nodes.some(function (n) {
      return (n.data || {}).is_new || (n.data || {}).gone;
    });
    els.graphChangesBtn.hidden = !hasDiff;
    if (!hasDiff) { changesOnly = false; els.graphChangesBtn.setAttribute("aria-pressed", "false"); els.graphChangesBtn.classList.remove("active"); }
    // Re-fit once painted and again when the animated layout settles — the
    // panel may still be sizing when cytoscape initializes.
    cy.on("layoutstop", function () { cy.fit(undefined, 40); });
    requestAnimationFrame(function () {
      if (cy) { cy.resize(); cy.fit(undefined, 40); }
    });
    setupTimeline(data);
    applyEdgeFilter();
    if (!graphLabelsOn) {
      cy.style().selector("node").style("label", "").update();
    }

    // Selecting a node focuses its neighborhood; selecting a SECOND node while
    // one is focused traces the strongest connection chain between them
    // ("how does this registration tie back to the subject?"). Double-click
    // isolates an ego view. Right-click opens the action menu.
    var lastTap = { id: null, at: 0 };
    cy.on("tap", "node", function (evt) {
      var n = evt.target;
      hideGraphCtx();
      var now = Date.now();
      if (lastTap.id === n.id() && now - lastTap.at < 350) {
        focusEgo(n, evShifter() ? 2 : 1);
        lastTap = { id: null, at: 0 };
        return;
      }
      lastTap = { id: n.id(), at: now };
      if (selNode && selNode !== n && selNode.inside()) {
        highlightPath(selNode, n);
        return;
      }
      selNode = n;
      var hood = n.closedNeighborhood();
      cy.elements().addClass("dimmed").removeClass("hl");
      hood.removeClass("dimmed");
      hood.nodes().addClass("hl");
      hood.connectedEdges().removeClass("dimmed");
      n.connectedEdges().addClass("hl");
      showNodePanel(n);
    });
    cy.on("cxttap", "node", function (evt) {
      showGraphCtx(evt.target, evt.renderedPosition || evt.cyRenderedPosition);
    });
    cy.on("cxttap", function (evt) {
      if (evt.target === cy) hideGraphCtx();
    });
    cy.on("tap", function (evt) {
      if (evt.target === cy) {
        selNode = null;
        exitEgo();
        cy.elements().removeClass("hl dimmed");
        els.nodePanel.classList.remove("open");
      }
    });
    els.graphPanel.scrollIntoView({ behavior: "smooth" });
  }

  // Trace the shortest evidence chain between two nodes and light it up.
  function highlightPath(a, b) {
    var dij = cy.elements().dijkstra({ root: a, directed: false });
    var path = dij.pathTo(b);
    if (!path || path.length === 0) {
      toast("No connection found between those nodes", "error");
      return;
    }
    cy.elements().addClass("dimmed").removeClass("hl");
    path.removeClass("dimmed");
    path.nodes().addClass("hl");
    path.edges().addClass("hl");
    var weakest = null;
    path.edges().forEach(function (e) {
      var c = e.data("confidence") || 0;
      if (weakest === null || c < weakest) weakest = c;
    });
    showNodePanel(b, weakest === null ? null :
      "path via " + (path.nodes().length - 1) + " hops · weakest link " +
      weakest + "%");
    selNode = null;
  }

  /* ---------------- workbench: notes, dismiss, ego, cluster, exports ------ */

  var dismissedIds = {};     // session-level: hidden via right-click
  var changesOnly = false;
  var clusterMode = false;

  function evShifter() {
    return window.event ? window.event.shiftKey : false;   // dblclick modifier
  }

  // ---- investigator notes (per investigation, in localStorage) ------------
  function notesKey() { return "sop.notes." + (currentInvId || "none"); }
  function loadNotes() {
    try { return JSON.parse(localStorage.getItem(notesKey()) || "{}"); }
    catch (e) { return {}; }
  }
  function saveNote(nodeId, text) {
    var notes = loadNotes();
    if (text && text.trim()) notes[nodeId] = text.trim();
    else delete notes[nodeId];
    try { localStorage.setItem(notesKey(), JSON.stringify(notes)); } catch (e) {}
    if (cy) {
      var n = cy.getElementById(nodeId);
      if (n.nonempty()) {
        n.toggleClass("noted", !!notes[nodeId]);
        n.data("labelText",
          (n.data("label") || "") + (n.data("sublabel") ? "\n" + n.data("sublabel") : "") +
          (notes[nodeId] ? " ✎" : ""));
      }
    }
  }

  // ---- right-click action menu --------------------------------------------
  function hideGraphCtx() {
    els.graphCtx.hidden = true;
  }
  function showGraphCtx(node, rpos) {
    if (!node.inside()) return;
    var d = node.data();
    var items = [];
    if (d.url) items.push({ label: "Open profile ↗", act: function () {
      window.open(d.url, "_blank", "noopener");
    }});
    if (d.url) items.push({ label: "Copy URL", act: function () {
      (navigator.clipboard ? navigator.clipboard.writeText(d.url) :
        Promise.reject()).then(function () { toast("URL copied", "success"); },
          function () { toast("Clipboard unavailable", "error"); });
    }});
    var handle = d.type === "handle" ? d.label :
      ((d.type === "account" && !d.gone && d.label) ? d.label : null);
    if (handle) items.push({ label: "Investigate this handle", act: function () {
      pivotToForm(handle);
    }});
    items.push({ label: "Trace path from here", act: function () {
      selNode = node;
      toast("Now click another node to trace the path between them", "info");
    }});
    items.push({ label: loadNotes()[node.id()] ? "Edit note" : "Add note",
                 act: function () { showNodePanel(node); } });
    if (!d.gone) items.push({ label: "Hide from graph", act: function () {
      dismissedIds[node.id] = true;
      node.remove();
      updateGraphStats();
      toast("Hidden for this session (returns on next render)", "info");
    }});

    var menu = els.graphCtx;
    menu.innerHTML = "";
    items.forEach(function (it) {
      var b = document.createElement("button");
      b.type = "button";
      b.textContent = it.label;
      b.addEventListener("click", function () {
        hideGraphCtx();
        it.act();
      });
      menu.appendChild(b);
    });
    menu.hidden = false;
    var wrap = els.graphWrap.getBoundingClientRect();
    var x = Math.min(rpos.x + wrap.left + 8, window.innerWidth - 190);
    var y = Math.min(rpos.y + wrap.top + 8, window.innerHeight - 40 - items.length * 30);
    menu.style.left = x + "px";
    menu.style.top = y + "px";
  }
  document.addEventListener("click", function (ev) {
    if (!els.graphCtx.hidden && !els.graphCtx.contains(ev.target)) hideGraphCtx();
  });

  function pivotToForm(handle) {
    switchTab("investigate");
    els.tabInv.click();                       // ensure Investigation mode
    els.invUsernames.value = handle;
    document.getElementById("controls").scrollIntoView({ behavior: "smooth" });
    setTimeout(function () { els.invUsernames.focus(); }, 250);
    toast("Handle loaded — review parameters, then Start investigation", "info");
  }

  // ---- ego view -------------------------------------------------------------
  function focusEgo(n, depth) {
    var hood = n.closedNeighborhood();
    if (depth >= 2) hood = hood.union(hood.neighborhood().closedNeighborhood());
    cy.elements().addClass("dimmed").removeClass("hl");
    hood.removeClass("dimmed");
    hood.nodes().addClass("hl");
    els.graphFocusChip.hidden = false;
    els.graphFocusChip.querySelector(".fc-label").textContent =
      "ego ×" + depth + ": " + (n.data("label") || n.id());
    cy.animate({ fit: { eles: hood, padding: 50 } }, { duration: 250 });
    showNodePanel(n);
  }
  function exitEgo() {
    if (els.graphFocusChip.hidden) return;
    els.graphFocusChip.hidden = true;
    cy.elements().removeClass("dimmed hl");
    if (cy) cy.fit(undefined, 40);
  }
  els.graphFocusClose.addEventListener("click", exitEgo);

  // ---- cluster by category (compound nodes) ---------------------------------
  function setCluster(on) {
    clusterMode = on;
    els.graphClusterBtn.classList.toggle("active", on);
    els.graphClusterBtn.setAttribute("aria-pressed", String(on));
    if (!cy) return;
    var parents = {};
    cy.batch(function () {
      cy.nodes('[type = "account"], [type = "registration"]').forEach(function (n) {
        var cat = (n.data("data") || {}).category;
        var pid = cat ? "cat:" + cat : null;
        if (on && !pid) { n.move({ parent: null }); return; }
        if (on && !parents[pid]) {
          parents[pid] = true;
          cy.add({ group: "nodes", data: { id: pid, type: "catparent",
                   label: String(cat).toUpperCase(),
                   labelText: String(cat).toUpperCase() },
                   classes: "g-catparent" });
        }
        n.move({ parent: on ? pid : null });
      });
      if (!on) cy.nodes('[type = "catparent"]').remove();
    });
    runLayout();
  }

  // Re-run the current layout without refetching.
  function runLayout() {
    if (!cy) return;
    var lname = els.graphLayout.value;
    if (lname === "fcose" && !fcoseRegistered) lname = "cose";
    var opts = {
      name: lname, animate: true, animationDuration: 600,
      nodeRepulsion: 12000, idealEdgeLength: 100, gravity: 0.35,
      padding: 40,
      concentric: function (n) { return n.data("confidence") || 40; },
      levelWidth: function () { return 25; },
      roots: "#person", directed: false
    };
    cy.layout(opts).one("layoutstop", function () { cy.fit(undefined, 40); }).run();
  }

  els.graphLayout.addEventListener("change", runLayout);
  els.graphClusterBtn.addEventListener("click", function () {
    setCluster(!clusterMode);
  });

  // ---- changes-only filter ----------------------------------------------------
  els.graphChangesBtn.addEventListener("click", function () {
    changesOnly = !changesOnly;
    els.graphChangesBtn.classList.toggle("active", changesOnly);
    els.graphChangesBtn.setAttribute("aria-pressed", String(changesOnly));
    applyGraphFilters();
    if (changesOnly) {
      var interesting = cy.nodes(".is-new, .gone-node");
      if (interesting.nonempty()) {
        cy.animate({ fit: { eles: interesting.closedNeighborhood(), padding: 70 } },
                   { duration: 250 });
      }
    }
  });

  // extend visibility with the changes-only gate
  var _nodeVisibleBase = nodeVisible;
  nodeVisible = function (n) {
    if (changesOnly) {
      var dd = n.data();
      var isNew = (dd.data || {}).is_new, gone = (dd.data || {}).gone;
      if (!(isNew || gone || dd.type === "person")) return false;
    }
    return _nodeVisibleBase(n);
  };

  // ---- stats strip --------------------------------------------------------------
  function updateGraphStats() {
    if (!cy) { els.graphStats.textContent = ""; return; }
    var confirmed = 0, flagged = 0, fresh = 0, gone = 0;
    cy.nodes().forEach(function (n) {
      var v = (n.data("verification") || (n.data("data") || {}).verification);
      if (v === "confirmed") confirmed++;
      if (v === "likely_false_positive") flagged++;
      if ((n.data("data") || {}).is_new) fresh++;
      if ((n.data("data") || {}).gone) gone++;
    });
    var parts = [
      cy.nodes().length + "N",
      cy.edges().length + "E",
      confirmed + "✓",
      flagged ? flagged + "⚠" : null,
      fresh ? "+" + fresh + " new" : null,
      gone ? gone + " gone" : null
    ].filter(Boolean);
    els.graphStats.textContent = parts.join(" · ");
  }

  // ---- minimap --------------------------------------------------------------------
  var navigatorReady = false;
  function initNavigator() {
    if (navigatorReady || typeof cy.navigator !== "function") return;
    try {
      cy.navigator({ container: els.cyNav, viewLiveFramerate: 0 });
      navigatorReady = true;
      els.cyNav.style.display = "block";
    } catch (e) { /* never block the graph on a minimap */ }
  }

  // ---- exports: CSV + GraphML -------------------------------------------------------
  function download(name, mime, content) {
    var blob = new Blob([content], { type: mime });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  function csvCell(v) {
    if (v === null || v === undefined) return "";
    v = String(v);
    return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
  }

  els.graphCsvBtn.addEventListener("click", function () {
    if (!graphData) return;
    var rows = [["id", "type", "label", "site", "url", "confidence",
                 "verification", "category", "created_at", "is_new", "gone"]];
    graphData.nodes.forEach(function (n) {
      var d = n.data || {};
      rows.push([n.id, n.type, n.label, d.site || n.sublabel || "", n.url || "",
        n.confidence, d.verification || n.verification || "",
        d.category || "", n.created_at || "", d.is_new ? "yes" : "",
        d.gone ? "yes" : ""]);
    });
    graphData.edges.forEach(function (e) {
      rows.push([e.id, "edge", e.rationale || "", "", "",
        e.confidence, "", "", "", "", ""]);
    });
    download("signals-ops-graph.csv", "text/csv",
      rows.map(function (r) { return r.map(csvCell).join(","); }).join("\n"));
    toast("Graph exported as CSV", "success");
  });

  els.graphGraphmlBtn.addEventListener("click", function () {
    if (!graphData) return;
    var esc = function (s) {
      return String(s === null || s === undefined ? "" : s)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    };
    var keys = ["label", "type", "site", "url", "confidence",
                "verification", "category", "created_at"];
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n';
    keys.forEach(function (k) {
      xml += '  <key id="d_' + k + '" for="node" attr.name="' + k +
             '" attr.type="string"/>\n';
    });
    xml += '  <key id="d_conf" for="edge" attr.name="confidence" attr.type="double"/>\n' +
           '  <key id="d_rat" for="edge" attr.name="rationale" attr.type="string"/>\n' +
           '  <graph id="G" edgedefault="undirected">\n';
    graphData.nodes.forEach(function (n) {
      var d = n.data || {};
      xml += '    <node id="' + esc(n.id) + '">\n';
      var vals = { label: n.label, type: n.type, site: d.site || n.sublabel || "",
                   url: n.url || "", confidence: n.confidence,
                   verification: d.verification || n.verification || "",
                   category: d.category || "", created_at: n.created_at || "" };
      keys.forEach(function (k) {
        if (vals[k] !== "" && vals[k] !== null && vals[k] !== undefined) {
          xml += '      <data key="d_' + k + '">' + esc(vals[k]) + '</data>\n';
        }
      });
      xml += '    </node>\n';
    });
    graphData.edges.forEach(function (e) {
      xml += '    <edge source="' + esc(e.source) + '" target="' + esc(e.target) + '">\n' +
             '      <data key="d_conf">' + esc(e.confidence) + '</data>\n' +
             (e.rationale ? '      <data key="d_rat">' + esc(e.rationale) + '</data>\n' : "") +
             '    </edge>\n';
    });
    xml += '  </graph>\n</graphml>\n';
    download("signals-ops-graph.graphml", "application/xml", xml);
    toast("GraphML exported — imports into Gephi/yEd", "success");
  });

  // ---- fullscreen ---------------------------------------------------------------------
  els.graphFsBtn.addEventListener("click", function () {
    els.graphPanel.classList.toggle("fs");
    setTimeout(function () {
      if (cy) { cy.resize(); cy.fit(undefined, 40); }
    }, 80);
  });

  // ---- help ------------------------------------------------------------------------------
  els.graphHelpBtn.addEventListener("click", function () {
    els.graphHelp.hidden = !els.graphHelp.hidden;
  });

  // ---- keyboard shortcuts (ignored while typing) ------------------------------------------
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape") {
      if (!els.graphCtx.hidden) { hideGraphCtx(); return; }
      if (!els.graphHelp.hidden) { els.graphHelp.hidden = true; return; }
      if (els.graphPanel.classList.contains("fs")) {
        els.graphFsBtn.click();
        return;
      }
      exitEgo();
      return;
    }
    var tag = (ev.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") return;
    if (els.graphPanel.style.display !== "block") return;
    switch (ev.key.toLowerCase()) {
      case "f": if (cy) cy.fit(undefined, 40); break;
      case "l": els.graphLabelsBtn.click(); break;
      case "e": els.graphPngBtn.click(); break;
      case "s": ev.preventDefault(); els.graphSearch.focus(); break;
      case "c": setCluster(!clusterMode); break;
      case "1": case "2": case "3": case "4": {
        var chips = document.querySelectorAll(".gchip");
        var chip = chips[parseInt(ev.key, 10) - 1];
        if (chip) chip.click();
        break;
      }
    }
  });

  // The "Graph" action is now the promoted first-class Case graph workspace.
  // (renderGraph / the inline Cytoscape panel remain for the fallback path but
  // are no longer the primary surface.)
  els.graphBtn.addEventListener("click", function () {
    if (!currentInvId) { toast("No investigation selected", "error"); return; }
    switchTab("casegraph");
  });

  /* ==================== case graph (WebGL workspace) ==================== */
  // Increment 0 — substrate proof. Renders the EXISTING /graph payload with
  // sigma.js (WebGL) on a deterministic radial layout (BFS hops from the
  // person node). Reuses nodeColor()/nodeSize() so the SIGNALS OPS colour
  // discipline (green = verified only) carries over unchanged. Tiers, on-canvas
  // cards, correlation bonds and the full evidence trail arrive in later
  // increments. Fully additive: the inline Cytoscape panel above is untouched.
  var cgSigma = null;
  var cgData = null;   // last-rendered payload (for filter re-application)
  var cgEls = {
    stage: document.getElementById("cgStage"),
    canvas: document.getElementById("cgCanvas"),
    empty: document.getElementById("cgEmpty"),
    fallback: document.getElementById("cgFallback"),
    inspector: document.getElementById("cgInspector"),
    triage: document.getElementById("cgTriage"),
    cards: document.getElementById("cgCards"),
    hulls: document.getElementById("cgHulls"),
    search: document.getElementById("cgSearch"),
    fitBtn: document.getElementById("cgFitBtn"),
    resetBtn: document.getElementById("cgResetBtn"),
    csvBtn: document.getElementById("cgCsvBtn"),
    pngBtn: document.getElementById("cgPngBtn"),
    graphmlBtn: document.getElementById("cgGraphmlBtn"),
    changesBtn: document.getElementById("cgChangesBtn"),
    tlBar: document.getElementById("cgTimeline"),
    tlPlay: document.getElementById("cgTlPlay"),
    tlScrub: document.getElementById("cgTlScrub"),
    tlDate: document.getElementById("cgTlDate")
  };
  var cgChangesOnly = false;   // diff filter: show only new/gone since last scan
  var cgEgoSet = null;         // when set, isolate this neighbourhood (ego view)
  var cgTl = { dates: [], minT: 0, maxT: 1, playing: false, raf: null };
  var cgDepth = {};          // node id -> hops from the subject (for provenance)

  // Entity-card overlay state. Cards are pooled by node id and only mounted for
  // on-screen nodes, so panning a 500-node graph never floods the DOM.
  var cgNodeById = {};       // id -> raw payload node (rich fields for cards)
  var cgCardPool = {};       // id -> card element currently mounted
  var cgSelectedId = null;
  var CG_CARD_TYPES = { account: 1, email: 1, phone: 1 };
  var CG_CARD_W = 168, CG_CARD_H = 46, CG_CARD_MAX = 44;

  // Triage tiers — the reading order for an account. Colour keeps the SIGNALS
  // OPS discipline: green = verified (confirmed) only, amber = working lead,
  // grey = recessed noise, red = refuted. `rank` drives the radial band (the
  // confirmed core hugs the subject; refuted is flung to the rim) and `sizeK`
  // makes signal bigger than noise.
  var CG_TIER = {
    confirmed: { color: "#4cc38a", rank: 0, sizeK: 1.35, label: "Confirmed" },
    strong:    { color: "#e0a63d", rank: 1, sizeK: 1.12, label: "Strong" },
    weak:      { color: "#6c786c", rank: 2, sizeK: 0.82, label: "Weak" },
    refuted:   { color: "#f0615d", rank: 3, sizeK: 0.90, label: "Refuted" }
  };
  var CG_TIER_ORDER = ["confirmed", "strong", "weak", "refuted"];
  var cgTierVis = { confirmed: true, strong: true, weak: true, refuted: true };

  function cgNodeColor(n) {
    if (n.type === "account" && n.tier && CG_TIER[n.tier]) {
      return CG_TIER[n.tier].color;
    }
    return nodeColor(n);
  }
  function cgNodeSize(n) {
    var k = (n.type === "account" && n.tier && CG_TIER[n.tier])
      ? CG_TIER[n.tier].sizeK : 1;
    return Math.max(4, Math.round(nodeSize(n) * 0.32 * k));
  }

  // Single source of truth for node visibility — every active filter (tier,
  // changes-only, ego, timeline). The sigma reducer AND the DOM card/hull
  // overlays AND the fit routine all consult this so they never disagree.
  function cgNodeHidden(id, attrs) {
    if (attrs.cgType === "account" && attrs.cgTier && !cgTierVis[attrs.cgTier]) {
      return true;
    }
    if (cgChangesOnly && !attrs.cgNew && !attrs.cgGone &&
        attrs.cgType !== "person") {
      return true;
    }
    if (cgEgoSet && !cgEgoSet[id]) return true;
    if (cgTlActive() && attrs.cgCreated && attrs.cgCreated > cgTlCursor()) {
      return true;
    }
    return false;
  }

  // Resolve the UMD globals defensively — the browser build may expose the
  // constructor as a namespace member (Sigma.Sigma) or the default export.
  function cgLibs() {
    var G = window.graphology &&
      (window.graphology.Graph || window.graphology.default || window.graphology);
    var S = window.Sigma &&
      (window.Sigma.Sigma || window.Sigma.default || window.Sigma);
    return (typeof G === "function" && typeof S === "function")
      ? { Graph: G, Sigma: S } : null;
  }

  function cgShow(what) {
    if (!cgEls.stage) return;
    cgEls.empty.hidden = what !== "empty";
    cgEls.fallback.hidden = what !== "fallback";
    cgEls.canvas.style.display = what === "graph" ? "block" : "none";
  }

  function openCaseGraph() {
    if (!currentInvId) { cgShow("empty"); return; }
    if (!cgLibs()) { cgShow("fallback"); return; }
    fetch("/api/investigate/" + currentInvId + "/graph")
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { toast(data.error, "error"); cgShow("empty"); return; }
        cgRender(data);
      })
      .catch(function () {
        toast("Failed to load case graph", "error"); cgShow("empty");
      });
  }

  // Layout encodes triage: ACCOUNTS sit in radial bands by tier — confirmed
  // hugs the subject, refuted is flung to the rim — so signal reads inside,
  // noise outside. Structural nodes (person, handles, contacts, infra) keep a
  // BFS hop-distance placement so the scaffolding still makes sense.
  var CG_TIER_RADIUS = { confirmed: 250, strong: 440, weak: 660, refuted: 880 };

  function cgLayout(data) {
    var adj = {};
    data.nodes.forEach(function (n) { adj[n.id] = []; });
    data.edges.forEach(function (e) {
      if (adj[e.source] && adj[e.target]) {
        adj[e.source].push(e.target); adj[e.target].push(e.source);
      }
    });
    var root = adj.person ? "person" : (data.nodes[0] && data.nodes[0].id);
    var depth = {}, queue = [];
    if (root) { depth[root] = 0; queue.push(root); }
    for (var i = 0; i < queue.length; i++) {
      var cur = queue[i];
      adj[cur].forEach(function (nb) {
        if (depth[nb] === undefined) { depth[nb] = depth[cur] + 1; queue.push(nb); }
      });
    }
    var maxD = 0;
    Object.keys(depth).forEach(function (k) { if (depth[k] > maxD) maxD = depth[k]; });
    data.nodes.forEach(function (n) {
      if (depth[n.id] === undefined) depth[n.id] = maxD + 1;
    });
    cgDepth = depth;   // provenance: hops from the subject, for the inspector

    var pos = {};
    // Structural (non-account) nodes → hop-distance rings.
    var structural = data.nodes.filter(function (n) { return n.type !== "account"; });
    var byDepth = {};
    structural.forEach(function (n) {
      var d = depth[n.id]; (byDepth[d] = byDepth[d] || []).push(n.id);
    });
    Object.keys(byDepth).forEach(function (d) {
      var ids = byDepth[d], dn = Number(d), R = dn === 0 ? 0 : 120 + dn * 60;
      ids.forEach(function (id, idx) {
        if (dn === 0) { pos[id] = { x: 0, y: 0 }; return; }
        var ang = (idx / ids.length) * Math.PI * 2 + dn * 0.7;
        pos[id] = { x: Math.cos(ang) * R, y: Math.sin(ang) * R };
      });
    });
    // Account nodes → tier bands. A dense tier is spread across a ~90px-thick
    // band (radius jitter) so hundreds of candidates read as a band, not a
    // single overplotted ring.
    var byTier = {};
    data.nodes.forEach(function (n) {
      if (n.type !== "account") return;
      var t = (n.tier && CG_TIER_RADIUS[n.tier]) ? n.tier : "weak";
      (byTier[t] = byTier[t] || []).push(n.id);
    });
    CG_TIER_ORDER.forEach(function (t) {
      var ids = byTier[t] || [], base = CG_TIER_RADIUS[t], n = ids.length;
      ids.forEach(function (id, idx) {
        var ang = (idx / Math.max(1, n)) * Math.PI * 2 + CG_TIER[t].rank * 0.6;
        var r = base + (idx % 7) * 14;
        pos[id] = { x: Math.cos(ang) * r, y: Math.sin(ang) * r };
      });
    });
    return pos;
  }

  function cgRender(data) {
    var libs = cgLibs();
    if (!libs) { cgShow("fallback"); return; }
    cgData = data;
    cgNodeById = {};
    data.nodes.forEach(function (n) { cgNodeById[n.id] = n; });
    cgClearCards();
    cgSelectedId = null;
    // Fresh case → clear any tier filter and camera framing carried over from
    // the previous one.
    cgTierVis = { confirmed: true, strong: true, weak: true, refuted: true };
    cgShow("graph");
    if (cgSigma) { try { cgSigma.setCustomBBox(null); } catch (e) {} cgSigma.kill(); cgSigma = null; }
    var g = new libs.Graph();
    var pos = cgLayout(data);
    var hasDiff = false;
    data.nodes.forEach(function (n) {
      var p = pos[n.id] || { x: 0, y: 0 };
      var d = n.data || {};
      if (d.is_new || d.gone) hasDiff = true;
      var created = n.created_at ? Date.parse(n.created_at) : NaN;
      g.addNode(n.id, {
        x: p.x, y: p.y,
        size: cgNodeSize(n),
        color: d.gone ? "#e05a4e" : cgNodeColor(n),
        label: n.label || n.id,
        cgType: n.type,
        cgTier: n.type === "account" ? (n.tier || "weak") : null,
        cgNew: !!d.is_new,
        cgGone: !!d.gone,
        cgCreated: isNaN(created) ? null : created
      });
    });
    // Run-diff toolbar affordance: only offered when this scan diffs a baseline.
    if (cgEls.changesBtn) {
      cgEls.changesBtn.hidden = !hasDiff;
      if (!hasDiff) {
        cgChangesOnly = false;
        cgEls.changesBtn.setAttribute("aria-pressed", "false");
        cgEls.changesBtn.classList.remove("active");
      }
    }
    data.edges.forEach(function (e) {
      if (!g.hasNode(e.source) || !g.hasNode(e.target)) return;
      if (e.source === e.target || g.hasEdge(e.source, e.target)) return;
      // Correlation bonds (same-avatar/name/bio) are the identity backbone, so
      // they're elevated: thick amber (the working accent, like handle pivots).
      // Everything else is a neutral grey spoke whose lightness — never hue —
      // encodes confidence, keeping green reserved for verified signals.
      var isCorr = e.kind === "correlation";
      try {
        g.addEdge(e.source, e.target, {
          size: isCorr ? 2.6 : Math.max(0.6, (e.confidence || 40) / 42),
          color: isCorr ? "#e0a63d"
            : ((e.confidence || 0) >= 60 ? "#33402f" : "#20271f"),
          cgKind: e.kind || "link"
        });
      } catch (err) { /* skip parallel/invalid edge */ }
    });
    cgUpdateTriage(data);
    cgSetupTimeline(data);
    // Defer construction one tick so the freshly-activated panel has laid out
    // (the container needs real dimensions). setTimeout — not rAF — because
    // rAF is suspended while the document is hidden (a backgrounded tab would
    // otherwise leave the graph unbuilt until refocused).
    setTimeout(function () {
      cgSigma = new libs.Sigma(g, cgEls.canvas, {
        renderLabels: true,
        labelColor: { color: "#c9d3c7" },
        labelSize: 11,
        labelFont: "'JetBrains Mono', ui-monospace, monospace",
        labelWeight: "500",
        defaultEdgeColor: "#20271f",
        minCameraRatio: 0.15,
        maxCameraRatio: 8
      });
      cgSigma.on("clickNode", function (ev) {
        cgSelectedId = ev.node;
        cgInspect(ev.node, data);
        cgSyncOverlays();
      });
      cgSigma.on("clickStage", function () {
        cgSelectedId = null;
        if (cgEgoSet) { cgExitEgo(); }
        cgEls.inspector.innerHTML =
          '<div class="cg-insp-empty">Select an entity to see its evidence trail.</div>';
        cgSyncOverlays();
      });
      // Keep the DOM cards + hull canvas glued to the WebGL camera every frame.
      cgSigma.on("afterRender", cgSyncOverlays);
      // Tier filter: hide accounts whose tier chip is off. Hiding a node also
      // hides its labels and connected edges, so toggling "Weak" off collapses
      // the noise ring and leaves the confirmed/strong core.
      cgSigma.setSetting("nodeReducer", function (node, attrs) {
        if (cgNodeHidden(node, attrs)) {
          return Object.assign({}, attrs, { hidden: true });
        }
        // New nodes get a highlight ring (sigma's base circle has no border).
        if (attrs.cgNew) {
          return Object.assign({}, attrs, { highlighted: true });
        }
        return attrs;
      });
      cgSigma.setSetting("edgeReducer", function (edge, attrs) {
        if (cgEgoSet) {
          var ext = cgSigma.getGraph().extremities(edge);
          if (!cgEgoSet[ext[0]] || !cgEgoSet[ext[1]]) {
            return Object.assign({}, attrs, { hidden: true });
          }
        }
        return attrs;
      });
      // Double-click a node → ego view: isolate its neighbourhood.
      cgSigma.on("doubleClickNode", function (ev) {
        if (ev.event && ev.event.original) ev.event.original.preventDefault();
        cgFocusEgo(ev.node);
      });
      cgSigma.refresh();
      cgSigma.getCamera().animatedReset({ duration: 300 });
      cgSyncOverlays();   // don't wait a render frame for the first overlays
    }, 0);
  }

  // Toggle a tier's visibility and refresh (the reducer does the hiding).
  function cgToggleTier(tier) {
    cgTierVis[tier] = !cgTierVis[tier];
    if (cgSigma) { cgFitVisible(); cgSigma.refresh(); cgSyncOverlays(); }
    if (cgData) cgUpdateTriage(cgData);
  }

  // Reframe the camera onto whatever tiers are still shown, so hiding the noise
  // zooms into the survivors (and their cards spread out) instead of leaving
  // them tiny in the middle. Uses sigma's custom bbox = the visible extent.
  function cgFitVisible() {
    if (!cgSigma) return;
    var g = cgSigma.getGraph();
    var minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity, any = false;
    g.forEachNode(function (id, a) {
      if (cgNodeHidden(id, a)) return;
      any = true;
      if (a.x < minX) minX = a.x;
      if (a.x > maxX) maxX = a.x;
      if (a.y < minY) minY = a.y;
      if (a.y > maxY) maxY = a.y;
    });
    if (!any) return;
    var padX = (maxX - minX) * 0.12 + 60, padY = (maxY - minY) * 0.12 + 60;
    try {
      cgSigma.setCustomBBox({ x: [minX - padX, maxX + padX], y: [minY - padY, maxY + padY] });
      cgSigma.getCamera().animatedReset({ duration: 350 });
    } catch (e) { /* sigma version without custom bbox — skip the reframe */ }
  }

  /* ---- entity cards: DOM overlay synced to sigma's camera --------------- */
  function cgClearCards() {
    Object.keys(cgCardPool).forEach(function (id) { cgCardPool[id].remove(); });
    cgCardPool = {};
    if (cgEls.cards) cgEls.cards.innerHTML = "";
    if (cgEls.hulls) {
      var ctx = cgEls.hulls.getContext("2d");
      ctx.clearRect(0, 0, cgEls.hulls.width, cgEls.hulls.height);
    }
  }

  function cgBuildCard(node) {
    var tier = (node.type === "account" && node.tier) ? CG_TIER[node.tier] : null;
    var accent = tier ? tier.color : (NODE_COLORS[node.type] || "#8b968a");
    var el = document.createElement("div");
    el.className = "cg-card";
    if (node.id) el.dataset.nid = node.id;

    var av = document.createElement("div");
    av.className = "cg-card-av";
    if (node.avatar) {
      av.style.backgroundImage = 'url("' + node.avatar + '")';
    } else {
      av.textContent = (node.label || node.id || "?").slice(0, 1).toUpperCase();
      av.style.color = accent;
    }
    el.appendChild(av);

    var main = document.createElement("div");
    main.className = "cg-card-main";
    var handle = document.createElement("div");
    handle.className = "cg-card-handle";
    handle.appendChild(document.createTextNode(node.label || node.id));
    var pip = document.createElement("span");
    pip.className = "cg-card-pip";
    pip.style.background = accent;
    handle.appendChild(pip);
    main.appendChild(handle);

    var site = document.createElement("div");
    site.className = "cg-card-site";
    site.textContent = (node.sublabel || node.type) +
      (tier ? " · " + tier.label : "");
    main.appendChild(site);

    if (node.confidence != null) {
      var bar = document.createElement("div");
      bar.className = "cg-card-bar";
      var fill = document.createElement("i");
      fill.style.width = Math.max(4, Math.min(100, node.confidence)) + "%";
      fill.style.background = accent;
      bar.appendChild(fill);
      main.appendChild(bar);
    }
    el.appendChild(main);
    return el;
  }

  // Runs every frame: mount cards for on-screen card-type nodes, but only when
  // few enough are visible (i.e. zoomed in) so it reads as Gotham cards, not a
  // wall of boxes. The selected node always keeps its card. When cards are
  // showing, sigma's own labels step aside to avoid double text.
  function cgSyncCards() {
    if (!cgSigma || !cgEls.cards) return;
    var g = cgSigma.getGraph();
    var W = cgEls.canvas.offsetWidth, H = cgEls.canvas.offsetHeight;
    var onscreen = [];
    g.forEachNode(function (id, attrs) {
      if (!CG_CARD_TYPES[attrs.cgType]) return;
      // Mirror every reducer filter — it hides at render time without touching
      // the graph attribute, so the overlay must re-check the same predicate.
      if (cgNodeHidden(id, attrs)) return;
      var vp = cgSigma.graphToViewport({ x: attrs.x, y: attrs.y });
      if (vp.x < -CG_CARD_W || vp.x > W + CG_CARD_W ||
          vp.y < -CG_CARD_H || vp.y > H + CG_CARD_H) return;
      onscreen.push({ id: id, vp: vp });
    });
    var useCards = onscreen.length > 0 && onscreen.length <= CG_CARD_MAX;
    var show = {};
    if (useCards) { onscreen.forEach(function (e) { show[e.id] = e.vp; }); }
    if (cgSelectedId && g.hasNode(cgSelectedId)) {
      var a = g.getNodeAttributes(cgSelectedId);
      if (!cgNodeHidden(cgSelectedId, a)) {
        show[cgSelectedId] = cgSigma.graphToViewport({ x: a.x, y: a.y });
      }
    }
    // sigma labels off while cards carry the text; back on when zoomed out.
    var wantLabels = !useCards;
    if (cgSigma.getSetting("renderLabels") !== wantLabels) {
      cgSigma.setSetting("renderLabels", wantLabels);
    }
    Object.keys(cgCardPool).forEach(function (id) {
      if (!show[id]) { cgCardPool[id].remove(); delete cgCardPool[id]; }
    });
    Object.keys(show).forEach(function (id) {
      var el = cgCardPool[id];
      if (!el) {
        el = cgBuildCard(cgNodeById[id] || { id: id });
        cgEls.cards.appendChild(el);
        cgCardPool[id] = el;
      }
      var vp = show[id];
      el.style.transform = "translate(" + Math.round(vp.x + 12) + "px," +
        Math.round(vp.y - CG_CARD_H / 2) + "px)";
      el.classList.toggle("sel", id === cgSelectedId);
    });
  }

  function cgSyncOverlays() { cgSyncHulls(); cgSyncCards(); }

  // Convex hull (monotone chain) of a small point set, for same-person hulls.
  function cgHull(points) {
    if (points.length < 3) return points.slice();
    var pts = points.slice().sort(function (a, b) {
      return a.x === b.x ? a.y - b.y : a.x - b.x;
    });
    function cross(o, a, b) {
      return (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
    }
    var lower = [];
    for (var i = 0; i < pts.length; i++) {
      while (lower.length >= 2 &&
             cross(lower[lower.length - 2], lower[lower.length - 1], pts[i]) <= 0)
        lower.pop();
      lower.push(pts[i]);
    }
    var upper = [];
    for (var j = pts.length - 1; j >= 0; j--) {
      while (upper.length >= 2 &&
             cross(upper[upper.length - 2], upper[upper.length - 1], pts[j]) <= 0)
        upper.pop();
      upper.push(pts[j]);
    }
    lower.pop(); upper.pop();
    return lower.concat(upper);
  }

  // Draw a translucent amber shape around each correlation cluster's visible
  // members — the visual "these accounts are one person". A 2-member cluster is
  // a rounded capsule; 3+ is an expanded convex hull.
  function cgSyncHulls() {
    if (!cgSigma || !cgEls.hulls) return;
    var cv = cgEls.hulls;
    var W = cgEls.canvas.offsetWidth, H = cgEls.canvas.offsetHeight;
    if (cv.width !== W || cv.height !== H) { cv.width = W; cv.height = H; }
    var ctx = cv.getContext("2d");
    ctx.clearRect(0, 0, W, H);
    if (!cgData) return;
    var g = cgSigma.getGraph();
    var clusters = {};
    g.forEachNode(function (id, a) {
      var node = cgNodeById[id];
      if (!node || !node.cluster) return;
      if (cgNodeHidden(id, a)) return;
      var vp = cgSigma.graphToViewport({ x: a.x, y: a.y });
      (clusters[node.cluster] = clusters[node.cluster] || []).push(vp);
    });
    var PAD = 28;
    Object.keys(clusters).forEach(function (cid) {
      var pts = clusters[cid];
      if (pts.length < 2) return;
      ctx.save();
      ctx.fillStyle = "rgba(224,166,61,0.07)";
      ctx.strokeStyle = "rgba(224,166,61,0.34)";
      ctx.lineWidth = 1.25;
      ctx.lineJoin = "round";
      if (pts.length === 2) {
        // capsule: a thick round-capped stroke between the two points
        ctx.strokeStyle = "rgba(224,166,61,0.10)";
        ctx.lineCap = "round";
        ctx.lineWidth = PAD * 2;
        ctx.beginPath();
        ctx.moveTo(pts[0].x, pts[0].y);
        ctx.lineTo(pts[1].x, pts[1].y);
        ctx.stroke();
        ctx.strokeStyle = "rgba(224,166,61,0.34)";
        ctx.lineWidth = 1.25;
        ctx.stroke();
      } else {
        var hull = cgHull(pts);
        var cx = 0, cy = 0;
        hull.forEach(function (p) { cx += p.x; cy += p.y; });
        cx /= hull.length; cy /= hull.length;
        ctx.beginPath();
        hull.forEach(function (p, i) {
          var dx = p.x - cx, dy = p.y - cy;
          var len = Math.sqrt(dx * dx + dy * dy) || 1;
          var ex = p.x + (dx / len) * PAD, ey = p.y + (dy / len) * PAD;
          if (i === 0) ctx.moveTo(ex, ey); else ctx.lineTo(ex, ey);
        });
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      }
      ctx.restore();
    });
  }

  // Triage bar: one clickable chip per tier (count + colour). Clicking a chip
  // hides/shows that tier on the canvas so an analyst can collapse the noise
  // and read the confirmed/strong core in seconds.
  function cgUpdateTriage(data) {
    if (!cgEls.triage) return;
    var counts = { confirmed: 0, strong: 0, weak: 0, refuted: 0 };
    var fresh = 0, gone = 0;
    data.nodes.forEach(function (n) {
      if (n.type === "account") {
        var t = (n.tier && counts[n.tier] !== undefined) ? n.tier : "weak";
        counts[t]++;
      }
      if ((n.data || {}).is_new) fresh++;
      if ((n.data || {}).gone) gone++;
    });
    cgEls.triage.innerHTML = "";
    var lead = document.createElement("span");
    lead.className = "cg-triage-hint";
    lead.textContent = "Triage";
    cgEls.triage.appendChild(lead);

    CG_TIER_ORDER.forEach(function (t) {
      var chip = document.createElement("button");
      chip.type = "button";
      chip.className = "cg-tier-chip" + (cgTierVis[t] ? " on" : " off");
      chip.setAttribute("aria-pressed", String(cgTierVis[t]));
      chip.title = (cgTierVis[t] ? "Hide" : "Show") + " " + CG_TIER[t].label + " accounts";
      var dot = document.createElement("span");
      dot.className = "cg-tier-dot";
      dot.style.background = CG_TIER[t].color;
      chip.appendChild(dot);
      chip.appendChild(document.createTextNode(
        CG_TIER[t].label + " " + counts[t]));
      chip.addEventListener("click", function () { cgToggleTier(t); });
      cgEls.triage.appendChild(chip);
    });

    if (fresh || gone) {
      var diff = document.createElement("span");
      diff.className = "cg-triage-diff";
      diff.textContent = (fresh ? "+" + fresh + " new" : "") +
        (fresh && gone ? " · " : "") + (gone ? gone + " gone" : "");
      cgEls.triage.appendChild(diff);
    }
  }

  function cgInspect(id, data) {
    var node = null;
    for (var i = 0; i < data.nodes.length; i++) {
      if (data.nodes[i].id === id) { node = data.nodes[i]; break; }
    }
    if (!node) return;
    var d = node.data || {};
    var box = document.createElement("div");
    var h = document.createElement("div");
    h.className = "cg-insp-title";
    h.textContent = node.label || id;
    box.appendChild(h);
    var t = document.createElement("div");
    t.className = "cg-insp-type";
    t.textContent = node.type + (node.sublabel ? " · " + node.sublabel : "");
    box.appendChild(t);
    // Tier badge (accounts only) — the headline triage verdict.
    if (node.type === "account" && node.tier && CG_TIER[node.tier]) {
      var badge = document.createElement("span");
      badge.className = "cg-tier-badge";
      badge.textContent = CG_TIER[node.tier].label;
      badge.style.color = CG_TIER[node.tier].color;
      badge.style.borderColor = CG_TIER[node.tier].color;
      box.appendChild(badge);
    }

    function row(k, v, link) {
      if (v === null || v === undefined || v === "") return;
      var r = document.createElement("div");
      r.className = "cg-insp-row";
      var kk = document.createElement("div");
      kk.className = "k"; kk.textContent = k;
      var vv = document.createElement("div");
      vv.className = "v";
      if (link) {
        var a = document.createElement("a");
        a.href = v; a.target = "_blank"; a.rel = "noopener noreferrer";
        a.textContent = v; vv.appendChild(a);
      } else {
        vv.textContent = typeof v === "object" ? JSON.stringify(v) : String(v);
      }
      r.appendChild(kk); r.appendChild(vv);
      box.appendChild(r);
    }
    row("confidence", node.confidence != null ? node.confidence + "%" : null);
    row("verification", node.verification || d.verification);
    row("category", d.category);
    row("engines", (node.engines || []).join(", "));
    row("created", node.created_at ? String(node.created_at).slice(0, 10) : null);
    if (d.is_new) row("status", "new since last scan");
    if (d.gone) row("status", "gone since last scan");

    // ---- evidence trail: how this ties to the subject, in plain language ----
    function section(title) {
      var s = document.createElement("div");
      s.className = "cg-insp-section";
      var st = document.createElement("div");
      st.className = "cg-insp-sectitle";
      st.textContent = title;
      s.appendChild(st);
      box.appendChild(s);
      return s;
    }
    function line(sec, text, accent) {
      var l = document.createElement("div");
      l.className = "cg-insp-line";
      if (accent) l.style.borderLeftColor = accent;
      l.textContent = text;
      sec.appendChild(l);
    }
    function pct(x) { return Math.round(x * 100) + "%"; }
    function otherLabel(oid) {
      var o = cgNodeById[oid];
      if (!o) return oid;
      return (o.label || oid) + (o.sublabel ? " on " + o.sublabel : "");
    }

    // Same-person evidence from correlation edges touching this node.
    var corr = (data.edges || []).filter(function (e) {
      return e.kind === "correlation" && (e.source === id || e.target === id);
    });
    if (corr.length) {
      var sec = section("Same-person evidence");
      corr.forEach(function (e) {
        var oid = e.source === id ? e.target : e.source;
        var ev = e.evidence || {};
        var said = false;
        if (ev.avatar_distance != null) {
          line(sec, "Same avatar as " + otherLabel(oid) +
            " (hash distance " + ev.avatar_distance + ")", "#e0a63d"); said = true;
        }
        if (ev.name_sim != null) {
          line(sec, "Display name " + pct(ev.name_sim) + " similar to " +
            otherLabel(oid), "#e0a63d"); said = true;
        }
        if (ev.bio_overlap != null) {
          line(sec, "Bio shares " + pct(ev.bio_overlap) + " of words with " +
            otherLabel(oid), "#e0a63d"); said = true;
        }
        if (!said) {
          line(sec, (e.rationale || "correlated") + " — " + otherLabel(oid),
            "#e0a63d");
        }
      });
      if (node.cluster) {
        var members = data.nodes.filter(function (n) {
          return n.cluster === node.cluster;
        }).length;
        if (members > 1) line(sec, "Part of a " + members +
          "-account identity cluster");
      }
    }

    // Provenance: how far this sits from the subject, and how it was derived.
    var prov = section("Provenance");
    var hops = cgDepth[id];
    if (hops === 0) {
      line(prov, "This is the subject");
    } else if (hops != null && hops < 900) {
      line(prov, hops + (hops === 1 ? " hop" : " hops") + " from the subject");
    } else if (hops != null) {
      line(prov, "Not connected to the subject in this graph");
    }
    if (d.source === "name") line(prov, "Name-derived candidate (speculative)");
    else if (d.source === "variant") line(prov, "Handle variant of the subject");
    else if (node.type === "account") line(prov, "Discovered by username match");
    if ((node.engines || []).length >= 2) {
      line(prov, "Corroborated by " + node.engines.length + " engines: " +
        node.engines.join(", "));
    }

    if (node.url) {
      var link = section("Profile");
      var a = document.createElement("a");
      a.className = "cg-insp-link";
      a.href = node.url; a.target = "_blank"; a.rel = "noopener noreferrer";
      a.textContent = node.url;
      link.appendChild(a);
    }

    // Investigator note (persisted per investigation, shared with the inline
    // graph's notes via the same localStorage key).
    var nsec = section("Note");
    var notes = loadNotes();
    var ta = document.createElement("textarea");
    ta.className = "cg-insp-note";
    ta.rows = 3;
    ta.value = notes[id] || "";
    ta.placeholder = "Investigator note for this entity…";
    var save = document.createElement("button");
    save.type = "button";
    save.className = "btn btn-ghost btn-sm";
    save.textContent = "Save note";
    save.addEventListener("click", function () {
      saveNote(id, ta.value);
      toast(ta.value.trim() ? "Note saved" : "Note cleared", "success");
    });
    nsec.appendChild(ta);
    nsec.appendChild(save);

    cgEls.inspector.innerHTML = "";
    cgEls.inspector.appendChild(box);
  }

  window.addEventListener("resize", function () {
    if (cgSigma && tabEls.casegraph && tabEls.casegraph.classList.contains("active")) {
      cgSigma.refresh();
    }
  });

  // Escape exits the ego view (when the Case graph is active and not typing).
  document.addEventListener("keydown", function (ev) {
    if (ev.key !== "Escape" || !cgEgoSet) return;
    if (!tabEls.casegraph || !tabEls.casegraph.classList.contains("active")) return;
    var tag = (ev.target.tagName || "").toLowerCase();
    if (tag === "input" || tag === "textarea") return;
    cgExitEgo();
  });

  /* ---- case-graph toolbar: search / fit / reset / export ---------------- */
  function cgSearchVisible(n) {
    return !(n.type === "account" && n.tier && !cgTierVis[n.tier]);
  }
  function cgSearchJump() {
    if (!cgSigma || !cgData) return;
    var q = (cgEls.search.value || "").trim().toLowerCase();
    if (!q) return;
    var match = null;
    for (var i = 0; i < cgData.nodes.length; i++) {
      var n = cgData.nodes[i];
      if (!cgSearchVisible(n)) continue;
      var hay = ((n.label || "") + " " + (n.sublabel || "") + " " +
        ((n.data || {}).category || "")).toLowerCase();
      if (hay.indexOf(q) !== -1) { match = n; break; }
    }
    if (!match) { toast('No entity matches “' + q + '”', "error"); return; }
    cgSelectedId = match.id;
    cgInspect(match.id, cgData);
    try {
      var dd = cgSigma.getNodeDisplayData(match.id);
      if (dd) {
        cgSigma.getCamera().animate(
          { x: dd.x, y: dd.y, ratio: Math.min(cgSigma.getCamera().ratio, 0.4) },
          { duration: 400 });
      }
    } catch (e) { /* camera helper unavailable — selection still stands */ }
    cgSyncOverlays();
  }
  if (cgEls.search) {
    cgEls.search.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter") cgSearchJump();
      else if (ev.key === "Escape") { cgEls.search.value = ""; cgEls.search.blur(); }
    });
  }

  function cgFit() {
    if (!cgSigma) return;
    try { cgSigma.setCustomBBox(null); } catch (e) {}
    cgSigma.refresh();
    cgSigma.getCamera().animatedReset({ duration: 350 });
    cgSyncOverlays();
  }
  if (cgEls.fitBtn) cgEls.fitBtn.addEventListener("click", cgFit);

  if (cgEls.resetBtn) cgEls.resetBtn.addEventListener("click", function () {
    cgTierVis = { confirmed: true, strong: true, weak: true, refuted: true };
    cgFit();
    if (cgData) cgUpdateTriage(cgData);
  });

  if (cgEls.csvBtn) cgEls.csvBtn.addEventListener("click", function () {
    if (!cgData) { toast("Nothing to export", "error"); return; }
    function cell(v) {
      if (v === null || v === undefined) return "";
      v = String(v);
      return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
    }
    var rows = [["id", "type", "label", "site", "url", "confidence", "tier",
                 "verification", "category", "cluster", "created_at"]];
    cgData.nodes.forEach(function (n) {
      var d = n.data || {};
      rows.push([n.id, n.type, n.label, d.site || n.sublabel || "", n.url || "",
        n.confidence, n.tier || "", n.verification || d.verification || "",
        d.category || "", n.cluster || "", n.created_at || ""]);
    });
    cgData.edges.forEach(function (e) {
      rows.push([e.id, "edge", e.rationale || "", "", "", e.confidence,
        e.kind || "", "", "", "", ""]);
    });
    var csv = rows.map(function (r) { return r.map(cell).join(","); }).join("\n");
    var blob = new Blob([csv], { type: "text/csv" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "case-graph.csv";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    toast("Case graph exported as CSV", "success");
  });

  // ---- ego view (double-click) ------------------------------------------
  function cgFitToNodes(ids) {
    if (!cgSigma || !ids.length) return;
    var g = cgSigma.getGraph();
    var minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity, any = false;
    ids.forEach(function (id) {
      if (!g.hasNode(id)) return;
      var a = g.getNodeAttributes(id); any = true;
      if (a.x < minX) minX = a.x; if (a.x > maxX) maxX = a.x;
      if (a.y < minY) minY = a.y; if (a.y > maxY) maxY = a.y;
    });
    if (!any) return;
    var padX = (maxX - minX) * 0.15 + 80, padY = (maxY - minY) * 0.15 + 80;
    try {
      cgSigma.setCustomBBox({ x: [minX - padX, maxX + padX], y: [minY - padY, maxY + padY] });
      cgSigma.getCamera().animatedReset({ duration: 350 });
    } catch (e) {}
  }
  function cgFocusEgo(nodeId) {
    if (!cgSigma) return;
    var g = cgSigma.getGraph();
    if (!g.hasNode(nodeId)) return;
    var set = {}; set[nodeId] = true;
    g.forEachNeighbor(nodeId, function (nb) { set[nb] = true; });
    cgEgoSet = set;
    cgSelectedId = nodeId;
    cgInspect(nodeId, cgData);
    cgFitToNodes(Object.keys(set));
    cgSigma.refresh();
    cgSyncOverlays();
  }
  function cgExitEgo() {
    cgEgoSet = null;
    if (cgSigma) cgFit();
  }

  // ---- timeline scrubber (grow the graph by account creation date) ------
  function cgTlActive() {
    return cgEls.tlBar && !cgEls.tlBar.hidden &&
      (cgTl.playing || parseInt(cgEls.tlScrub.value, 10) < 1000);
  }
  function cgTlCursor() {
    var v = parseInt(cgEls.tlScrub.value, 10);
    return cgTl.minT + (cgTl.maxT - cgTl.minT) * (v / 1000);
  }
  function cgSetupTimeline(data) {
    if (!cgEls.tlBar) return;
    cgStopTlPlay();
    cgTl.dates = data.nodes
      .map(function (n) { return n.created_at ? Date.parse(n.created_at) : NaN; })
      .filter(function (t) { return !isNaN(t); })
      .sort(function (a, b) { return a - b; });
    // Fewer than three dated sources is not a story — hide the control.
    cgEls.tlBar.hidden = cgTl.dates.length < 3;
    if (cgEls.tlBar.hidden) return;
    cgTl.minT = cgTl.dates[0];
    cgTl.maxT = Date.now();
    cgEls.tlScrub.value = "1000";
    cgUpdateTlReadout();
  }
  function cgUpdateTlReadout() {
    if (!cgEls.tlBar || cgEls.tlBar.hidden) return;
    var v = parseInt(cgEls.tlScrub.value, 10);
    cgEls.tlDate.textContent = v >= 1000 ? "now"
      : new Date(cgTlCursor()).toISOString().slice(0, 7);
    cgEls.tlPlay.innerHTML = cgTl.playing ? "&#10074;&#10074;" : "&#9654;";
  }
  function cgStopTlPlay() {
    cgTl.playing = false;
    if (cgTl.raf) cancelAnimationFrame(cgTl.raf);
    cgTl.raf = null;
    cgUpdateTlReadout();
  }
  function cgApplyTimeline() {
    if (cgSigma) cgSigma.refresh();
    cgSyncOverlays();
    cgUpdateTlReadout();
  }
  if (cgEls.tlScrub) cgEls.tlScrub.addEventListener("input", function () {
    cgStopTlPlay();
    cgApplyTimeline();
  });
  if (cgEls.tlPlay) cgEls.tlPlay.addEventListener("click", function () {
    if (cgTl.playing) { cgStopTlPlay(); return; }
    cgTl.playing = true;
    var start = null, dur = 12000, from = parseInt(cgEls.tlScrub.value, 10);
    if (from >= 1000) from = 0;
    function step(ts) {
      if (!cgTl.playing) return;
      if (!start) start = ts;
      var k = Math.min(1000, from + ((ts - start) / dur) * 1000);
      cgEls.tlScrub.value = String(Math.round(k));
      cgApplyTimeline();
      if (k >= 1000) { cgStopTlPlay(); return; }
      cgTl.raf = requestAnimationFrame(step);
    }
    cgTl.raf = requestAnimationFrame(step);
  });

  // ---- changes-only (run diff) filter -----------------------------------
  if (cgEls.changesBtn) cgEls.changesBtn.addEventListener("click", function () {
    cgChangesOnly = !cgChangesOnly;
    cgEls.changesBtn.classList.toggle("active", cgChangesOnly);
    cgEls.changesBtn.setAttribute("aria-pressed", String(cgChangesOnly));
    if (cgSigma) { cgFitVisible(); cgSigma.refresh(); cgSyncOverlays(); }
  });

  // ---- PNG export (composite the WebGL + hull layers) -------------------
  if (cgEls.pngBtn) cgEls.pngBtn.addEventListener("click", function () {
    if (!cgSigma) { toast("Nothing to export", "error"); return; }
    try {
      cgSigma.refresh();
      var W = cgEls.canvas.offsetWidth, H = cgEls.canvas.offsetHeight;
      var out = document.createElement("canvas");
      out.width = W; out.height = H;
      var ctx = out.getContext("2d");
      ctx.fillStyle = "#0a0c0a"; ctx.fillRect(0, 0, W, H);
      cgEls.canvas.querySelectorAll("canvas").forEach(function (c) {
        try { ctx.drawImage(c, 0, 0, W, H); } catch (e) {}
      });
      if (cgEls.hulls) { try { ctx.drawImage(cgEls.hulls, 0, 0, W, H); } catch (e) {} }
      var url = out.toDataURL("image/png");
      var a = document.createElement("a");
      a.href = url; a.download = "case-graph.png";
      document.body.appendChild(a); a.click(); a.remove();
      toast("Case graph exported as PNG", "success");
    } catch (e) { toast("PNG export failed", "error"); }
  });

  // ---- GraphML export (imports into Gephi/yEd) --------------------------
  if (cgEls.graphmlBtn) cgEls.graphmlBtn.addEventListener("click", function () {
    if (!cgData) { toast("Nothing to export", "error"); return; }
    var esc = function (s) {
      return String(s === null || s === undefined ? "" : s)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    };
    var keys = ["label", "type", "site", "url", "confidence", "tier",
                "verification", "category", "cluster", "created_at"];
    var xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
      '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n';
    keys.forEach(function (k) {
      xml += '  <key id="d_' + k + '" for="node" attr.name="' + k +
             '" attr.type="string"/>\n';
    });
    xml += '  <key id="d_conf" for="edge" attr.name="confidence" attr.type="double"/>\n' +
           '  <key id="d_kind" for="edge" attr.name="kind" attr.type="string"/>\n' +
           '  <key id="d_rat" for="edge" attr.name="rationale" attr.type="string"/>\n' +
           '  <graph id="G" edgedefault="undirected">\n';
    cgData.nodes.forEach(function (n) {
      var d = n.data || {};
      var vals = { label: n.label, type: n.type, site: d.site || n.sublabel || "",
                   url: n.url || "", confidence: n.confidence, tier: n.tier || "",
                   verification: n.verification || d.verification || "",
                   category: d.category || "", cluster: n.cluster || "",
                   created_at: n.created_at || "" };
      xml += '    <node id="' + esc(n.id) + '">\n';
      keys.forEach(function (k) {
        if (vals[k] !== "" && vals[k] !== null && vals[k] !== undefined) {
          xml += '      <data key="d_' + k + '">' + esc(vals[k]) + '</data>\n';
        }
      });
      xml += '    </node>\n';
    });
    cgData.edges.forEach(function (e) {
      xml += '    <edge source="' + esc(e.source) + '" target="' + esc(e.target) + '">\n' +
             '      <data key="d_conf">' + esc(e.confidence) + '</data>\n' +
             '      <data key="d_kind">' + esc(e.kind || "link") + '</data>\n' +
             (e.rationale ? '      <data key="d_rat">' + esc(e.rationale) + '</data>\n' : "") +
             '    </edge>\n';
    });
    xml += '  </graph>\n</graphml>\n';
    var blob = new Blob([xml], { type: "application/xml" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "case-graph.graphml";
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    toast("GraphML exported — imports into Gephi/yEd", "success");
  });

  /* ============================ export ============================ */
  function download(filename, text, mime) {
    var blob = new Blob([text], { type: mime });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  els.csvBtn.addEventListener("click", function () {
    if (!currentRun.length) { toast("Nothing to export", "error"); return; }
    var lines = ["username,site,url,verdict,confidence,created_at,last_activity,engines,source,variant_of,from_name,candidate,display_name,bio"];
    currentRun.forEach(function (r) {
      lines.push([r.username, r.site, r.url,
                  (r.verification || "unverified"),
                  (r.confidence != null ? r.confidence : ""),
                  r.created_at || "", r.last_activity || "",
                  (r.engines || []).join("|"), r.source || "",
                  r.variant_of || "", r.from_name || "", r.candidate || "",
                  r.display_name || "", r.bio || ""].map(function (v) {
        v = String(v == null ? "" : v);
        return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
      }).join(","));
    });
    download("sherlock-results.csv", lines.join("\n"), "text/csv");
    toast("CSV exported — " + currentRun.length + " rows", "success");
  });

  els.jsonBtn.addEventListener("click", function () {
    if (!currentRun.length) { toast("Nothing to export", "error"); return; }
    download("sherlock-results.json", JSON.stringify(currentRun, null, 2), "application/json");
    toast("JSON exported — " + currentRun.length + " entries", "success");
  });

  els.clearBtn.addEventListener("click", function () {
    stopStream();
    stopInvestigation();
    clearResults();
    els.overallBar.style.display = "none";
    els.results.innerHTML = EMPTY_STATE_HTML;
  });

  /* ============================ watchlist ============================ */
  function loadWatchlist() {
    fetch("/api/watchlist").then(function (r) { return r.json(); }).then(function (watches) {
      if (!watches.length) {
        els.watchList.innerHTML = '<div class="hint">No watches yet — add one to monitor a subject for changes.</div>';
        return;
      }
      els.watchList.innerHTML = "";
      watches.forEach(function (w) {
        var item = document.createElement("div");
        item.className = "watch-item" + (w.enabled ? " enabled" : "");
        var head = document.createElement("div");
        head.className = "w-label";
        head.textContent = w.label;
        var tog = document.createElement("button");
        tog.className = "w-toggle " + (w.enabled ? "on" : "off");
        tog.textContent = w.enabled ? "on" : "paused";
        tog.setAttribute("aria-label", (w.enabled ? "Pause" : "Resume") + " watch " + w.label);
        tog.addEventListener("click", function () {
          fetch("/api/watchlist/" + w.id + "/toggle", { method: "POST" })
            .then(function () { loadWatchlist(); });
        });
        head.appendChild(tog);
        item.appendChild(head);
        var meta = document.createElement("div");
        meta.className = "w-meta";
        var inp = [];
        if (w.inputs.name) inp.push("name: " + w.inputs.name);
        if ((w.inputs.usernames || []).length) inp.push("users: " + w.inputs.usernames.join(", "));
        if (w.inputs.email) inp.push("email: " + w.inputs.email);
        meta.textContent = inp.join(" · ") +
          " — every " + w.interval_hours + "h · last run: " +
          relTime(w.last_run_at) + " · " + w.alerts + " alert(s)";
        if (w.last_run_at) meta.title = w.last_run_at;
        item.appendChild(meta);
        var actions = document.createElement("div");
        actions.className = "w-actions";
        var del = document.createElement("button");
        del.className = "w-del";
        del.textContent = "delete";
        del.setAttribute("aria-label", "Delete watch " + w.label);
        del.addEventListener("click", function () {
          confirmModal(
            "Delete watch",
            "Stop monitoring “" + w.label + "”? Its alert history stays in the list below.",
            "Delete",
            function () {
              fetch("/api/watchlist/" + w.id, { method: "DELETE" })
                .then(function () {
                  toast("Watch deleted", "success");
                  loadWatchlist();
                })
                .catch(function () { toast("Failed to delete watch", "error"); });
            }
          );
        });
        actions.appendChild(del);
        item.appendChild(actions);
        els.watchList.appendChild(item);
      });
    }).catch(function () { /* best-effort */ });
  }

  els.watchCreateBtn.addEventListener("click", function () {
    var inputs = {};
    if (els.watchName.value.trim()) inputs.name = els.watchName.value.trim();
    var us = els.watchUsernames.value.split(/[,\n]+/).map(function (s) { return s.trim(); }).filter(Boolean);
    if (us.length) inputs.usernames = us;
    if (els.watchEmail.value.trim()) inputs.email = els.watchEmail.value.trim();
    if (!inputs.name && !inputs.usernames && !inputs.email) {
      toast("A watch needs a name, username, or email", "error");
      return;
    }
    fetch("/api/watchlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        label: els.watchLabel.value.trim(),
        inputs: inputs,
        interval_hours: parseInt(els.watchNewInterval.value, 10)
      })
    }).then(function (r) { return r.json(); }).then(function (resp) {
      if (resp.error) { toast(resp.error, "error"); return; }
      els.watchLabel.value = ""; els.watchName.value = "";
      els.watchUsernames.value = ""; els.watchEmail.value = "";
      toast("Watch created", "success");
      loadWatchlist();
    }).catch(function () { toast("Failed to create watch", "error"); });
  });

  /* ============================ alerts ============================ */
  var KIND_ICONS = {
    new_account: "＋", new_holehe_hit: "＋",
    account_gone: "－", holehe_hit_gone: "－"
  };

  function renderAlertItem(a) {
    var item = document.createElement("div");
    item.className = "alert-item" + (a.seen ? " seen" : " unseen");
    var msg = document.createElement("div");
    var kind = document.createElement("span");
    kind.className = "a-kind " + a.kind;
    kind.textContent = (KIND_ICONS[a.kind] ? KIND_ICONS[a.kind] + " " : "") + a.kind.replace(/_/g, " ");
    msg.appendChild(kind);
    msg.appendChild(document.createTextNode(a.message));
    item.appendChild(msg);
    var time = document.createElement("div");
    time.className = "a-time";
    time.textContent = relTime(a.created_at) + (a.watch_label ? " · " + a.watch_label : "");
    if (a.created_at) time.title = a.created_at;
    item.appendChild(time);
    return item;
  }

  function pollAlerts() {
    fetch("/api/alerts?unseen=1").then(function (r) { return r.json(); }).then(function (alerts) {
      setStatus("online");
      if (alerts.length) {
        els.alertBadge.style.display = "";
        els.alertBadge.textContent = alerts.length;
      } else {
        els.alertBadge.style.display = "none";
      }
      if (!alerts.length) {
        els.alertsList.innerHTML = '<div class="alert-item"><span class="a-time">No unseen alerts.</span></div>';
        return;
      }
      els.alertsList.innerHTML = "";
      alerts.forEach(function (a) { els.alertsList.appendChild(renderAlertItem(a)); });
    }).catch(function () {
      setStatus("offline");
    });
  }

  function loadAllAlerts() {
    fetch("/api/alerts").then(function (r) { return r.json(); }).then(function (alerts) {
      if (!alerts.length) {
        els.allAlertsList.innerHTML = '<div class="hint">No alerts yet. Alerts appear when a watched subject changes.</div>';
        return;
      }
      els.allAlertsList.innerHTML = "";
      alerts.forEach(function (a) { els.allAlertsList.appendChild(renderAlertItem(a)); });
    }).catch(function () { /* best-effort */ });
  }

  els.bellBtn.addEventListener("click", function (e) {
    e.stopPropagation();
    var open = els.alertsDrop.classList.toggle("open");
    els.bellBtn.setAttribute("aria-expanded", String(open));
  });
  document.addEventListener("click", function (e) {
    if (!els.alertsDrop.contains(e.target) && e.target !== els.bellBtn) {
      els.alertsDrop.classList.remove("open");
      els.bellBtn.setAttribute("aria-expanded", "false");
    }
  });
  els.markSeenBtn.addEventListener("click", function () {
    fetch("/api/alerts/mark_seen", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    }).then(function () { pollAlerts(); loadAllAlerts(); });
  });

  /* ============================ history ============================ */
  function loadHistory() {
    fetch("/api/history").then(function (r) { return r.json(); }).then(function (runs) {
      if (!runs.length) {
        els.historyPage.innerHTML = '<div class="hint">No runs yet — completed investigations and scans land here.</div>';
        return;
      }
      els.historyPage.innerHTML = "";
      runs.forEach(function (run) {
        var item = document.createElement("div");
        item.className = "hist-item";
        item.setAttribute("tabindex", "0");
        var main = document.createElement("div");
        var u = document.createElement("div");
        u.className = "h-user";
        u.textContent = run.username;
        if (run.kind && run.kind !== "sherlock") {
          var kb = document.createElement("span");
          kb.className = "h-kind";
          kb.textContent = run.kind;
          u.appendChild(kb);
        }
        var m = document.createElement("div");
        m.className = "h-meta";
        m.textContent = relTime(run.ts) + " · ";
        m.title = run.ts;
        var f = document.createElement("span");
        f.className = "h-found";
        // Investigations persist an honest split (confirmed accounts vs total
        // raw hits); quick scans keep the simple found/sites ratio.
        f.textContent = (run.kind === "investigation")
          ? (run.found + " confirmed · " + run.total + " hits")
          : (run.found + "/" + run.total + " found");
        m.appendChild(f);
        main.appendChild(u);
        main.appendChild(m);
        item.appendChild(main);
        if (run.kind === "investigation" && run.investigation_id) {
          var actions = document.createElement("div");
          actions.className = "h-actions";
          var rep = document.createElement("a");
          rep.textContent = "dossier";
          rep.href = "/api/investigate/" + run.investigation_id + "/report";
          rep.target = "_blank";
          rep.addEventListener("click", function (e) { e.stopPropagation(); });
          var gr = document.createElement("button");
          gr.textContent = "graph";
          gr.addEventListener("click", function (e) {
            e.stopPropagation();
            switchTab("investigate");
            resetInvestigationUI();
            els.overallBar.style.display = "none";
            enableInvestigationActions(run.investigation_id);
            els.graphBtn.click();
          });
          var rr = document.createElement("button");
          rr.textContent = "re-run";
          rr.addEventListener("click", function (e) {
            e.stopPropagation();
            startRerun(run.investigation_id);
          });
          actions.appendChild(rep);
          actions.appendChild(gr);
          actions.appendChild(rr);
          item.appendChild(actions);
        }
        item.addEventListener("click", function () { loadRun(run.id); });
        item.addEventListener("keydown", function (e) {
          if (e.key === "Enter" || e.key === " ") { e.preventDefault(); loadRun(run.id); }
        });
        els.historyPage.appendChild(item);
      });
    }).catch(function () { /* history is best-effort */ });
  }

  function renderSummaryReadOnly(summary, run) {
    function restore(r, extra) {
      addInvFoundRow(Object.assign({ username: r.username, site: r.site,
                                     url: r.url, engines: r.engines }, extra));
      if (r.enrichment || r.verification)
        enrichInvRow({ username: r.username, site: r.site,
                       enrichment: r.enrichment || {},
                       verification: r.verification });
    }
    (summary.accounts || []).forEach(function (r) {
      restore(r, { source: "base", variant_of: null, from_name: null,
                   candidate: null });
    });
    (summary.variants || []).forEach(function (r) {
      restore(r, { source: "variant", variant_of: r.variant_of });
    });
    (summary.name_accounts || []).forEach(function (r) {
      restore(r, { source: "name", from_name: r.from_name,
                   candidate: r.candidate });
    });
    var params = summary.params || {};
    var em = summary.email || {};
    if (em.gravatar || (em.holehe || []).length) {
      var addr = params.email || run.username;
      renderGravatar(addr, em.gravatar);
      (em.holehe || []).forEach(function (h) {
        // Spread the whole entry so recovery hints (email_recovery,
        // phone_number, corroborates_phone) survive a reload.
        addHoleheRow(Object.assign({ email: addr }, h));
      });
    }
    if (summary.phone) renderPhoneIntel(summary.phone);
    if (summary.domain) renderDomainIntel(summary.domain);
    if (summary.brokers) renderBrokerExposure(summary.brokers);
    renderCorrelation(summary.correlation || []);
    finalizeAccuracy();
    Object.keys(invCards).forEach(function (k) {
      invCards[k].status.textContent = "loaded · " + run.ts;
    });
  }

  function loadRun(id) {
    fetch("/api/history/" + id).then(function (r) { return r.json(); }).then(function (run) {
      if (run.error) { toast("Run not found", "error"); return; }
      switchTab("investigate");
      stopStream();
      stopInvestigation();
      resetInvestigationUI();
      els.overallBar.style.display = "none";

      if (run.kind === "investigation" && run.results && !Array.isArray(run.results)) {
        renderSummaryReadOnly(run.results, run);
        if (run.results.params) {
          currentInvInputs = {
            name: run.results.params.name || "",
            usernames: run.results.params.usernames || [],
            email: run.results.params.email || ""
          };
        }
        // Prefer the linked investigation id (graph/dossier need it).
        fetch("/api/investigate/" + (run.investigation_id || 0))
          .then(function (r) { return r.json(); })
          .then(function (inv) {
            if (!inv.error) enableInvestigationActions(inv.id);
          }).catch(function () {});
        els.exportBar.style.display = "flex";
        els.results.scrollIntoView({ behavior: "smooth" });
        return;
      }

      if (run.kind === "recon" && run.results && !Array.isArray(run.results)) {
        // Legacy deep-recon run: reuse the same renderer.
        renderSummaryReadOnly({
          accounts: run.results.accounts || [],
          variants: run.results.variants || [],
          name_accounts: [],
          email: run.results.email || {},
          phone: null,
          correlation: run.results.correlation || [],
          params: run.results.params || {}
        }, run);
        els.exportBar.style.display = "flex";
        els.results.scrollIntoView({ behavior: "smooth" });
        return;
      }

      var c = getCard(run.username);
      c.scanning.textContent = "loaded · " + run.ts;
      c.fill.style.width = "100%";
      (run.results || []).forEach(function (r) {
        addFoundRow(run.username, r.site, r.url, null);
      });
      if (!run.results || !run.results.length) {
        c.rows.innerHTML = '<div class="rrow error"><span class="status">No accounts found in this run.</span></div>';
      }
      els.exportBar.style.display = "flex";
      els.results.scrollIntoView({ behavior: "smooth" });
    }).catch(function () { toast("Failed to load run", "error"); });
  }

  /* ============================ init ============================ */
  loadHistory();
  loadWatchlist();
  pollAlerts();
  setInterval(pollAlerts, 30000);
})();
