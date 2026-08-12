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
    invVariants: document.getElementById("invVariants"),
    invThorough: document.getElementById("invThorough"),
    invTimeout: document.getElementById("invTimeout"),
    invNsfw: document.getElementById("invNsfw"),
    invStartBtn: document.getElementById("invStartBtn"),
    invStopBtn: document.getElementById("invStopBtn"),
    graphPanel: document.getElementById("graphPanel"),
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
      '<div class="empty-icon" aria-hidden="true">' +
        '<svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="10.5" cy="10.5" r="6.5"/><line x1="15.2" y1="15.2" x2="21" y2="21"/></svg>' +
      "</div>" +
      "<p>One clue in — a name, username, email, or phone — and hit <b>Start investigation</b>.</p>" +
      '<p class="empty-sub">Accounts, email exposure, phone intel, correlations and an identity graph stream in live.</p>' +
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
    health: document.getElementById("tabHealth")
  };

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
      if (tab === "watchlist") { loadWatchlist(); loadAllAlerts(); }
      if (tab === "history") { loadHistory(); }
      if (tab === "health") { loadHealthSources(); }
      closeSidebar();
    });
  });
  function switchTab(tab) {
    document.querySelector('.app-tab[data-tab="' + tab + '"]').click();
  }

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
    c.found.textContent = c.foundCount + " found";
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
    var card = document.createElement("div");
    card.className = "user-card";
    card.innerHTML =
      '<div class="user-head"><h2></h2><span class="badge scanning">running</span>' +
      '<span class="badge found">0 found</span>' +
      '<span class="dim" style="font-size:11px;margin-left:auto"></span></div>' +
      '<div class="result-rows"></div>';
    card.querySelector("h2").textContent = badgeText || title;
    els.results.appendChild(card);
    var refs = {
      head: head, root: card,
      status: card.querySelector(".badge.scanning"),
      found: card.querySelector(".badge.found"),
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
    c.found.textContent = c.foundCount + " found";
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
    confirmed: { cls: "confirmed", text: "✓ verified" },
    unconfirmed: { cls: "unconfirmed", text: "? unconfirmed" },
    likely_false_positive: { cls: "false", text: "⚠ likely false" }
  };

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
    var st = document.createElement("span");
    st.className = d.exists ? "email-hit" : "email-miss";
    st.textContent = d.exists ? ("registered" + (d.domain ? " — " + d.domain : ""))
                              : (d.error ? "error: " + d.error : (d.rate_limit ? "rate limited" : ""));
    row.appendChild(s); row.appendChild(st);
    c.rows.appendChild(row);
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
    } else {
      addRow("Valid", p.valid ? "yes" : (p.possible ? "possible, not valid" : "no"),
             p.valid ? "phone-valid" : "phone-invalid");
      addRow("E.164", p.e164);
      addRow("International", p.international);
      addRow("Country", p.country);
      addRow("Region", p.region);
      addRow("Location", p.location);
      addRow("Carrier", p.carrier);
      addRow("Line type", p.line_type);
      addRow("Timezones", (p.timezones || []).join(", "));
      addRow("Note", p.note);
    }
    c.rows.appendChild(dl);
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
    invEs.addEventListener("domain_intel", function (e) {
      renderDomainIntel(JSON.parse(e.data));
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
      var msg = "Investigation complete — " + d.found + " accounts, " +
        d.variant_hits + " variant hits, " + d.name_hits + " candidate hits, " +
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

  var NODE_COLORS = {
    person: "#5ea0ff",
    account: "#5ea0ff",
    email: "#e0a338",
    phone: "#4cc3d9",
    registration: "#7d8a9c",
    domain: "#c39bff",
    ip: "#f778ba",
    nameserver: "#6e7681"
  };

  function confidenceBand(conf) {
    if (conf >= 70) return { label: "High", cls: "conf-high" };
    if (conf >= 40) return { label: "Medium", cls: "conf-med" };
    return { label: "Low", cls: "conf-low" };
  }

  function nodeColor(n) {
    if (n.type === "account") {
      var v = n.verification || (n.data || {}).verification;
      if (v === "likely_false_positive") return "#f0615d";  // flagged red
      if (v === "confirmed") return "#4cc38a";               // verified green
      if ((n.engines || []).length >= 2) return "#4cc38a";
      if ((n.data || {}).source === "name") return "#e0a338";
    }
    return NODE_COLORS[n.type] || "#7d8a9c";
  }

  function nodeSize(n) {
    if (n.type === "person") return 46;
    if (n.type === "email" || n.type === "phone") return 30;
    return 16 + Math.round((n.confidence || 40) * 0.22);
  }

  function applyGraphFilters() {
    if (!cy) return;
    var edgeMin = parseInt(els.confSlider.value, 10);
    var nodeMin = parseInt(els.nodeConfSlider.value, 10);
    els.confSliderVal.textContent = edgeMin + "%";
    els.nodeConfSliderVal.textContent = nodeMin + "%";
    // Dim account nodes below the confidence threshold (other entity types —
    // person/email/phone/domain/ip — are inputs/facts and always shown).
    var dimmed = {};
    cy.nodes().forEach(function (n) {
      var weak = n.data("type") === "account" &&
        (n.data("confidence") || 0) < nodeMin;
      dimmed[n.id()] = weak;
      n.style("opacity", weak ? 0.12 : 1);
    });
    // Hide an edge below the edge threshold, or if either endpoint is dimmed.
    cy.edges().forEach(function (e) {
      var show = (e.data("confidence") || 0) >= edgeMin &&
        !dimmed[e.data("source")] && !dimmed[e.data("target")];
      e.style("display", show ? "element" : "none");
    });
  }

  // Backwards-compatible alias (renderGraph calls applyEdgeFilter once built).
  var applyEdgeFilter = applyGraphFilters;

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

  function showNodePanel(n) {
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
    var elements = [];
    data.nodes.forEach(function (n) {
      var nd = {
        id: n.id, type: n.type, label: n.label, sublabel: n.sublabel || "",
        url: n.url || "",
        confidence: n.confidence, engines: n.engines || [],
        data: n.data || {},
        color: nodeColor(n), size: nodeSize(n),
        labelText: n.label + (n.sublabel ? "\n" + n.sublabel : "")
      };
      // Only set `avatar` when there is a real URL. An empty string still
      // matches the `node[avatar]` style rule, and cytoscape then throws
      // parsing "" as a background-image — which silently killed the graph.
      if (n.avatar) nd.avatar = n.avatar;
      elements.push({ data: nd });
    });
    data.edges.forEach(function (e) {
      elements.push({ data: {
        id: e.id, source: e.source, target: e.target,
        confidence: e.confidence, rationale: e.rationale
      }});
    });
    if (cy) { cy.destroy(); cy = null; }
    cy = cytoscape({
      container: els.cy,
      elements: elements,
      wheelSensitivity: 0.3,
      style: [
        { selector: "node", style: {
          "background-color": "data(color)",
          "width": "data(size)", "height": "data(size)",
          "label": "data(labelText)",
          "color": "#eaf0f7", "font-size": 9, "line-height": 1.3,
          "font-family": "ui-sans-serif, system-ui, sans-serif",
          "min-zoomed-font-size": 7,
          "text-wrap": "wrap", "text-max-width": "110px",
          "text-valign": "bottom", "text-margin-y": 5,
          "text-background-color": "#090c11", "text-background-opacity": 0.78,
          "text-background-padding": 3, "text-background-shape": "roundrectangle",
          "border-width": 1.5, "border-color": "data(color)", "border-opacity": 0.55,
          "background-opacity": 0.95,
          "transition-property": "border-width, border-color, opacity",
          "transition-duration": 120
        }},
        // Contact identifiers read as tags; domains as hexagons; IPs as diamonds.
        { selector: 'node[type="email"]', style: { "shape": "round-rectangle" } },
        { selector: 'node[type="phone"]', style: { "shape": "round-rectangle" } },
        { selector: 'node[type="registration"]', style: { "shape": "round-rectangle" } },
        { selector: 'node[type="nameserver"]', style: { "shape": "round-rectangle" } },
        { selector: 'node[type="domain"]', style: { "shape": "hexagon" } },
        { selector: 'node[type="ip"]', style: { "shape": "diamond" } },
        { selector: 'node[type="person"]', style: {
          "border-width": 3, "border-color": "#eaf0f7", "border-opacity": 1,
          "font-size": 12, "font-weight": "bold"
        }},
        { selector: "node[avatar]", style: {
          "background-image": "data(avatar)",
          "background-fit": "cover", "background-clip": "node",
          "background-image-crossorigin": "anonymous"
        }},
        { selector: "edge", style: {
          "width": "mapData(confidence, 0, 100, 1, 4.5)",
          "line-color": "#3a4658", "curve-style": "bezier",
          "opacity": 0.85,
          "label": "data(confidence)", "font-size": 8, "color": "#8a97a8",
          "min-zoomed-font-size": 8,
          "font-family": "ui-monospace, monospace",
          "text-rotation": "autorotate",
          "text-background-color": "#090c11", "text-background-opacity": 0.7,
          "text-background-padding": 1
        }},
        { selector: "edge[confidence >= 60]", style: { "line-color": "#4cc38a" } },
        { selector: "edge[confidence < 40]", style: { "line-style": "dashed", "opacity": 0.6 } },
        { selector: "node:selected", style: { "border-color": "#ffffff", "border-width": 3, "border-opacity": 1 } },
        { selector: "node.hl", style: { "border-color": "#ffffff", "border-width": 3, "border-opacity": 1 } },
        { selector: "edge.hl", style: { "line-color": "#8dbcff", "opacity": 1, "width": 3 } },
        { selector: ".dimmed", style: { "opacity": 0.12 } }
      ],
      layout: {
        name: "cose", animate: true, animationDuration: 800,
        nodeRepulsion: 8000, idealEdgeLength: 110, gravity: 0.4,
        padding: 40
      }
    });
    // Re-fit once painted and again when the animated layout settles — the
    // panel may still be sizing when cytoscape initializes.
    cy.on("layoutstop", function () { cy.fit(undefined, 40); });
    requestAnimationFrame(function () {
      if (cy) { cy.resize(); cy.fit(undefined, 40); }
    });
    // Selecting a node focuses its neighborhood: highlight the node + its
    // links, dim everything else. Tapping the background clears the focus.
    cy.on("tap", "node", function (evt) {
      var n = evt.target;
      var hood = n.closedNeighborhood();
      cy.elements().addClass("dimmed").removeClass("hl");
      hood.removeClass("dimmed");
      hood.nodes().addClass("hl");
      hood.connectedEdges().removeClass("dimmed");
      n.connectedEdges().addClass("hl");
      showNodePanel(n);
    });
    cy.on("tap", function (evt) {
      if (evt.target === cy) {
        cy.elements().removeClass("hl dimmed");
        els.nodePanel.classList.remove("open");
      }
    });
    applyEdgeFilter();
    if (!graphLabelsOn) {
      cy.style().selector("node").style("label", "").update();
    }
    els.graphPanel.scrollIntoView({ behavior: "smooth" });
  }

  els.graphBtn.addEventListener("click", function () {
    if (!currentInvId) { toast("No investigation selected", "error"); return; }
    if (els.graphPanel.style.display === "block") {
      els.graphPanel.style.display = "none";
      return;
    }
    fetch("/api/investigate/" + currentInvId + "/graph")
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { toast(data.error, "error"); return; }
        renderGraph(data);
      })
      .catch(function () { toast("Failed to load graph", "error"); });
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
    var lines = ["username,site,url,status,engines,source,variant_of,from_name,candidate,display_name,bio"];
    currentRun.forEach(function (r) {
      lines.push([r.username, r.site, r.url, r.status,
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
        f.textContent = run.found + "/" + run.total + " found";
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
        addHoleheRow({ email: addr, site: h.site, domain: h.domain,
                       exists: h.exists, error: h.error,
                       rate_limit: h.rate_limit });
      });
    }
    if (summary.phone) renderPhoneIntel(summary.phone);
    if (summary.domain) renderDomainIntel(summary.domain);
    renderCorrelation(summary.correlation || []);
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
