window.T3 =
  window.T3 || { findings: [], score: null, traffic: [], cspAudit: null };
window.T3utils =
  window.T3utils ||
  {
    loadSession: () => null,
    saveSession: () => {},
    escapeHtml: (s) => String(s),
  };

function appMain() {
  const parsers = window.T3parsers;
  const cache = window.T3cache;
  const csp = window.T3csp;
  const ui = window.T3ui;
  const copyas = window.T3copyas;

  function getEl(id) {
    return document.getElementById(id);
  }
  function updateSessionCount() {
    const el = getEl("session-count");
    if (el) el.textContent = String(window.T3.traffic?.length || 0);
  }

function renderAdvancedCookieAnalysis() {
    const container = getEl("cookie-analysis-results");
    if (!container) return;
    container.innerHTML = "";

    function parseSingleCookie(rawCookieStr) {
      const parts = String(rawCookieStr).split(";");
      const [nameValue, ...attrParts] = parts;
      const [name, ...valParts] = nameValue.split("=");
      const value = valParts.join("=");
      const attrs = {};
      for (const ap of attrParts) {
        const [an, av] = ap.trim().split("=");
        const key = (an || "").trim().toLowerCase();
        if (!key) continue;
        attrs[key] = (av || "").trim() || true;
      }
      return { name: (name || "").trim(), value: (value || "").trim(), attrs };
    }

    const allCookies = [];
    (window.T3.traffic || []).forEach(tx => {
        const setCookieHeader = tx.response?.headers?.["Set-Cookie"];
        if (!setCookieHeader) return;
        
        const cookieStrings = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
        cookieStrings.forEach(rawString => {
            allCookies.push(parseSingleCookie(rawString));
        });
    });

    if (allCookies.length === 0) {
      container.innerHTML = `<div class="card"><div class="card-body text-gray-400">No cookies have been captured from session traffic yet.</div></div>`;
      return;
    }

    const createRisk = (severity, text) => ({ severity, text });
    const TRACKING_COOKIE_NAMES = ['_ga', '_gid', '_gat', 'FPLC', 'AMP_TOKEN', '__gads'];

    allCookies.forEach(cookie => {
      if (!cookie || !cookie.name) return;

      const risks = [];
      const attributes = { ...cookie.attrs };

      if (!attributes.secure) risks.push(createRisk('high', 'Cookie sent over insecure HTTP. It can be intercepted.'));
      if (!attributes.httponly) risks.push(createRisk('medium', 'Cookie accessible to client-side scripts (XSS risk).'));
      if (!attributes.samesite) risks.push(createRisk('medium', 'No SameSite attribute. Vulnerable to CSRF attacks.'));

      if (cookie.name.startsWith('__Host-')) {
        if (!attributes.secure || attributes.domain || (attributes.path !== '/')) {
          risks.push(createRisk('high', 'Misconfigured "__Host-" prefix. It MUST be secure, have Path=/, and no Domain attribute.'));
        } else {
          risks.push(createRisk('info', '"__Host-" prefix used correctly, enhancing security.'));
        }
      } else if (cookie.name.startsWith('__Secure-')) {
         if (!attributes.secure) risks.push(createRisk('high', 'Misconfigured "__Secure-" prefix. It MUST be set with the Secure attribute.'));
         else risks.push(createRisk('info', '"__Secure-" prefix used correctly.'));
      }

      if (TRACKING_COOKIE_NAMES.some(tracker => cookie.name.toLowerCase().startsWith(tracker.toLowerCase()))) {
          risks.push(createRisk('low', `Heuristically identified as a potential tracking cookie (${cookie.name}).`));
      }

      let expiryText = "Session Cookie";
      if (attributes.expires) {
          const expiryDate = new Date(attributes.expires);
          if (!isNaN(expiryDate)) {
            const diffDays = (expiryDate.getTime() - new Date().getTime()) / (1000 * 3600 * 24);
            if (diffDays > 365) risks.push(createRisk('low', `Very long expiration (${Math.round(diffDays / 365)} years).`));
            expiryText = expiryDate.toUTCString();
          } else {
            expiryText = attributes.expires;
          }
      }
      attributes.expires = expiryText;
      
      const card = document.createElement('div');
      card.className = 'card cookie-card';

      let riskHtml = '<ul class="risk-list">';
      risks.forEach(risk => {
          const icon = risk.severity === 'high' ? 'fas fa-shield-virus' : risk.severity === 'medium' ? 'fas fa-exclamation-triangle' : risk.severity === 'low' ? 'fas fa-info-circle' : 'fas fa-check-circle';
          riskHtml += `<li class="risk-${risk.severity}"><i class="${icon} risk-icon"></i><span class="risk-text">${esc(risk.text)}</span></li>`;
      });
      riskHtml += '</ul>';

      card.innerHTML = `
        <div class="card-header"><h3 class="card-title">${esc(cookie.name)}</h3></div>
        <div class="card-body">
          <ul class="cookie-attributes">
              <li><span class="attr-name">Value</span><span class="attr-value">${esc(cookie.value) || '""'}</span></li>
              ${Object.entries(attributes).map(([key, value]) => `<li><span class="attr-name">${esc(key)}</span><span class="attr-value">${value === true ? '✓' : esc(value)}</span></li>`).join('')}
          </ul>
          <hr class="my-2 border-gray-800" />
          <h4 class="text-gray-300 font-bold mb-2">Security Analysis</h4>
          ${risks.length > 0 ? riskHtml : '<p class="text-sm text-gray-400">No major security risks detected.</p>'}
        </div>
      `;
      container.appendChild(card);
    });
  }

  function renderScoreBreakdownLocal(findings) {
    const root = getEl("score-breakdown");
    if (!root) return;
    const penalties = { Critical: 25, High: 15, Medium: 8, Low: 3, Info: 0 };
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    (findings || []).forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    const parts = Object.keys(counts).map((k) => {
      const n = counts[k] || 0;
      const pts = n * (penalties[k] || 0);
      return `${k}: ${n}${pts ? ` (-${pts})` : ""}`;
    });
    root.textContent = parts.join("  •  ");
  }
  
  function renderFiltersLocal(findings, onChange) {
    const root = getEl("results-filters");
    if (!root) return;
    root.innerHTML = "";
    const levels = ["Critical", "High", "Medium", "Low", "Info"];
    const counts = Object.fromEntries(levels.map((l) => [l, 0]));
    (findings || []).forEach((f) => (counts[f.severity] = (counts[f.severity] || 0) + 1));
    const active = new Set(levels);

    function sevClass(sev) {
      return {
        Critical: "sev-critical",
        High: "sev-high",
        Medium: "sev-medium",
        Low: "sev-low",
        Info: "sev-info",
      }[sev];
    }

    levels.forEach((sev) => {
      const wrap = document.createElement("label");
      wrap.className = "text-xs flex items-center gap-1";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = true;
      cb.addEventListener("change", () => {
        if (cb.checked) active.add(sev);
        else active.delete(sev);
        onChange?.(new Set(active));
      });
      const chip = document.createElement("span");
      chip.className = `finding-severity ${sevClass(sev) || "sev-info"}`;
      chip.textContent = `${sev} ${counts[sev] || 0}`;
      wrap.appendChild(cb);
      wrap.appendChild(chip);
      root.appendChild(wrap);
    });
  }

  function useRenderScoreBreakdown(findings) {
    if (ui && typeof ui.renderScoreBreakdown === "function")
      ui.renderScoreBreakdown(findings);
    else renderScoreBreakdownLocal(findings);
  }
  function useRenderFilters(findings, onChange) {
    if (ui && typeof ui.renderFilters === "function")
      ui.renderFilters(findings, onChange);
    else renderFiltersLocal(findings, onChange);
  }
  function useFilterBySeverity(findings, set) {
    if (ui && typeof ui.filterFindingsBySeverity === "function")
      return ui.filterFindingsBySeverity(findings, set);
    return (findings || []).filter((f) => set.has(f.severity));
  }

  const esc = (s) => window.T3utils.escapeHtml(s);

  function renderSessionList() {
    const wrap = getEl("session-list");
    if (!wrap) return;
    wrap.innerHTML = "";

    const txs = window.T3.traffic || [];
    if (!txs.length) {
      wrap.innerHTML =
        '<div class="text-gray-400 text-sm">Session is empty. Add transactions above.</div>';
      return;
    }

    txs.forEach((tx, idx) => {
      const req = tx.request || {};
      const res = tx.response || {};
      const host = req.headers?.Host || req.headers?.host || "unknown-host";

      const row = document.createElement("div");
      row.className =
        "flex items-center justify-between gap-2 border border-gray-800 rounded p-2";

      const left = document.createElement("div");
      left.className = "text-sm";
      left.textContent = `#${idx + 1} ${req.method || ""} ${req.path || "/"} @ ${
        host
      } ${res.statusCode ? "— " + res.statusCode : ""}`;

      const right = document.createElement("div");
      const rm = document.createElement("button");
      rm.className = "btn btn-sm";
      rm.textContent = "Remove";
      rm.addEventListener("click", () => {
        const arr = window.T3.traffic || [];
        arr.splice(idx, 1);
        window.T3.traffic = arr;
        updateSessionCount();
        renderSessionList();
        cache.renderCacheLab(window.T3.traffic, {
          ignoreTracking:
            getEl("origin-ignore-tracking") &&
            getEl("origin-ignore-tracking").checked,
        });
        renderAdvancedCookieAnalysis();
        updateSelectors();
        window.T3utils.saveSession();
      });
      right.appendChild(rm);

      row.appendChild(left);
      row.appendChild(right);
      wrap.appendChild(row);
    });
  }

  const saved =
    (window.T3utils && typeof window.T3utils.loadSession === "function"
      ? window.T3utils.loadSession()
      : null) || null;
  if (saved) {
    window.T3.traffic = saved.traffic || [];
    window.T3.findings = saved.findings || [];
    window.T3.score = saved.score || null;
    window.T3.cspAudit = saved.cspAudit || null;

    updateSessionCount();
    renderSessionList();
    cache.renderCacheLab(window.T3.traffic, {
      ignoreTracking:
        getEl("origin-ignore-tracking") &&
        getEl("origin-ignore-tracking").checked,
    });
    if (window.T3.cspAudit && csp && typeof csp.renderCspAudit === "function") {
      csp.renderCspAudit(window.T3.cspAudit);
    }
    if (window.T3.findings.length) {
      if (ui && typeof ui.updateScoreUI === "function")
        ui.updateScoreUI(window.T3.score ?? 100);
      useRenderScoreBreakdown(window.T3.findings);
      if (ui && typeof ui.renderDashboard === "function")
        ui.renderDashboard(window.T3.findings);
      useRenderFilters(window.T3.findings, (set) => {
        const filtered = useFilterBySeverity(window.T3.findings, set);
        if (ui && typeof ui.renderDashboard === "function")
          ui.renderDashboard(filtered);
      });
    } else if (ui && typeof ui.updateScoreUI === "function") {
      ui.updateScoreUI(null);
    }
    renderAdvancedCookieAnalysis();
    updateSelectors();
  } else {
    updateSelectors();
  }

  getEl("add-session")?.addEventListener("click", () => {
    const txs =
      (parsers && typeof parsers.gatherInputTraffic === "function"
        ? parsers.gatherInputTraffic()
        : []) || [];
    if (!txs.length) {
      alert("Please provide a request and/or response.");
      return;
    }
    window.T3.traffic = [...(window.T3.traffic || []), ...txs];
    updateSessionCount();
    renderSessionList();
    cache.renderCacheLab(window.T3.traffic, {
      ignoreTracking:
        getEl("origin-ignore-tracking") &&
        getEl("origin-ignore-tracking").checked,
    });
    renderAdvancedCookieAnalysis();
    updateSelectors();
    window.T3utils.saveSession();
    alert("Added to session.");
  });

  function analyzeSession() {
    if (!window.T3.traffic?.length) {
      alert("Session is empty. Add one or more transactions first.");
      return;
    }
    const passive =
      (cache && typeof cache.runPassiveAnalysis === "function"
        ? cache.runPassiveAnalysis(window.T3.traffic)
        : []) || [];
    const latest = latestResWithCsp(window.T3.traffic);
    if (csp && typeof csp.evaluateCspForUi === "function") {
      window.T3.cspAudit = csp.evaluateCspForUi(latest);
      if (typeof csp.renderCspAudit === "function") {
        csp.renderCspAudit(window.T3.cspAudit);
      }
    }
    const cspAuditFindings =
      (csp &&
        typeof csp.auditItemsToFindings === "function" &&
        csp.auditItemsToFindings(window.T3.cspAudit)) ||
      [];
    const cspWithMeta = cspAuditFindings.map((f) => ({
      ...f,
      source: "audit",
      id: `csp-${Math.random().toString(36).slice(2)}`,
    }));

    const merged = dedupe([...passive, ...cspWithMeta]);
    const withCurls =
      ui && typeof ui.generateCurlCommands === "function"
        ? ui.generateCurlCommands(merged)
        : merged;
    window.T3.findings = withCurls;
    window.T3.score =
      ui && typeof ui.calculateScore === "function"
        ? ui.calculateScore(withCurls)
        : 100;
    if (ui && typeof ui.updateScoreUI === "function")
      ui.updateScoreUI(window.T3.score);
    useRenderScoreBreakdown(withCurls);
    useRenderFilters(withCurls, (set) => {
      const filtered = useFilterBySeverity(withCurls, set);
      if (ui && typeof ui.renderDashboard === "function")
        ui.renderDashboard(filtered);
    });
    if (ui && typeof ui.renderDashboard === "function")
      ui.renderDashboard(withCurls);

    cache.renderCacheLab(window.T3.traffic, {
      ignoreTracking:
        getEl("origin-ignore-tracking") &&
        getEl("origin-ignore-tracking").checked,
    });

    renderSessionList();
    renderAdvancedCookieAnalysis();
    updateSelectors();
    window.T3utils.saveSession();
    location.hash = "#/results";
  }
  getEl("analyze-btn")?.addEventListener("click", analyzeSession);
  getEl("analyze-btn-bottom")?.addEventListener("click", analyzeSession);

  getEl("clear-session")?.addEventListener("click", () => {
    if (!confirm("Clear all transactions in session?")) return;
    window.T3.traffic = [];
    window.T3.findings = [];
    window.T3.score = null;
    window.T3.cspAudit = null;

    updateSessionCount();
    renderSessionList();

    cache.renderCacheLab([], {});
    if (ui && typeof ui.renderDashboard === "function") ui.renderDashboard([]);
    if (ui && typeof ui.updateScoreUI === "function") ui.updateScoreUI(null);
    if (csp && typeof csp.renderCspAudit === "function") csp.renderCspAudit(null);

    const dl = getEl("diff-left");
    const dr = getEl("diff-right");
    if (dl) dl.innerHTML = "";
    if (dr) dr.innerHTML = "";
    const selA = getEl("diff-a");
    const selB = getEl("diff-b");
    if (selA) selA.innerHTML = "";
    if (selB) selB.innerHTML = "";

    const labSel = getEl("lab-req-select");
    if (labSel) labSel.innerHTML = '<option value="">— none —</option>';
    const labBase = getEl("lab-base-request");
    if (labBase) labBase.value = "";
    const labPayloads = getEl("lab-payloads");
    if (labPayloads) labPayloads.innerHTML = "";
    const labResp = getEl("lab-raw-response");
    if (labResp) labResp.value = "";
    const labReport = getEl("lab-report");
    if (labReport) labReport.innerHTML = "";

    const scoreBreak = getEl("score-breakdown");
    if (scoreBreak) scoreBreak.textContent = "";
    const filterRoot = getEl("results-filters");
    if (filterRoot) filterRoot.innerHTML = "";

    renderAdvancedCookieAnalysis();
    updateSelectors();
    window.T3utils.saveSession();
  });

  getEl("recompute-keys")?.addEventListener("click", () => {
    cache.renderCacheLab(window.T3.traffic, {
      ignoreTracking:
        getEl("origin-ignore-tracking") &&
        getEl("origin-ignore-tracking").checked,
    });
  });

  getEl("lab-load-from-parsed")?.addEventListener("click", () => {
    const sel = getEl("lab-req-select");
    const idx = sel?.value ? Number(sel.value) : NaN;
    if (Number.isNaN(idx) || !window.T3.traffic[idx]?.request) {
      alert("Select a parsed request first.");
      return;
    }
    const req = window.T3.traffic[idx].request;
    const start = `${req.method || "GET"} ${req.path || "/"} ${
      req.httpVersion || "HTTP/1.1"
    }`;
    const headers = Object.entries(req.headers || {})
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`)
      .join("\r\n");
    const raw = [start, headers, "", req.body || ""].join("\r\n");
    getEl("lab-base-request").value = raw;
  });

  getEl("lab-generate")?.addEventListener("click", () => {
    const raw = getEl("lab-base-request").value || "";
    const baseReq =
      raw.trim() && parsers && typeof parsers.parseRequest === "function"
        ? parsers.parseRequest(raw)
        : window.T3.traffic?.[0]?.request;
    if (!baseReq?.method) {
      alert("Provide a base request (select from parsed or paste raw).");
      return;
    }
    const techs = Array.from(
      document.querySelectorAll(".lab-tech:checked")
    ).map((el) => el.value);
    if (!techs.length) {
      alert("Select at least one technique.");
      return;
    }
    const combine = getEl("lab-combine") && getEl("lab-combine").checked;
    const smuggVariants = Array.from(
      document.querySelectorAll(".lab-smugg-variant:checked")
    ).map((el) => el.value);

    const container = getEl("lab-payloads");
    container.innerHTML = "";

    if (combine) {
      const combined =
        cache && typeof cache.combineTechniques === "function"
          ? cache.combineTechniques(baseReq, techs)
          : null;
      if (combined) {
        container.appendChild(
          renderPayloadBlock(combined.title, combined.raw, combined.why)
        );
      }
      const incompatible = new Set(["smuggling", "response-split", "fat-get"]);
      const rest = techs.filter((t) => incompatible.has(t));
      rest.forEach((t) => {
        cache
          .payloadsForTech(baseReq, t)
          .forEach((pl) =>
            container.appendChild(renderPayloadBlock(pl.title, pl.raw, pl.why))
          );
      });
    } else {
      techs.forEach((t) => {
        cache
          .payloadsForTech(baseReq, t)
          .forEach((pl) =>
            container.appendChild(renderPayloadBlock(pl.title, pl.raw, pl.why))
          );
      });
    }

    if (techs.includes("smuggling") && smuggVariants.length) {
      const adv = cache.advancedSmugglingPayloads(baseReq);
      const mapTitleToKey = {
        "Smuggling CL.TE": "CL.TE",
        "Smuggling TE.CL": "TE.CL",
        "Smuggling TE-TE (duplicate chunked)": "TE-TE",
        "Smuggling obf: space before colon": "obf-space-colon",
        "Smuggling obf: header casing": "obf-casing",
        "Smuggling: chunk extension": "chunk-ext",
        "Smuggling: TE obs-fold": "obs-fold",
        "Smuggling: duplicate TE with casing": "dup-casing",
        "Smuggling: CL-CL conflict": "clcl-conflict",
        "Smuggling: TE with extra LWS": "te-lws",
      };
      adv.forEach((pl) => {
        const key = mapTitleToKey[pl.title] || "";
        if (!key || smuggVariants.includes(key)) {
          container.appendChild(renderPayloadBlock(pl.title, pl.raw, pl.why));
        }
      });
    }
  });

  getEl("lab-clear")?.addEventListener("click", () => {
    const cont = getEl("lab-payloads");
    if (cont) cont.innerHTML = "";
  });

  getEl("lab-clear-response")?.addEventListener("click", () => {
    const t = getEl("lab-raw-response");
    if (t) t.value = "";
    const r = getEl("lab-report");
    if (r) r.innerHTML = "";
  });

  getEl("lab-analyze")?.addEventListener("click", () => {
    const rawR = getEl("lab-raw-response").value || "";
    if (!rawR.trim()) {
      alert("Paste a raw HTTP response to analyze.");
      return;
    }
    const selectedTechs = Array.from(
      document.querySelectorAll(".lab-tech:checked")
    ).map((el) => el.value);
    const smuggVariants = Array.from(
      document.querySelectorAll(".lab-smugg-variant:checked")
    ).map((el) => el.value);
    const techs = selectedTechs.includes("smuggling")
      ? [...selectedTechs, ...smuggVariants]
      : selectedTechs;

    const report =
      cache && typeof cache.analyzeLabResponse === "function"
        ? cache.analyzeLabResponse(rawR, techs, {})
        : "Analysis module missing.";
    const out = getEl("lab-report");
    out.innerHTML = "";
    const pre = document.createElement("pre");
    pre.className = "code-block";
    pre.textContent = report;
    out.appendChild(pre);
  });

  function renderPayloadBlock(title, raw, why) {
    const block = document.createElement("div");
    block.className = "card";
    const header = document.createElement("div");
    header.className = "card-header";
    const titleEl = document.createElement("div");
    titleEl.className = "card-title";
    titleEl.textContent = title;
    const tools = document.createElement("div");

    const copyBtn = document.createElement("button");
    copyBtn.className = "btn btn-sm";
    copyBtn.textContent = "Copy";
    copyBtn.addEventListener("click", async () => {
      await navigator.clipboard.writeText(raw);
      copyBtn.textContent = "Copied!";
      setTimeout(() => (copyBtn.textContent = "Copy"), 1200);
    });

    const copyCurlBtn = document.createElement("button");
    copyCurlBtn.className = "btn btn-sm";
    copyCurlBtn.textContent = "Copy as cURL";
    copyCurlBtn.addEventListener("click", async () => {
      const req =
        parsers && typeof parsers.parseRequest === "function"
          ? parsers.parseRequest(raw)
          : null;
      const curl =
        copyas && typeof copyas.requestToCurl === "function"
          ? copyas.requestToCurl(req || {})
          : "";
      await navigator.clipboard.writeText(curl);
      copyCurlBtn.textContent = "Copied!";
      setTimeout(() => (copyCurlBtn.textContent = "Copy as cURL"), 1200);
    });

    tools.appendChild(copyBtn);
    tools.appendChild(copyCurlBtn);
    header.appendChild(titleEl);
    header.appendChild(tools);

    const body = document.createElement("div");
    body.className = "card-body";
    if (why) {
      const info = document.createElement("div");
      info.className = "text-xs text-gray-400 mb-2";
      info.textContent = why;
      body.appendChild(info);
    }
    const pre = document.createElement("pre");
    pre.className = "code-block";
    pre.textContent = raw;
    body.appendChild(pre);

    block.appendChild(header);
    block.appendChild(body);
    return block;
  }

  getEl("diff-run")?.addEventListener("click", () => {
    const aIdx = Number(getEl("diff-a").value || -1);
    const bIdx = Number(getEl("diff-b").value || -1);
    if (aIdx < 0 || bIdx < 0) return alert("Select two items.");
    const A = window.T3.traffic[aIdx]?.response;
    const B = window.T3.traffic[bIdx]?.response;
    const AL = A
      ? `${A.httpVersion} ${A.statusCode} ${A.statusText}\n` +
        Object.entries(A.headers || {})
          .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`)
          .join("\n") +
        `\n\n${A.body || ""}`
      : "";
    const BL = B
      ? `${B.httpVersion} ${B.statusCode} ${B.statusText}\n` +
        Object.entries(B.headers || {})
          .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`)
          .join("\n") +
        `\n\n${B.body || ""}`
      : "";
    const changesOnly = !!(
      getEl("diff-changes-only") && getEl("diff-changes-only").checked
    );
    if (ui && typeof ui.renderDiff === "function") {
      ui.renderDiff(AL, BL, changesOnly);
    }
  });

  getEl("diff-swap")?.addEventListener("click", () => {
    const a = getEl("diff-a");
    const b = getEl("diff-b");
    if (!a || !b) return;
    const tmp = a.value;
    a.value = b.value;
    b.value = tmp;
  });

  function populateDiffSelectors() {
    const a = getEl("diff-a");
    const b = getEl("diff-b");
    if (!a || !b) return;
    a.innerHTML = "";
    b.innerHTML = "";
    (window.T3.traffic || []).forEach((tx, idx) => {
      const label = `#${idx + 1} ${
        tx.request?.method || ""
      } ${tx.request?.path || "/"} (${tx.response?.statusCode || "-"})`;
      const oa = document.createElement("option");
      oa.value = String(idx);
      oa.textContent = label;
      const ob = oa.cloneNode(true);
      a.appendChild(oa);
      b.appendChild(ob);
    });
  }
  window.populateDiffSelectors = populateDiffSelectors;

  function populateCorsReqSelect() {
    const sel = getEl("cors-req-select");
    if (!sel) return;
    sel.innerHTML = '<option value="">— none —</option>';
    (window.T3.traffic || []).forEach((tx, idx) => {
      const rq = tx.request || {};
      const host = rq.headers?.Host || rq.headers?.host || "unknown-host";
      const label = `#${idx + 1} ${rq.method || ""} ${rq.path || "/"} @ ${host}`;
      const opt = document.createElement("option");
      opt.value = String(idx);
      opt.textContent = label;
      sel.appendChild(opt);
    });
  }
  function updateSelectors() {
    populateDiffSelectors();
    populateCorsReqSelect();
  }

  getEl("cors-load-from-parsed")?.addEventListener("click", () => {
    const sel = getEl("cors-req-select");
    const idx = sel?.value ? Number(sel.value) : NaN;
    const tx = window.T3.traffic?.[idx];
    if (!tx?.request) {
      alert("Select a parsed request first.");
      return;
    }
    const req = tx.request;
    const host = req.headers?.Host || req.headers?.host || "example.com";
    const proto =
      req.headers?.["X-Forwarded-Proto"] ||
      (req.headers?.Forwarded || "").match(/proto=([^;]+)/)?.[1] ||
      "https";
    getEl("cors-scheme").value = String(proto).toLowerCase();
    getEl("cors-host").value = host;
    getEl("cors-path").value = req.path || "/";

    const originPreset = getEl("cors-origin-preset");
    if (originPreset) originPreset.value = "app-sub";
    getEl("cors-origin").value = `https://app.${host}`;
  });

  getEl("cors-origin-preset")?.addEventListener("change", () => {
    const preset = getEl("cors-origin-preset").value;
    const host = getEl("cors-host").value || "example.com";
    const originEl = getEl("cors-origin");
    if (preset === "app-sub") originEl.value = `https://app.${host}`;
    else if (preset === "null") originEl.value = "null";
  });

  function buildAcrh() {
    const checks = Array.from(
      document.querySelectorAll(".cors-chk-hdr:checked")
    )
      .map((el) => el.value)
      .filter(Boolean);
    const extra = (getEl("cors-acrh")?.value || "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    return Array.from(new Set([...checks, ...extra])).join(", ");
  }

  getEl("cors-gen")?.addEventListener("click", () => {
    const scheme = (getEl("cors-scheme")?.value || "https").toLowerCase();
    const host = getEl("cors-host")?.value || "example.com";
    const path = getEl("cors-path")?.value || "/";
    const origin = getEl("cors-origin")?.value || "https://app.example";
    const acrm = getEl("cors-acrm-select")?.value || "PUT";
    const acrh = buildAcrh();

    const start = `OPTIONS ${path} HTTP/1.1`;
    const headers = [
      `Host: ${host}`,
      `Origin: ${origin}`,
      `Access-Control-Request-Method: ${acrm}`,
    ];
    if (acrh) headers.push(`Access-Control-Request-Headers: ${acrh}`);

    const raw = [start, ...headers, "", ""].join("\r\n");
    const curlParts = [
      "curl -i -sS",
      "-X OPTIONS",
      `-H 'Origin: ${origin}'`,
      `-H 'Access-Control-Request-Method: ${acrm}'`,
    ];
    if (acrh) curlParts.push(`-H 'Access-Control-Request-Headers: ${acrh}'`);
    curlParts.push(`'${scheme}://${host}${path}'`);
    const curl = curlParts.join(" ");

    getEl("cors-raw").textContent = raw;
    getEl("cors-curl").textContent = curl;
  });

  getEl("cors-copy-curl")?.addEventListener("click", async () => {
    const t = getEl("cors-curl")?.textContent || "";
    if (!t.trim()) return;
    await navigator.clipboard.writeText(t);
    const b = getEl("cors-copy-curl");
    const old = b.textContent;
    b.textContent = "Copied!";
    setTimeout(() => (b.textContent = old), 1200);
  });

  getEl("cors-copy-raw")?.addEventListener("click", async () => {
    const t = getEl("cors-raw")?.textContent || "";
    if (!t.trim()) return;
    await navigator.clipboard.writeText(t);
    const b = getEl("cors-copy-raw");
    const old = b.textContent;
    b.textContent = "Copied!";
    setTimeout(() => (b.textContent = old), 1200);
  });

  getEl("cors-clear")?.addEventListener("click", () => {
    getEl("cors-raw").textContent = "";
    getEl("cors-curl").textContent = "";
  });

  getEl("cors-analyze")?.addEventListener("click", () => {
    const raw = getEl("cors-resp")?.value || "";
    if (!raw.trim()) return;

    const res =
      parsers && typeof parsers.parseResponse === "function"
        ? parsers.parseResponse(raw)
        : { headers: {}, statusCode: NaN, statusText: "" };

    const h = res.headers || {};
    const lines = [];

    const acao = h["Access-Control-Allow-Origin"];
    const acac = String(h["Access-Control-Allow-Credentials"] || "");
    const acam = h["Access-Control-Allow-Methods"] || "";
    const acarh = h["Access-Control-Allow-Headers"] || "";
    const vary = String(h.Vary || "");

    const origin = getEl("cors-origin")?.value || "";
    const acrm = getEl("cors-acrm-select")?.value || "";
    const acrh = buildAcrh();
    const expectCreds = getEl("cors-expect-credentials")?.checked || false;

    if (!acao && !acam && !acarh) {
      lines.push("❗ No CORS headers detected.");
    } else {
      lines.push(`ACAO: ${acao || "(none)"}`);
      lines.push(`ACAC: ${acac || "(none)"}`);
      lines.push(`ACAM: ${acam || "(none)"}`);
      lines.push(`ACAH: ${acarh || "(none)"}`);
      lines.push(`Vary: ${vary || "(none)"}`);

      if (acao === "*" && /true/i.test(acac)) {
        lines.push("❗ Wildcard + credentials is insecure.");
      }
      if (acao && origin && acao === origin && !/origin/i.test(vary)) {
        lines.push("⚠️ ACAO reflects Origin but missing Vary: Origin.");
      }
      if (acao && /null/i.test(String(acao))) {
        lines.push("⚠️ Accepts null origin.");
      }

      if (acam && acrm) {
        const allowed = String(acam)
          .toUpperCase()
          .split(",")
          .map((s) => s.trim());
        if (!allowed.includes(acrm.toUpperCase())) {
          lines.push(`⚠️ Method ${acrm} not listed in ACAM: ${acam}`);
        }
      }

      if (acrh) {
        const want = acrh
          .split(",")
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean);
        const allowed = String(acarh)
          .toLowerCase()
          .split(",")
          .map((s) => s.trim());
        const missing = want.filter((w) => !allowed.includes(w));
        if (want.length && missing.length) {
          lines.push(
            `⚠️ Some requested headers not allowed: ${missing.join(", ")}`
          );
        }
      }

      if (expectCreds && !/true/i.test(acac || "")) {
        lines.push(
          "⚠️ Credentials expected but ACAC is not 'true' (browser will block)."
        );
      }
      if (!acao) {
        lines.push("⚠️ Missing ACAO entirely.");
      }
    }

    getEl("cors-report").textContent = lines.join("\n");
  });

  getEl("cors-analyze-clear")?.addEventListener("click", () => {
    getEl("cors-resp").value = "";
    getEl("cors-report").textContent = "";
  });

  function doExport() {
    const list = window.T3.findings || [];
    const selected = list.some((f) => f.includeInReport)
      ? list.filter((f) => f.includeInReport)
      : list;

    const lines = [];
    lines.push(`# HTTP Security Analysis Report`);
    lines.push("");
    lines.push(`- Score: ${window.T3.score ?? 0}/100`);
    lines.push(`- Transactions: ${window.T3.traffic.length}`);
    lines.push("");
    lines.push("## Findings");
    lines.push("");
    for (const f of selected) {
      lines.push(`### [${f.severity}] ${f.type}`);
      lines.push(`- Affected: ${f.affected || "n/a"}`);
      lines.push(`- Description: ${f.description || ""}`);
      if (f.evidence) {
        lines.push("");
        lines.push("```");
        lines.push(String(f.evidence));
        lines.push("```");
      }
      lines.push("");
    }
    const md = lines.join("\n");
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "http-security-report.md";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 500);
  }
  getEl("export-btn")?.addEventListener("click", doExport);
  getEl("export-btn-bottom")?.addEventListener("click", doExport);
  getEl("export-btn-report")?.addEventListener("click", doExport);

  getEl("csp-build")?.addEventListener("click", () => {
    const policy = {};
    const checked = document.querySelectorAll(".csp-opt:checked");
    checked.forEach(box => {
      const dir = box.dataset.dir;
      const val = box.dataset.val;
      if (!policy[dir]) policy[dir] = [];
      policy[dir].push(val);
    });

    const policyString = Object.entries(policy)
      .map(([dir, vals]) => `${dir} ${[...new Set(vals)].join(' ')}`)
      .join('; ');
    
    getEl("csp-built").textContent = `Content-Security-Policy: ${policyString}`;
  });

  getEl("csp-preset-strict")?.addEventListener("click", () => {
    const text = `object-src 'none'; script-src 'nonce-rAnd0m' 'strict-dynamic' https: http:; base-uri 'none';`;
    getEl("csp-workshop-input").value = `Content-Security-Policy: ${text}`;
    
    document.querySelectorAll(".csp-opt").forEach(box => box.checked = false);
    
    document.querySelector(".csp-opt[data-dir='object-src'][data-val=\"'none'\"]").checked = true;
    document.querySelector(".csp-opt[data-dir='base-uri'][data-val=\"'none'\"]").checked = true;
    document.querySelector(".csp-opt[data-dir='script-src'][data-val=\"'strict-dynamic'\"]").checked = true;
  });

  getEl("csp-copy-built")?.addEventListener("click", async () => {
    const text = getEl("csp-built")?.textContent || "";
    if (!text.trim()) return;
    await navigator.clipboard.writeText(text);
    const btn = getEl("csp-copy-built");
    const oldText = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = oldText), 1200);
  });


  getEl("pp-build")?.addEventListener("click", () => {
      const directives = [];
      const allFeatures = document.querySelectorAll(".pp-opt");
      allFeatures.forEach(box => {
          const feature = box.dataset.feat;
          if (box.checked) {
              directives.push(`${feature}=(self)`);
          } else {
              directives.push(`${feature}=()`);
          }
      });
      getEl("pp-built").textContent = `Permissions-Policy: ${directives.join(', ')}`;
  });

  getEl("pp-preset-strict")?.addEventListener("click", () => {
      document.querySelectorAll(".pp-opt").forEach(box => box.checked = false);
      getEl("pp-build")?.click();
  });

  getEl("pp-copy-built")?.addEventListener("click", async () => {
    const text = getEl("pp-built")?.textContent || "";
    if (!text.trim()) return;
    await navigator.clipboard.writeText(text);
    const btn = getEl("pp-copy-built");
    const oldText = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = oldText), 1200);
  });

  getEl("coopcoep-gen")?.addEventListener("click", () => {
      const text = `Cross-Origin-Opener-Policy: same-origin\nCross-Origin-Embedder-Policy: require-corp`;
      getEl("coopcoep-output").textContent = text;
  });


  const harInput = getEl("har-input");
  const harDrop = getEl("har-drop");
  const harPaste = getEl("har-paste");
  const harStatus = getEl("har-import-status");

  async function importHarText(text) {
    if (!text) return;
    const txs =
      parsers && typeof parsers.parseHarText === "function"
        ? parsers.parseHarText(text)
        : [];
    if (!txs.length) {
      if (harStatus) harStatus.textContent = "No valid entries found in HAR.";
      return;
    }
    window.T3.traffic = [...(window.T3.traffic || []), ...txs];
    updateSessionCount();
    renderSessionList();
    cache.renderCacheLab(window.T3.traffic, {
      ignoreTracking:
        getEl("origin-ignore-tracking") &&
        getEl("origin-ignore-tracking").checked,
    });
    renderAdvancedCookieAnalysis();
    updateSelectors();
    window.T3utils.saveSession();
    if (harStatus) harStatus.textContent = `Imported ${txs.length} transactions.`;
  }

  async function importHarFile(file) {
    if (!file) return;
    const text = await file.text();
    importHarText(text);
  }

  harInput?.addEventListener("change", () => {
    const f = harInput.files?.[0];
    importHarFile(f);
  });
  if (harDrop) {
    ["dragenter", "dragover"].forEach((ev) =>
      harDrop.addEventListener(ev, (e) => {
        e.preventDefault();
        harDrop.classList.add("dragover");
      })
    );
    ["dragleave", "drop"].forEach((ev) =>
      harDrop.addEventListener(ev, (e) => {
        e.preventDefault();
        harDrop.classList.remove("dragover");
      })
    );
    harDrop.addEventListener("drop", (e) => {
      const f = e.dataTransfer?.files?.[0];
      importHarFile(f);
    });
  }
  getEl("har-import-clear")?.addEventListener("click", () => {
    if (harInput) harInput.value = "";
    if (harPaste) harPaste.value = "";
    if (harStatus) harStatus.textContent = "";
    const fileNameDisplay = getEl("har-file-name");
    if(fileNameDisplay) fileNameDisplay.textContent = 'No file chosen';
  });
  getEl("har-import-text")?.addEventListener("click", () => {
    importHarText(harPaste?.value || "");
  });

  function latestResWithCsp(traffic) {
    let latest = null;
    for (const tx of traffic) {
      if (tx.response && tx.response.headers?.["Content-Security-Policy"]) {
        latest = tx.response;
      }
    }
    return latest;
  }
  function dedupe(arr) {
    const seen = new Set();
    const out = [];
    for (const f of arr) {
      const key = `${f.type}|${f.severity}|${f.affected}|${f.description}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
    return out;
  }

  updateSelectors();
}

document.addEventListener("DOMContentLoaded", appMain);
