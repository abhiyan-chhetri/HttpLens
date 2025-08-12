(function attachCsp() {
  const KNOWN_RISKS = {
    "www.googletagmanager.com":
      "Known JSONP endpoints; CSP bypass risk if scripts allowed.",
    "ajax.googleapis.com":
      "JSONP and Angular libraries; known CSP bypass vectors.",
    "maps.googleapis.com": "JSONP endpoints; CSP bypass risk.",
    "googleads.g.doubleclick.net": "JSONP endpoints; CSP bypass risk.",
  };

  function ensureSuppressSet(audit) {
    if (!audit) return { suppress: new Set() };
    if (audit.suppress instanceof Set) return audit;
    if (Array.isArray(audit.suppress)) {
      audit.suppress = new Set(audit.suppress);
      return audit;
    }
    if (audit.suppress && typeof audit.suppress === "object") {
      audit.suppress = new Set(Object.keys(audit.suppress));
      return audit;
    }
    audit.suppress = new Set();
    return audit;
  }

  function parseCspDirectives(csp) {
    const out = {};
    const parts = String(csp || "")
      .split(";")
      .map((s) => s.trim())
      .filter(Boolean);
    for (const p of parts) {
      const [dir, ...vals] = p.split(/\s+/);
      if (!dir) continue;
      out[dir.toLowerCase()] = vals;
    }
    return out;
  }

  function evaluateCspForUi(res) {
    if (!res) return null;
    const csp = res.headers?.["Content-Security-Policy"];
    if (!csp) return null;

    const d = parseCspDirectives(csp);
    const sections = [];
    const suppress = new Set();

    function mkItem(label, type, why, fix, key) {
      return { label, type, why, fix, key };
    }
    function addHosts(vals, items, dir, forScriptElem = false) {
      vals
        .filter((v) => /^https?:\/\//i.test(v))
        .forEach((host) => {
          const h = host.replace(/^https?:\/\/(www\.)?/i, "").replace(/\/+$/, "");
          if (KNOWN_RISKS[h]) {
            items.push(
              mkItem(
                host,
                "error",
                KNOWN_RISKS[h],
                "Prefer nonces/hashes + 'strict-dynamic' or remove host allowlisting.",
                `${dir}||${host}`
              )
            );
          } else {
            items.push(
              mkItem(
                host,
                forScriptElem ? "info" : "ok",
                forScriptElem
                  ? "Ensure it does not serve JSONP/Angular; allowlists can be bypassed."
                  : "Allowed host.",
                "",
                `${dir}||${host}`
              )
            );
          }
        });
    }

    {
      const dir = "default-src";
      const vals = d[dir] || [];
      const items = [];
      if (vals.length === 0)
        items.push(
          mkItem(
            "default-src missing",
            "warn",
            "No default fallback; more permissive directives may apply.",
            "Define default-src 'none' and add narrow per-type directives.",
            "default-src||missing"
          )
        );
      if (vals.includes("'self'"))
        items.push(
          mkItem("'self'", "ok", "Restricts to same-origin resources.", "", `${dir}||'self'`)
        );
      sections.push({ dir, vals, items });
    }

    {
      const dir = "script-src";
      const vals = d[dir] || d["default-src"] || [];
      const items = [];
      if (vals.includes("'unsafe-inline'"))
        items.push(
          mkItem(
            "'unsafe-inline'",
            "error",
            "Allows inline scripts and on* handlers; enables straightforward XSS.",
            "Remove 'unsafe-inline'. Use nonces/hashes; consider 'strict-dynamic'.",
            "script-src||'unsafe-inline'"
          )
        );
      if (vals.includes("'unsafe-eval'"))
        items.push(
          mkItem(
            "'unsafe-eval'",
            "warn",
            "Allows eval-like APIs; widens XSS impact.",
            "Remove 'unsafe-eval' and refactor code to avoid eval APIs.",
            "script-src||'unsafe-eval'"
          )
        );
      if (!vals.includes("'strict-dynamic'"))
        items.push(
          mkItem(
            "Host allowlists",
            "warn",
            "Host allowlists can be bypassed (e.g., JSONP). Nonces/hashes + 'strict-dynamic' are safer.",
            "Adopt nonces/hashes and include 'strict-dynamic'; avoid broad host allowlists.",
            "script-src||allowlist"
          )
        );
      addHosts(vals, items, dir);
      sections.push({ dir, vals, items });
    }

    {
      const dir = "script-src-elem";
      const vals = d[dir] || [];
      const items = [];
      if (vals.includes("'unsafe-inline'"))
        items.push(
          mkItem(
            "'unsafe-inline'",
            "error",
            "Allows risky in-page <script> elements.",
            "Use nonces/hashes; remove 'unsafe-inline'.",
            "script-src-elem||'unsafe-inline'"
          )
        );
      if (vals.includes("'unsafe-eval'"))
        items.push(
          mkItem(
            "'unsafe-eval'",
            "warn",
            "Enables eval-like APIs for scripts loaded via elements.",
            "Remove 'unsafe-eval' and refactor.",
            "script-src-elem||'unsafe-eval'"
          )
        );
      addHosts(vals, items, dir, true);
      if (vals.some((v) => /^https?:\/\/ajax\.googleapis\.com/.test(v))) {
        items.push(
          mkItem(
            "https://ajax.googleapis.com",
            "error",
            "JSONP and Angular libraries; known CSP bypass vectors.",
            "Prefer nonces/hashes + 'strict-dynamic'; avoid allowing this host.",
            "script-src-elem||ajax.googleapis.com"
          )
        );
      }
      sections.push({ dir, vals, items });
    }

    for (const dir of [
      "style-src",
      "connect-src",
      "img-src",
      "font-src",
      "frame-src",
      "manifest-src",
    ]) {
      const vals = d[dir] || d["default-src"] || [];
      const items = [];
      if (dir === "style-src" && vals.includes("'unsafe-inline'"))
        items.push(
          mkItem(
            "'unsafe-inline'",
            "warn",
            "Allows inline styles; may assist style-based injection.",
            "Prefer nonce-based styles or avoid inline styles.",
            "style-src||'unsafe-inline'"
          )
        );
      if (vals.includes("'self'"))
        items.push(
          mkItem("'self'", "ok", "Restricts to same-origin resources.", "", `${dir}||'self'`)
        );
      addHosts(vals, items, dir);
      sections.push({ dir, vals, items });
    }

    const tt = (d["require-trusted-types-for"] || []).join(" ");
    const meta = [];
    if (!/script/.test(tt || "")) {
      meta.push({
        type: "info",
        message:
          "Consider require-trusted-types-for 'script' to mitigate DOM XSS.",
      });
    }

    return ensureSuppressSet({ csp, sections, meta, suppress });
  }

  function emojiFor(type) {
    return type === "error"
      ? "❗"
      : type === "warn"
      ? "⚠️"
      : type === "ok"
      ? "✅"
      : "ℹ️";
  }

  function renderCspAudit(audit) {
    const root = document.getElementById("csp-report");
    if (!root) return;
    root.innerHTML = "";
    if (!audit) {
      const card = document.createElement("div");
      card.className = "card";
      const body = document.createElement("div");
      body.className = "card-body text-gray-400";
      body.textContent = "No CSP header found in analyzed responses.";
      card.appendChild(body);
      root.appendChild(card);
      return;
    }

    audit = ensureSuppressSet(audit);

    const titleCard = document.createElement("div");
    titleCard.className = "card";
    const titleBody = document.createElement("div");
    titleBody.className = "card-body";
    const p = document.createElement("div");
    p.className = "text-sm text-gray-300 mb-2";
    p.textContent = "Raw Content-Security-Policy";
    const pre = document.createElement("pre");
    pre.className = "code-block";
    pre.textContent = audit.csp || "";
    titleBody.appendChild(p);
    titleBody.appendChild(pre);
    titleCard.appendChild(titleBody);
    root.appendChild(titleCard);

    for (const section of audit.sections || []) {
      const card = document.createElement("div");
      card.className = "card";

      const header = document.createElement("div");
      header.className =
        "card-header cursor-pointer select-none flex items-center justify-between";

      const left = document.createElement("div");
      const title = document.createElement("div");
      title.className = "card-title";
      title.textContent = section.dir;
      left.appendChild(title);

      const riskRow = document.createElement("div");
      riskRow.className = "text-xs text-gray-300 mt-1";
      const riskyInline = (section.items || [])
        .filter((it) => {
          return (
            (it.type === "error" || it.type === "warn") &&
            !audit.suppress.has(it.key)
          );
        })
        .slice(0, 4)
        .map((it) => `${emojiFor(it.type)} ${it.label}`);
      if (riskyInline.length) {
        riskRow.textContent = riskyInline.join("  •  ");
        left.appendChild(riskRow);
      }

      const right = document.createElement("div");
      right.className = "text-xs text-gray-400";
      const counts = { error: 0, warn: 0, info: 0, ok: 0 };
      (section.items || []).forEach((it) => {
        if (audit.suppress.has(it.key)) return;
        counts[it.type] = (counts[it.type] || 0) + 1;
      });
      const parts = [];
      if (counts.error) parts.push(`❗${counts.error}`);
      if (counts.warn) parts.push(`⚠️${counts.warn}`);
      if (counts.info) parts.push(`ℹ️${counts.info}`);
      if (counts.ok) parts.push(`✅${counts.ok}`);
      right.textContent = parts.join("  ");

      header.appendChild(left);
      header.appendChild(right);

      const body = document.createElement("div");
      body.className = "card-body hidden";

      const valsDiv = document.createElement("div");
      valsDiv.className = "text-xs text-gray-400 mb-2";
      valsDiv.textContent =
        (section.vals || []).length > 0
          ? "Values: " + section.vals.join(" ")
          : "Values: (none)";
      body.appendChild(valsDiv);

      for (const item of section.items || []) {
        if (audit.suppress.has(item.key)) continue;
        const row = document.createElement("div");
        row.className = "flex items-start gap-3 text-sm py-1";

        const badge = document.createElement("span");
        badge.textContent = emojiFor(item.type);

        const labels = document.createElement("div");
        const label = document.createElement("div");
        label.className = "text-gray-200";
        label.textContent = item.label;
        const why = document.createElement("div");
        why.className = "text-gray-400 text-xs";
        why.textContent = item.why || "";
        const fix = document.createElement("div");
        fix.className = "text-gray-400 text-xs italic";
        fix.textContent = item.fix || "";
        labels.appendChild(label);
        if (item.why) labels.appendChild(why);
        if (item.fix) labels.appendChild(fix);

        const falseBtn = document.createElement("button");
        falseBtn.className = "btn btn-sm";
        falseBtn.textContent = "Mark false positive";
        falseBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          audit.suppress.add(item.key);
          renderCspAudit(audit);
          syncCspFindingsIntoMain();
        });

        row.appendChild(badge);
        row.appendChild(labels);
        row.appendChild(falseBtn);
        body.appendChild(row);
      }

      header.addEventListener("click", () => {
        body.classList.toggle("hidden");
      });

      card.appendChild(header);
      card.appendChild(body);
      root.appendChild(card);
    }

    const exp = document.getElementById("csp-expand-all");
    if (exp) exp.addEventListener("click", () => toggleAllCsp(true));
    const col = document.getElementById("csp-collapse-all");
    if (col) col.addEventListener("click", () => toggleAllCsp(false));
  }

  function toggleAllCsp(expand) {
    document
      .querySelectorAll("#csp-report .card .card-body")
      .forEach((b) => b.classList.toggle("hidden", !expand));
  }

  function auditItemsToFindings(audit) {
    if (!audit) return [];
    audit = ensureSuppressSet(audit);
    const out = [];
    for (const section of audit.sections || []) {
      for (const item of section.items || []) {
        if (audit.suppress.has(item.key)) continue;
        if (item.type === "error" || item.type === "warn") {
          out.push({
            type: "csp",
            severity: item.type === "error" ? "Medium" : "Low",
            status: "potential",
            description: `${section.dir}: ${item.label} — ${item.why}`,
            evidence: item.fix || "",
            affected: "CSP",
            tags: ["csp"],
          });
        }
      }
    }
    return out;
  }

  function syncCspFindingsIntoMain() {
    const T = window.T3;
    if (!T) return;
    T.cspAudit = ensureSuppressSet(T.cspAudit);
    T.findings = (T.findings || []).filter(
      (f) => !(f.type === "csp" && f.source === "audit")
    );
    const add = auditItemsToFindings(T.cspAudit).map((f) => ({
      ...f,
      source: "audit",
      id: `csp-${Math.random().toString(36).slice(2)}`,
    }));
    T.findings = dedupeFindings([...T.findings, ...add]);
    const ui = window.T3ui;
    if (ui) {
      T.score = ui.calculateScore(T.findings);
      ui.updateScoreUI(T.score);
      ui.renderDashboard(T.findings);
    }
  }

  function dedupeFindings(arr) {
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

  window.T3csp = {
    parseCspDirectives,
    evaluateCspForUi,
    renderCspAudit,
    auditItemsToFindings,
    syncCspFindingsIntoMain,
  };
})();
