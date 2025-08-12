(function attachUI() {
  function severityClass(sev) {
    return {
      Critical: "sev-critical",
      High: "sev-high",
      Medium: "sev-medium",
      Low: "sev-low",
      Info: "sev-info",
    }[sev];
  }

  function updateScoreUI(score) {
    const el = document.getElementById("security-score");
    if (!el) return;
    el.classList.remove("text-green-400", "text-yellow-400", "text-red-400");
    if (score === null || score === undefined || Number.isNaN(Number(score))) {
      el.textContent = "—";
      return;
    }
    const s = Number(score);
    el.textContent = String(s);
    if (s >= 85) el.classList.add("text-green-400");
    else if (s >= 60) el.classList.add("text-yellow-400");
    else el.classList.add("text-red-400");
  }

  function calculateScore(findings) {
    let score = 100;
    const penalties = {
      Critical: 10,
      High: 5,
      Medium: 3,
      Low: 1,
      Info: 0,
    };
    for (const f of findings || []) {
      const sev = f.severity || "Info";
      const p = penalties[sev] ?? 0;
      score -= p;
    }
    if (score < 0) score = 0;
    if (score > 100) score = 100;
    return Math.round(score);
  }

  function renderScoreBreakdown(findings) {
    const root = document.getElementById("score-breakdown");
    if (!root) return;
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    const penalties = {
      Critical: 10,
      High: 5,
      Medium: 3,
      Low: 1,
      Info: 0,
    };
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

  function renderFilters(findings, onChange) {
    const root = document.getElementById("results-filters");
    if (!root) return;
    root.innerHTML = "";

    const levels = ["Critical", "High", "Medium", "Low", "Info"];
    const counts = Object.fromEntries(levels.map((l) => [l, 0]));
    (findings || []).forEach((f) => (counts[f.severity] = (counts[f.severity] || 0) + 1));

    const active = new Set(levels);

    const make = (sev) => {
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
      chip.className = `finding-severity ${severityClass(sev) || "sev-info"}`;
      chip.textContent = `${sev} ${counts[sev] || 0}`;
      wrap.appendChild(cb);
      wrap.appendChild(chip);
      return wrap;
    };

    levels.forEach((s) => root.appendChild(make(s)));
  }

  function filterFindingsBySeverity(findings, sevSet) {
    if (!sevSet || sevSet.size === 0) return findings || [];
    return (findings || []).filter((f) => sevSet.has(f.severity));
  }

  function markAddToReport(f, card) {
    f.includeInReport = !f.includeInReport;
    const btn = card.querySelector(".btn-add-report");
    if (btn)
      btn.textContent = f.includeInReport ? "Added to Report ✓" : "Add to Report";
  }

  function renderDashboard(findings) {
    const dash = document.getElementById("results-dashboard");
    if (!dash) return;
    dash.innerHTML = ""; // Clear previous findings

    if (!findings || findings.length === 0) {
      const empty = document.createElement("div");
      empty.className = "card";
      const body = document.createElement("div");
      body.className = "card-body text-gray-400";
      body.textContent =
        "No findings from passive analysis. Consider active probing if needed.";
      empty.appendChild(body);
      dash.appendChild(empty);
      return;
    }

    for (const f of findings) {
      const card = document.createElement("div");
      card.className = "card";
      card.id = f.id;

      const header = document.createElement("div");
      header.className = "card-header";

      const left = document.createElement("div");
      left.className = "flex items-center gap-2 flex-wrap";

      const sev = document.createElement("span");
      sev.className = `finding-severity ${severityClass(f.severity) || "sev-info"}`;
      sev.textContent = f.severity;

      const status = document.createElement("span");
      status.className =
        "text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-200";
      status.textContent = f.status === "confirmed" ? "Confirmed" : "Potential";

      const type = document.createElement("span");
      type.className = "text-sm text-indigo-300";
      type.textContent = f.type;

      left.appendChild(sev);
      left.appendChild(status);
      left.appendChild(type);

      const right = document.createElement("div");
      right.className = "flex items-center gap-2";

      const fpBtn = document.createElement("button");
      fpBtn.className = "btn btn-sm";
      fpBtn.style.background = "#372929"; // Muted red background
      fpBtn.style.borderColor = "#543838";
      fpBtn.textContent = "False Positive";
      fpBtn.addEventListener("click", () => {
        window.T3.findings = (window.T3.findings || []).filter((x) => x.id !== f.id);
        
        window.T3.score = calculateScore(window.T3.findings);
        updateScoreUI(window.T3.score);
        renderScoreBreakdown(window.T3.findings);
        
        renderDashboard(window.T3.findings);
        
        window.T3utils.saveSession();
      });

      const addBtn = document.createElement("button");
      addBtn.className = "btn btn-sm btn-add-report";
      addBtn.textContent = f.includeInReport ? "Added to Report ✓" : "Add to Report";
      addBtn.addEventListener("click", () => {
        markAddToReport(f, card);
        window.T3utils.saveSession();
      });

      const meta = document.createElement("div");
      meta.className = "text-right text-xs text-gray-400";
      meta.innerHTML = `<div>ID: ${window.T3utils.escapeHtml(f.id)}</div>`;

      right.appendChild(addBtn);
      right.appendChild(fpBtn); // Add the new button to the UI
      right.appendChild(meta);
      
      header.appendChild(left);
      header.appendChild(right);
      card.appendChild(header);

      const body = document.createElement("div");
      body.className = "card-body space-y-2";

      if (f.description) {
        const desc = document.createElement("div");
        desc.className = "text-gray-200";
        desc.textContent = f.description;
        body.appendChild(desc);
      }

      if (f.affected) {
        const affected = document.createElement('div');
        affected.className = 'text-sm text-gray-400';
        affected.innerHTML = `<b>Affected:</b> ${window.T3utils.escapeHtml(f.affected)}`;
        body.appendChild(affected);
      }

      if (f.evidence) {
        const evidence = document.createElement("pre");
        evidence.className = "code-block";
        evidence.textContent = (f.evidence || "").toString();
        body.appendChild(evidence);
      }
      
      if (f.curlCommand) {
        const block = document.createElement("div");
        block.className = "mt-2 space-y-2";

        const label = document.createElement("div");
        label.className = "text-gray-300";
        label.textContent = "Guided probe (curl):";

        const code = document.createElement("pre");
        code.className = "code-block";
        code.textContent = f.curlCommand;

        const btn = document.createElement("button");
        btn.className = "btn";
        btn.textContent = "Paste Response for Analysis";

        const container = document.createElement("div");
        container.className = "space-y-2";

        btn.addEventListener("click", () => {
            if (container.querySelector(".analysis-box")) {
                return;
            }
            const analysisBox = document.createElement("div");
            analysisBox.className = "analysis-box mt-2 space-y-2";

            const ta = document.createElement("textarea");
            ta.rows = 8;
            ta.className = "textarea";
            ta.placeholder = "Paste the full raw HTTP response here. The finding will update automatically if the probe is detected.";
            
            const resNote = document.createElement("div");
            resNote.className = "text-xs text-gray-500";
            resNote.textContent = "Awaiting response that contains the probe value...";
            
            analysisBox.appendChild(ta);
            analysisBox.appendChild(resNote);
            container.appendChild(analysisBox);

            ta.addEventListener("input", () => {
                const confirmed = analyzeActiveResponse(f, ta.value, card);
                if (confirmed) {
                    resNote.innerHTML = '<span class="text-green-400">✅ Success! Probe detected and finding marked as Confirmed.</span>';
                    ta.style.borderColor = '#22c55e';
                }
            });
        });

        block.appendChild(label);
        block.appendChild(code);
        block.appendChild(btn);
        block.appendChild(container);
        body.appendChild(block);
      }

      card.appendChild(body);
      dash.appendChild(card);
    }
  }

  function analyzeActiveResponse(finding, rawResponse, cardEl) {
    try {
      const text = String(rawResponse || "");
      let confirmed = false;

      if (finding.type === "cache-key-collision") {
        const tokenMatch = finding.curlCommand?.match(/\?(t3test=\d+)/);
        if (tokenMatch && text.includes(tokenMatch[1])) confirmed = true;
        if (/^age:\s*[1-9]\d*/im.test(text)) confirmed = true;
      }
      if (
        finding.type === "unkeyed-header-reflection" ||
        finding.type === "unkeyed-parameter-poisoning"
      ) {
        const probe = finding._probeValue;
        if (probe && text.includes(probe)) confirmed = true;
      }

      if (confirmed && finding.status !== 'confirmed') {
        finding.status = "confirmed";
        const statusBadge = cardEl.querySelector(".bg-gray-700");
        if (statusBadge) {
          statusBadge.textContent = "Confirmed";
          statusBadge.classList.remove('bg-gray-700');
          statusBadge.classList.add('bg-green-700');
        }
        
        if (finding.type === "unkeyed-header-reflection") {
          finding.severity = "Critical";
          const sevEl = cardEl.querySelector(".finding-severity");
          if (sevEl) {
            sevEl.textContent = "Critical";
            sevEl.className = "finding-severity sev-critical";
          }
        }

        if (window.T3.findings) {
          window.T3.score = calculateScore(window.T3.findings);
          updateScoreUI(window.T3.score);
        }
      }
      return confirmed;
    } catch {
      return false;
    }
  }

  function generateCurlCommands(findings) {
    const updated = findings.map((f) => ({ ...f }));
    for (const f of updated) {
      try {
        if (f.type === "cache-key-collision") {
          const [host, path] = String(f.affected || "").split(" ");
          const url = `https://${host}${path || "/"}`;
          const token = "t3test=" + Date.now();
          f.curlCommand =
            `curl -i -sS '${url}?${token}' -H 'Cache-Control: no-cache'`;
        }
        if (f.type === "unkeyed-header-reflection") {
          const [host, path] = String(f.affected || "").split(" ");
          const url = `https://${host}${path || "/"}`;
          const headerName = (f.description.match(/"([^"]+)"/) || [])[1];
          const probeVal = "t3test-" + Date.now();
          if (headerName) {
            f.curlCommand = `curl -i -sS '${url}' -H '${headerName}: ${probeVal}'`;
            f._probeValue = probeVal;
          }
        }
        if (f.type === "unkeyed-parameter-poisoning") {
          const [host, path] = String(f.affected || "").split(" ");
          const url = `https://${host}${path || "/"}`;
          const param = "x";
          const probeVal = "t3test-" + Date.now();
          f.curlCommand = `curl -i -sS '${url}?${param}=${probeVal}'`;
          f._probeValue = probeVal;
        }
        if (f.type === "request-smuggling") {
          f.curlCommand =
            "printf 'POST / HTTP/1.1\\r\\nHost: target\\r\\n" +
            "Transfer-Encoding: chunked\\r\\nContent-Length: 4\\r\\n\\r\\n" +
            "0\\r\\n\\r\\n' | nc target 80";
        }
      } catch {}
    }
    return updated;
  }

  function diffRender(leftText, rightText, changesOnly) {
    const A = String(leftText || "").split("\n");
    const B = String(rightText || "").split("\n");

    const n = A.length;
    const m = B.length;
    const dp = Array.from({ length: n + 1 }, () => Array(m + 1).fill(0));
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        if (A[i] === B[j]) dp[i][j] = dp[i + 1][j + 1] + 1;
        else dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
    const script = [];
    let i = 0,
      j = 0;
    while (i < n && j < m) {
      if (A[i] === B[j]) {
        script.push({ t: "eq", a: A[i], b: B[j] });
        i++;
        j++;
      } else if (dp[i + 1][j] >= dp[i][j + 1]) {
        script.push({ t: "del", a: A[i] });
        i++;
      } else {
        script.push({ t: "add", b: B[j] });
        j++;
      }
    }
    while (i < n) {
      script.push({ t: "del", a: A[i++] });
    }
    while (j < m) {
      script.push({ t: "add", b: B[j++] });
    }

    const leftEl = document.getElementById("diff-left");
    const rightEl = document.getElementById("diff-right");
    if (!leftEl || !rightEl) return;

    leftEl.innerHTML = "";
    rightEl.innerHTML = "";

    for (const step of script) {
      if (step.t === "eq") {
        if (!changesOnly) {
          const l = document.createElement("div");
          l.className = "diff-line diff-eq";
          l.textContent = step.a;
          const r = document.createElement("div");
          r.className = "diff-line diff-eq";
          r.textContent = step.b;
          leftEl.appendChild(l);
          rightEl.appendChild(r);
        }
      } else if (step.t === "del") {
        const l = document.createElement("div");
        l.className = "diff-line diff-del";
        l.textContent = step.a;
        leftEl.appendChild(l);
        const r = document.createElement('div');
        r.className = 'diff-line';
        r.innerHTML = '&nbsp;';
        rightEl.appendChild(r);
      } else if (step.t === "add") {
        const l = document.createElement('div');
        l.className = 'diff-line';
        l.innerHTML = '&nbsp;';
        leftEl.appendChild(l);
        const r = document.createElement("div");
        r.className = "diff-line diff-add";
        r.textContent = step.b;
        rightEl.appendChild(r);
      }
    }
  }

  window.T3ui = {
    updateScoreUI,
    calculateScore,
    renderDashboard,
    generateCurlCommands,
    renderDiff: diffRender,
    renderFilters,
    renderScoreBreakdown,
    filterFindingsBySeverity
  };
})();
