window.T3 =
  window.T3 || { findings: [], score: null, traffic: [], cspAudit: null };

(function initRouter() {
  function showRoute(route) {
    document.querySelectorAll(".route").forEach((el) => {
      const r = el.getAttribute("data-route");
      el.classList.toggle("hidden", r !== route);
    });
    document.querySelectorAll(".nav-link").forEach((a) => {
      a.classList.toggle("active", a.getAttribute("href") === "#" + route);
    });

    if (
      route === "/diff" &&
      typeof window.populateDiffSelectors === "function"
    ) {
      window.populateDiffSelectors();
    }
    if (route === "/cache" && window.T3cache) {
      const t = (window.T3 && window.T3.traffic) || [];
      const cb = document.getElementById("origin-ignore-tracking");
      window.T3cache.renderCacheLab(t, {
        ignoreTracking: !!(cb && cb.checked),
      });
    }
  }

  function onHash() {
    const raw = location.hash || "#/inputs";
    const route = raw.replace("#", "");
    const known = [
      "/inputs",
      "/results",
      "/cache",
      "/diff",
      "/payloads",
      "/cookies",
      "/csp",
      "/project",
      "/report",
      "/cors", // CORS Lab
    ];
    showRoute(known.includes(route) ? route : "/inputs");
  }

  window.addEventListener("hashchange", onHash);
  window.addEventListener("DOMContentLoaded", onHash);
})();

window.T3utils = {
  normHeaderName(name) {
    if (!name) return "";
    return String(name)
      .toLowerCase()
      .split("-")
      .map((p) => (p ? p[0].toUpperCase() + p.slice(1) : ""))
      .join("-");
  },

  safeTrim(s) {
    return (s || "").replace(/^\s+|\s+$/g, "");
  },

  splitHeadersAndBody(raw) {
    if (typeof raw !== "string") return { head: "", body: "" };
    const idx = raw.search(/\r?\n\r?\n/);
    if (idx === -1) return { head: raw, body: "" };
    return {
      head: raw.slice(0, idx),
      body: raw.slice(idx).replace(/^\r?\n\r?\n/, ""),
    };
  },

  parseHeaderLines(head) {
    const lines = String(head || "").split(/\r?\n/);
    const headers = {};
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line || /^\s*$/.test(line)) continue;
      const m = line.match(/^\s*([^:]+)\s*:\s*(.*)\s*$/);
      if (!m) continue;
      const name = this.normHeaderName(m[1]);
      const val = m[2].trim();
      if (headers[name] !== undefined) {
        const prev = headers[name];
        headers[name] = Array.isArray(prev) ? [...prev, val] : [prev, val];
      } else {
        headers[name] = val;
      }
    }
    return headers;
  },

  parseStartLineTokens(line) {
    return (line || "").trim().split(/\s+/);
  },

  escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;");
  },

  tryDecodeAll(s) {
    const out = [];
    try {
      const url = decodeURIComponent(s);
      if (url !== s) out.push({ kind: "URL", value: url });
      const url2 = decodeURIComponent(url);
      if (url2 !== url) out.push({ kind: "URL x2", value: url2 });
    } catch {}
    try {
      const b = atob(String(s).replace(/\s+/g, ""));
      out.push({ kind: "Base64", value: b });
    } catch {}
    try {
      const hex = String(s).replace(/[^0-9a-f]/gi, "");
      if (hex.length % 2 === 0 && hex.length >= 2) {
        const v = hex
          .match(/.{2}/g)
          .map((h) => String.fromCharCode(parseInt(h, 16)))
          .join("");
        out.push({ kind: "Hex", value: v });
      }
    } catch {}
    try {
      const txt = String(s)
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'");
      if (txt !== s) out.push({ kind: "HTML", value: txt });
    } catch {}
    return out;
  },

  detectPatterns(s) {
    const patterns = [];
    if (/[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/.test(s)) {
      patterns.push("JWT");
    }
    const ts = String(s).match(/\b1\d{9}\b/);
    if (ts) {
      const d = new Date(Number(ts[0]) * 1000);
      if (!isNaN(d)) patterns.push(`UnixTS -> ${d.toISOString()}`);
    }
    if (
      /\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i.test(
        s
      )
    ) {
      patterns.push("UUIDv4");
    }
    return patterns;
  },

  saveSession() {
    try {
      const data = {
        traffic: window.T3.traffic || [],
        findings: window.T3.findings || [],
        score: window.T3.score || 0,
        cspAudit: window.T3.cspAudit || null,
      };
      localStorage.setItem("t3-session", JSON.stringify(data));
    } catch {}
  },

  loadSession() {
    try {
      const raw = localStorage.getItem("t3-session");
      if (!raw) return null;
      return JSON.parse(raw);
    } catch {
      return null;
    }
  },
};
