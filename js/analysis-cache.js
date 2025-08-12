(function attachCacheAndPayloadEngines() {
  const U = window.T3utils || {
    normHeaderName: (s) =>
      String(s || "")
        .toLowerCase()
        .split("-")
        .map((p) => (p ? p[0].toUpperCase() + p.slice(1) : ""))
        .join("-"),
    safeTrim: (s) => (s || "").replace(/^\s+|\s+$/g, ""),
  };

  function urlParts(path) {
    const [p, q] = String(path || "/").split("?");
    return { path: p || "/", query: q || "" };
  }

  function parseQueryParams(qs) {
    const out = {};
    for (const kv of String(qs || "").split("&")) {
      if (!kv) continue;
      const [k, v = ""] = kv.split("=");
      const key = decodeURIComponent(k || "").trim();
      const val = decodeURIComponent(v || "");
      if (!key) continue;
      if (out[key] === undefined) out[key] = [];
      out[key].push(val);
    }
    return out;
  }

  function groupBy(arr, keyFn) {
    const map = new Map();
    for (const x of arr) {
      const k = keyFn(x);
      const v = map.get(k) || [];
      v.push(x);
      map.set(k, v);
    }
    return map;
  }

  function simpleHash(s) {
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
    return (h >>> 0).toString(16);
  }

  function isTrackingParam(name) {
    return /^(utm_|fbclid$|gclid$)/i.test(name || "");
  }

  function normalizePath(p) {
    try {
      return p.replace(/\/{2,}/g, "/").replace(/\/\.\//g, "/");
    } catch {
      return p;
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

  function runPassiveAnalysis(trafficArray) {
    let findings = [];

    for (const tx of trafficArray) {
      findings.push(...checkUnkeyedHeaders(tx));
      findings.push(...checkRequestSmugglingSignatures(tx));
      findings.push(...checkMisconfigurations(tx));
      findings.push(...checkSecurityHeaders(tx));
      findings.push(...checkCors(tx)); // NEW
      findings.push(...checkHstsPreload(tx)); // NEW
      findings.push(...checkCookies(tx));

      findings.push(...checkUnkeyedParameterPoisoning(tx));
      findings.push(...checkParameterCloaking(tx));
      findings.push(...checkFatGet(tx));
      findings.push(...checkResponseSplitting(tx));
      findings.push(...checkHeaderOversize(tx));
      findings.push(...checkMetaCharacters(tx));
      findings.push(...checkMethodOverride(tx));
      findings.push(...checkParameterPollution(tx));
    }

    findings.push(...checkCacheKeyCollisions(trafficArray));
    findings = dedupeFindings(findings);

    const enriched = findings
      .filter(Boolean)
      .map((f, idx) => ({
        id: f.id || `finding-${idx + 1}-${Date.now()}`,
        status: f.status || "potential",
        ...f,
      }))
      .sort((a, b) => {
        const order = { Critical: 1, High: 2, Medium: 3, Low: 4, Info: 5 };
        return (order[a.severity] || 99) - (order[b.severity] || 99);
      });

    return enriched;
  }

  function checkCacheKeyCollisions(trafficArray) {
    const results = [];
    try {
      const key = (tx) => {
        const host =
          tx?.request?.headers?.Host ||
          tx?.request?.headers?.host ||
          "unknown-host";
        const url = tx?.request?.path || "/";
        const [path, query] = String(url).split("?");
        return {
          host: String(host).toLowerCase(),
          path,
          query: query || "",
        };
      };

      const byPath = new Map();
      for (const tx of trafficArray) {
        if (!tx?.request) continue;
        const k = key(tx);
        const mapKey = `${k.host} ${k.path}`;
        const entry = byPath.get(mapKey) || [];
        entry.push({ tx, k });
        byPath.set(mapKey, entry);
      }

      for (const [mapKey, arr] of byPath) {
        if (arr.length < 2) continue;
        const cacheable = arr.filter(({ tx }) => {
          const cc = String(
            tx?.response?.headers?.["Cache-Control"] || ""
          ).toLowerCase();
          const vary = String(tx?.response?.headers?.Vary || "");
          const setCookie = tx?.response?.headers?.["Set-Cookie"];
          const hasSetCookie = Array.isArray(setCookie)
            ? setCookie.length > 0
            : !!setCookie;
          const cacheableHeur =
            /public|max-age=\d+/.test(cc) &&
            !/no-store/.test(cc) &&
            !hasSetCookie;
          return cacheableHeur && vary.trim() === "";
        });

        if (cacheable.length >= 2) {
          const qs = new Set(
            cacheable.map(({ k }) => (k.query || "").trim()).filter(Boolean)
          );
          if (qs.size >= 2) {
            results.push({
              type: "cache-key-collision",
              severity: "High",
              status: "potential",
              description:
                "Potential cache key collision: same host+path, cacheable, differing queries, missing Vary.",
              evidence: Array.from(qs)
                .slice(0, 5)
                .map((q) => `?${q}`)
                .join(", "),
              affected: mapKey,
              tags: ["cache", "cdn", "origin"],
            });
          }
        }
      }
    } catch (e) {}
    return results;
  }

  function checkUnkeyedHeaders(transaction) {
    const results = [];
    try {
      const req = transaction?.request;
      const res = transaction?.response;
      if (!req || !res) return results;

      const vary = String(res.headers?.Vary || "");
      const body = String(res.body || "");
      const hdrs = req.headers || {};

      const suspectNames = [
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Original-URL",
        "X-Host",
        "Forwarded",
      ];

      for (const name of suspectNames) {
        const val = hdrs[name];
        if (!val) continue;

        const valStr = Array.isArray(val) ? val.join(", ") : String(val);
        const reflectedInHeaders = Object.values(res.headers || {}).some((v) =>
          String(Array.isArray(v) ? v.join(" ") : v).includes(valStr)
        );
        const reflectedInBody = body.includes(valStr);

        const reflected = reflectedInHeaders || reflectedInBody;
        const varied = vary
          .split(",")
          .map((s) => U.normHeaderName(s.trim()))
          .includes(U.normHeaderName(name));

        if (reflected && !varied) {
          results.push({
            type: "unkeyed-header-reflection",
            severity: "High",
            status: "potential",
            description:
              `Request header "${name}" appears reflected in response without Vary. This can enable cache poisoning.`,
            evidence: `Reflected value: ${valStr}`,
            affected:
              (req.headers?.Host || "unknown-host") + " " + (req.path || "/"),
            tags: ["cache", "poisoning", "vary"],
          });
        }
      }
    } catch (e) {}
    return results;
  }

  function checkRequestSmugglingSignatures(transaction) {
    const results = [];
    try {
      const req = transaction?.request;
      if (!req) return results;

      const h = {};
      for (const [k, v] of Object.entries(req.headers || {})) {
        h[k.toLowerCase()] = v;
      }

      const cl = h["content-length"];
      const te = h["transfer-encoding"];
      const teStr = Array.isArray(te) ? te.join(",") : te;

      if (cl && te) {
        results.push({
          type: "request-smuggling",
          severity: "High",
          status: "potential",
          description: "Both Content-Length and Transfer-Encoding present.",
          evidence: `Content-Length: ${cl}, Transfer-Encoding: ${te}`,
          affected: req.path || "/",
          tags: ["smuggling", "CL-TE"],
        });
      }

      if (Array.isArray(req.headers?.["Content-Length"])) {
        results.push({
          type: "request-smuggling",
          severity: "High",
          status: "potential",
          description: "Multiple Content-Length headers (CL-CL conflict).",
          evidence: JSON.stringify(req.headers?.["Content-Length"]),
          affected: req.path || "/",
          tags: ["smuggling", "CL-CL"],
        });
      }

      if (teStr && /chunked\s*,\s*chunked/i.test(teStr)) {
        results.push({
          type: "request-smuggling",
          severity: "High",
          status: "potential",
          description: "Duplicate 'chunked' in Transfer-Encoding (TE-TE).",
          evidence: `Transfer-Encoding: ${teStr}`,
          affected: req.path || "/",
          tags: ["smuggling", "TE-TE"],
        });
      }
      if (typeof teStr === "string" && /\btransfer-encoding\b/i.test(teStr)) {
        results.push({
          type: "request-smuggling",
          severity: "Medium",
          status: "potential",
          description: "Suspicious TE obfuscation (casing/spaces/commas).",
          evidence: `Transfer-Encoding: ${teStr}`,
          affected: req.path || "/",
          tags: ["smuggling", "obfuscation"],
        });
      }
    } catch (e) {}
    return results;
  }

  function checkMisconfigurations(transaction) {
    const results = [];
    const req = transaction?.request;
    const res = transaction?.response;
    if (!res) return results;

    const h = res.headers || {};
    const cc = String(h["Cache-Control"] || "");
    const setCookie = h["Set-Cookie"];
    const hasSetCookie = Array.isArray(setCookie)
      ? setCookie.length > 0
      : !!setCookie;

    if (!cc) {
      results.push({
        type: "misconfiguration",
        severity: "Low",
        status: "potential",
        description: "Missing Cache-Control header in response.",
        evidence: "No Cache-Control present.",
        affected: req?.path || "/",
        tags: ["cache"],
      });
    } else {
      if (!/no-store|private|max-age=\d+|no-cache|public/i.test(cc)) {
        results.push({
          type: "misconfiguration",
          severity: "Low",
          status: "potential",
          description: "Cache-Control present but lacks common directives.",
          evidence: `Cache-Control: ${cc}`,
          affected: req?.path || "/",
          tags: ["cache"],
        });
      }
      if (
        hasSetCookie &&
        /public|max-age=\d+/.test(cc) &&
        !/private|no-store/i.test(cc)
      ) {
        results.push({
          type: "cache-cookie",
          severity: "Medium",
          status: "potential",
          description:
            "Response sets cookies and appears cacheable. Risk of user data leak via shared caches.",
          evidence: `Cache-Control: ${cc}; Set-Cookie present`,
          affected: req?.path || "/",
          tags: ["cache", "privacy"],
        });
      }
    }

    const connection = String(h["Connection"] || "");
    if (h["Proxy-Connection"]) {
      results.push({
        type: "hop-by-hop",
        severity: "Low",
        status: "potential",
        description: 'Non-standard "Proxy-Connection" header detected.',
        evidence: `Proxy-Connection: ${h["Proxy-Connection"]}`,
        affected: req?.path || "/",
        tags: ["proxy", "hop-by-hop"],
      });
    }
    if (connection) {
      const tokens = connection
        .split(",")
        .map((t) => U.normHeaderName(t.trim()))
        .filter(Boolean);
      for (const t of tokens) {
        if (h[t]) {
          results.push({
            type: "hop-by-hop",
            severity: "Low",
            status: "potential",
            description:
              `Hop-by-hop "${t}" listed in Connection and present in response.`,
            evidence: `Connection: ${connection}; ${t}: ${h[t]}`,
            affected: req?.path || "/",
            tags: ["hop-by-hop"],
          });
        }
      }
    }

    const ct = String(h["Content-Type"] || "").toLowerCase();
    if (
      ct &&
      /json/.test(ct) &&
      /html/.test(ct) &&
      window.T3Rules &&
      window.T3Rules.ambiguousContentType
    ) {
      results.push({
        type: "ambiguous-content-type",
        severity: "Low",
        status: "potential",
        description:
          "Content-Type appears ambiguous (JSON + HTML). Risk of misparsing.",
        evidence: `Content-Type: ${h["Content-Type"]}`,
        affected: req?.path || "/",
        tags: ["content-type"],
      });
    }

    return results;
  }

  function checkSecurityHeaders(transaction) {
    const res = transaction?.response;
    const req = transaction?.request;
    const results = [];
    if (!res) return results;
    const h = res.headers || {};
    const have = (n) => !!h[n];

    if (!have("Strict-Transport-Security")) {
      results.push({
        type: "security-header",
        severity: "Medium",
        status: "potential",
        description:
          "Missing HTTP Strict Transport Security (HSTS): failure to enforce encrypted connections may enable MITM attacks.",
        evidence:
          "Add: Strict-Transport-Security: max-age=15552000; includeSubDomains; preload",
        affected: req?.path || "/",
        tags: ["headers", "transport", "hsts"],
      });
    }
    const hasXFO = have("X-Frame-Options");
    const csp = String(h["Content-Security-Policy"] || "");
    const hasFrameAncestors = /frame-ancestors/i.test(csp);
    if (!hasXFO && !hasFrameAncestors) {
      results.push({
        type: "security-header",
        severity: "Low",
        status: "potential",
        description:
          "Clickjacking Vulnerability: missing X-Frame-Options or CSP frame-ancestors.",
        evidence:
          "Add: X-Frame-Options: DENY (or CSP: frame-ancestors 'none') to prevent UI redress attacks.",
        affected: req?.path || "/",
        tags: ["headers", "clickjacking"],
      });
    }
    if (!have("X-Content-Type-Options")) {
      results.push({
        type: "security-header",
        severity: "Low",
        status: "potential",
        description:
          "MIME-Type Sniffing: missing X-Content-Type-Options: nosniff may allow content type misinterpretation leading to XSS.",
        evidence: "Add: X-Content-Type-Options: nosniff",
        affected: req?.path || "/",
        tags: ["headers", "mime"],
      });
    }
    if (!have("Referrer-Policy")) {
      results.push({
        type: "security-header",
        severity: "Low",
        status: "potential",
        description:
          "Missing Referrer-Policy: referrers may leak sensitive path/query info to third parties.",
        evidence:
          "Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
        affected: req?.path || "/",
        tags: ["headers", "privacy"],
      });
    }
    if (!have("Permissions-Policy")) {
      results.push({
        type: "security-header",
        severity: "Low",
        status: "potential",
        description:
          "Missing Permissions-Policy: no explicit restriction of powerful browser features.",
        evidence:
          "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        affected: req?.path || "/",
        tags: ["headers", "permissions"],
      });
    }
    if (!have("Cross-Origin-Opener-Policy")) {
      results.push({
        type: "security-header",
        severity: "Low",
        status: "potential",
        description:
          "Missing Cross-Origin-Opener-Policy (COOP): lacks Browse context isolation.",
        evidence: "Add: Cross-Origin-Opener-Policy: same-origin",
        affected: req?.path || "/",
        tags: ["headers", "isolation"],
      });
    }
    if (!have("Cross-Origin-Embedder-Policy")) {
      results.push({
        type: "security-header",
        severity: "Low",
        status: "potential",
        description:
          "Missing Cross-Origin-Embedder-Policy (COEP): cross-origin resource isolation not enforced.",
        evidence: "Add: Cross-Origin-Embedder-Policy: require-corp",
        affected: req?.path || "/",
        tags: ["headers", "isolation"],
      });
    }
    if (!have("Cross-Origin-Resource-Policy")) {
      results.push({
        type: "security-header",
        severity: "Low",
        status: "potential",
        description:
          "Missing Cross-Origin-Resource-Policy (CORP): cross-origin resource policy not specified.",
        evidence: "Add: Cross-Origin-Resource-Policy: same-origin",
        affected: req?.path || "/",
        tags: ["headers", "isolation"],
      });
    }

    const includeInfo =
      !window.T3Rules || window.T3Rules.infoDisclosure !== false;
    if (includeInfo) {
      const leakHeaders = [
        "Server",
        "X-Powered-By",
        "X-Aspnet-Version",
        "X-Generator",
      ];
      for (const name of leakHeaders) {
        if (h[name]) {
          results.push({
            type: "information-disclosure",
            severity: "Low",
            status: "potential",
            description:
              "Information Disclosure: server or framework-specific headers reveal version/stack details.",
            evidence: `${
              name
            }: ${Array.isArray(h[name]) ? h[name].join(", ") : h[name]}`,
            affected: req?.path || "/",
            tags: ["headers", "info-leak"],
          });
        }
      }
    }

    return results;
  }

  function parseSetCookie(setCookieVal) {
    const res = [];
    const values = Array.isArray(setCookieVal)
      ? setCookieVal
      : setCookieVal
      ? [setCookieVal]
      : [];
    for (const sc of values) {
      const parts = String(sc).split(";");
      const [nameValue, ...attrParts] = parts;
      const [name, ...valParts] = nameValue.split("=");
      const value = valParts.join("=");
      const attrs = {};
      for (const ap of attrParts) {
        const [an, av] = ap.trim().split("=");
        const key = (an || "").trim();
        const v = (av || "").trim();
        if (!key) continue;
        attrs[key.toLowerCase()] = v || true;
      }
      res.push({
        name: (name || "").trim(),
        value: (value || "").trim(),
        attrs,
        raw: sc,
      });
    }
    return res;
  }

  function checkCookies(transaction) {
    const results = [];
    const req = transaction?.request;
    const res = transaction?.response;
    if (!res) return results;

    const setCookie = res.headers?.["Set-Cookie"];
    if (!setCookie) return results;

    const cookies = parseSetCookie(setCookie);
    for (const c of cookies) {
      const issues = [];
      let sev = "Low";

      if (!("secure" in c.attrs)) {
        issues.push("missing Secure");
        sev = "Medium";
      }
      if (!("httponly" in c.attrs)) {
        issues.push("missing HttpOnly");
      }
      if (!("samesite" in c.attrs)) {
        issues.push("missing SameSite");
      }

      if (issues.length > 0) {
        results.push({
          type: "cookie",
          severity: sev,
          status: "potential",
          description:
            `Set-Cookie "${c.name}" is missing recommended attributes: ` +
            issues.join(", ") +
            ".",
          evidence: c.raw,
          affected: req?.path || "/",
          tags: ["cookie", "secure"],
        });
      }
    }

    return results;
  }

  function checkUnkeyedParameterPoisoning(tx) {
    const results = [];
    const req = tx?.request;
    const res = tx?.response;
    if (!req || !res) return results;
    const vary = String(res.headers?.Vary || "");
    const { query } = urlParts(req.path);
    if (!query) return results;

    const qp = parseQueryParams(query);
    const reflectedParams = [];
    for (const [k, vals] of Object.entries(qp)) {
      const needle = `${k}=${vals[0] ?? ""}`;
      const inBody = String(res.body || "").includes(vals[0] || "");
      const inHdr = Object.values(res.headers || {}).some((v) =>
        String(Array.isArray(v) ? v.join(" ") : v).includes(vals[0] || "")
      );
      const varied = vary
        .split(",")
        .map((s) => U.normHeaderName(s.trim()))
        .includes("Accept");
      if ((inBody || inHdr) && !varied) reflectedParams.push(needle);
    }
    if (reflectedParams.length) {
      results.push({
        type: "unkeyed-parameter-poisoning",
        severity: "High",
        status: "potential",
        description:
          "Reflected query parameters in cacheable response without Vary.",
        evidence: reflectedParams.slice(0, 5).join(", "),
        affected: req.path || "/",
        tags: ["cache", "poisoning"],
      });
    }
    return results;
  }

  function checkParameterCloaking(tx) {
    const results = [];
    const req = tx?.request;
    if (!req) return results;
    const { query } = urlParts(req.path);
    if (!query) return results;
    const qp = parseQueryParams(query);
    for (const [k, vals] of Object.entries(qp)) {
      if (vals.length > 1) {
        results.push({
          type: "parameter-cloaking",
          severity: "Medium",
          status: "potential",
          description:
            `Parameter "${k}" appears multiple times. Upstream and cache may disagree on effective value.`,
          evidence: `${k}=${vals.join(" & " + k + "=")}`,
          affected: req.path || "/",
          tags: ["cache", "cloaking"],
        });
      }
    }
    return results;
  }

  function checkFatGet(tx) {
    const results = [];
    const req = tx?.request;
    if (!req) return results;
    if ((req.method || "").toUpperCase() !== "GET") return results;

    if (U.safeTrim(req.body).length > 0) {
      results.push({
        type: "fat-get",
        severity: "Medium",
        status: "potential",
        description: "GET request with a message body detected.",
        evidence: `Body length: ${U.safeTrim(req.body).length}`,
        affected: req.path || "/",
        tags: ["cache", "routing"],
      });
    }
    return results;
  }

  function checkResponseSplitting(tx) {
    const results = [];
    const res = tx?.response;
    if (!res) return results;
    const suspectHeaders = ["Location", "Content-Disposition"];
    for (const h of suspectHeaders) {
      const val = res.headers?.[h];
      if (!val) continue;
      const s = Array.isArray(val) ? val.join(" ") : String(val);
      if (/%0d|%0a|\r|\n/i.test(s)) {
        results.push({
          type: "response-splitting",
          severity: "High",
          status: "potential",
          description: `${h} contains CR/LF characters or encodings (CRLF).`,
          evidence: `${h}: ${s}`,
          affected: "response",
          tags: ["crlf", "cache-poisoning"],
        });
      }
    }
    return results;
  }

  function checkHeaderOversize(tx) {
    const results = [];
    const req = tx?.request;
    if (!req) return results;
    const headersStr = Object.entries(req.headers || {})
      .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(",") : v}`)
      .join("\r\n");
    if (headersStr.length > 16384) {
      results.push({
        type: "header-oversize",
        severity: "Low",
        status: "potential",
        description:
          "Request headers exceed common proxy limits (HHO). May cause desync or cache anomalies.",
        evidence: `Headers length ~${headersStr.length} bytes`,
        affected: req.path || "/",
        tags: ["limits", "cache"],
      });
    }
    return results;
  }

  function checkMetaCharacters(tx) {
    const results = [];
    const req = tx?.request;
    if (!req) return results;
    const firstLine = `${req.method} ${req.path} ${req.httpVersion}`;
    if (/[\u0000\u0008\u000b]/.test(firstLine)) {
      results.push({
        type: "meta-characters",
        severity: "Medium",
        status: "potential",
        description: "Request line contains control/meta characters (HMC).",
        evidence: firstLine.replaceAll("\0", "\\0"),
        affected: req.path || "/",
        tags: ["parsing", "smuggling"],
      });
    }
    return results;
  }

  function checkMethodOverride(tx) {
    const results = [];
    const req = tx?.request;
    if (!req) return results;
    const override =
      req.headers?.["X-Http-Method-Override"] ||
      req.headers?.["X-Method-Override"];
    if (override) {
      results.push({
        type: "method-override",
        severity: "Low",
        status: "potential",
        description:
          "X-HTTP-Method-Override present (HMO). Intermediaries may disagree.",
        evidence: `Override: ${override}`,
        affected: req.path || "/",
        tags: ["method", "cache"],
      });
    }
    return results;
  }

  function checkParameterPollution(tx) {
    const results = [];
    const req = tx?.request;
    if (!req) return results;
    const { query } = urlParts(req.path);
    if (!query) return results;
    const qp = parseQueryParams(query);
    const polluted = Object.entries(qp)
      .filter(([_, vals]) => vals.length > 1)
      .map(([k, vals]) => `${k}=${vals.join("&" + k + "=")}`);
    if (polluted.length) {
      results.push({
        type: "parameter-pollution",
        severity: "Medium",
        status: "potential",
        description:
          "Multiple values for same parameter; upstream and cache may differ.",
        evidence: polluted.join(" ; "),
        affected: req.path || "/",
        tags: ["cache", "pollution"],
      });
    }
    return results;
  }

  function checkCors(tx) {
    const results = [];
    const req = tx?.request;
    const res = tx?.response;
    if (!res) return results;

    const h = res.headers || {};
    const vary = String(h.Vary || "");
    const acao = h["Access-Control-Allow-Origin"];
    const acac = String(h["Access-Control-Allow-Credentials"] || "").toLowerCase();
    const origin =
      req?.headers?.Origin ||
      req?.headers?.origin ||
      req?.headers?.["X-Origin"] ||
      "";

    if (!acao && !h["Access-Control-Allow-Methods"]) return results;

    if (acao === "*" && /true/.test(acac)) {
      results.push({
        type: "cors-misconfig",
        severity: "High",
        status: "potential",
        description:
          "CORS: Access-Control-Allow-Origin is '*' with Access-Control-Allow-Credentials: true.",
        evidence: `ACAO: ${acao}; ACAC: ${h["Access-Control-Allow-Credentials"]}`,
        affected: req?.path || "/",
        tags: ["cors"],
      });
    }

    if (origin && acao === origin) {
      const varies = vary
        .split(",")
        .map((s) => U.normHeaderName(s.trim()))
        .includes("Origin");
      if (!varies) {
        results.push({
          type: "cors-misconfig",
          severity: "Medium",
          status: "potential",
          description:
            "CORS: ACAO reflects Origin but response missing Vary: Origin.",
          evidence: `Origin: ${origin}; ACAO: ${acao}; Vary: ${vary || "(none)"}`,
          affected: req?.path || "/",
          tags: ["cors", "vary"],
        });
      }
    }

    if (acao && /null/i.test(String(acao))) {
      results.push({
        type: "cors-misconfig",
        severity: "Medium",
        status: "potential",
        description: "CORS: ACAO allows 'null' origin.",
        evidence: `ACAO: ${acao}`,
        affected: req?.path || "/",
        tags: ["cors"],
      });
    }

    return results;
  }

  function checkHstsPreload(tx) {
    const results = [];
    const req = tx?.request;
    const res = tx?.response;
    if (!res) return results;

    const h = res.headers || {};
    const sts = String(h["Strict-Transport-Security"] || "");
    const loc = String(h.Location || h.location || "");
    const code = Number(res.statusCode || 0);

    const parts = sts
      .split(";")
      .map((s) => s.trim())
      .filter(Boolean);
    const map = new Map();
    parts.forEach((p) => {
      const [k, v] = p.split("=").map((x) => x.trim());
      map.set(k.toLowerCase(), v ?? true);
    });

    const maxAge = Number(map.get("max-age") || 0);
    const hasISD = map.has("includesubdomains");
    const hasPreload = map.has("preload");

    const httpsRedirect =
      (code === 301 || code === 302 || code === 307 || code === 308) &&
      /^https:\/\//i.test(loc);

    const reasons = [];
    if (httpsRedirect) reasons.push("HTTPS redirect detected");
    if (maxAge >= 31536000) reasons.push("max-age ≥ 31536000");
    else reasons.push("max-age < 31536000");
    reasons.push(hasISD ? "includeSubDomains present" : "includeSubDomains missing");
    reasons.push(hasPreload ? "preload present" : "preload missing");

    const ready = maxAge >= 31536000 && hasISD && hasPreload;
    results.push({
      type: "hsts-preload",
      severity: ready ? "Info" : "Low",
      status: "potential",
      description: `HSTS Preload-ready: ${ready ? "yes" : "no"} — ${reasons.join(
        "; "
      )}`,
      evidence: sts || "(no HSTS)",
      affected: req?.path || "/",
      tags: ["hsts", "preload"],
    });

    return results;
  }

  function computeKeyModels(tx, opts) {
    const req = tx.request || {};
    const method = (req.method || "").toUpperCase();
    const host = req.headers?.Host || req.headers?.host || "unknown-host";
    const scheme =
      req.headers?.["X-Forwarded-Proto"] ||
      req.headers?.["Forwarded"]?.match(/proto=([^;]+)/)?.[1] ||
      "https";
    const { path, query } = urlParts(req.path);
    const vary = String(tx.response?.headers?.Vary || "");
    const varySet = new Set(
      vary
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((s) => U.normHeaderName(s))
    );

    const cdnKey = JSON.stringify({
      method,
      scheme: String(scheme).toLowerCase(),
      host: String(host).toLowerCase(),
      path,
      query,
      vary: [...varySet].sort(),
    });

    const qp = parseQueryParams(query);
    const originQ = Object.keys(qp)
      .filter((k) => !(opts?.ignoreTracking && isTrackingParam(k)))
      .sort()
      .map((k) => [k, qp[k]])
      .reduce((acc, [k, vals]) => {
        acc[k] = vals;
        return acc;
      }, {});
    const originKey = JSON.stringify({
      method,
      host: String(host).toLowerCase(),
      path: normalizePath(path),
      query: originQ,
    });

    return { cdnKey, originKey };
  }

  function renderCacheLab(traffic, opts) {
    const tableRoot = document.getElementById("cache-keys-table");
    const collisionsRoot = document.getElementById("cache-collisions");
    const poisonRoot = document.getElementById("poisoning-flags");
    const desyncRoot = document.getElementById("desync-hints");
    const remedRoot = document.getElementById("remediation-snippets");
    const graphSvg = document.getElementById("cache-graph");

    const cacheUiPresent =
      tableRoot && collisionsRoot && poisonRoot && desyncRoot;
    if (!cacheUiPresent) {
      const selLab = document.getElementById("lab-req-select");
      if (selLab) {
        selLab.innerHTML = '<option value="">— none —</option>';
        (traffic || []).forEach((tx, idx) => {
          const req = tx.request || {};
          const host =
            req.headers?.Host || req.headers?.host || "unknown-host";
          const opt = document.createElement("option");
          opt.value = String(idx);
          opt.textContent = `#${idx + 1} ${req.method || ""} ${
            req.path || "/"
          } @ ${host}`;
          selLab.appendChild(opt);
        });
      }
      return;
    }

    tableRoot.innerHTML = "";
    collisionsRoot.innerHTML = "";
    poisonRoot.innerHTML = "";
    desyncRoot.innerHTML = "";
    if (remedRoot) remedRoot.textContent = "";
    if (graphSvg) graphSvg.innerHTML = "";

    const selLab = document.getElementById("lab-req-select");
    if (selLab) selLab.innerHTML = '<option value="">— none —</option>';

    if (!traffic || !traffic.length) {
      tableRoot.innerHTML =
        '<div class="text-gray-400 text-sm">No transactions.</div>';
      return;
    }

    if (selLab) {
      traffic.forEach((tx, idx) => {
        const req = tx.request || {};
        const host = req.headers?.Host || req.headers?.host || "unknown-host";
        const opt = document.createElement("option");
        opt.value = String(idx);
        opt.textContent = `#${idx + 1} ${req.method || ""} ${
          req.path || "/"
        } @ ${host}`;
        selLab.appendChild(opt);
      });
    }

    const tbl = document.createElement("table");
    tbl.className = "w-full text-sm border-collapse overflow-auto min-w-[640px]";
    tbl.innerHTML =
      "<thead><tr>" +
      "<th class='px-2 py-1 text-left'>#</th>" +
      "<th class='px-2 py-1 text-left'>Method</th>" +
      "<th class='px-2 py-1 text-left'>Host</th>" +
      "<th class='px-2 py-1 text-left'>Path</th>" +
      "<th class='px-2 py-1 text-left'>Query</th>" +
      "<th class='px-2 py-1 text-left'>Vary</th>" +
      "<th class='px-2 py-1 text-left'>CDN Key (hash)</th>" +
      "<th class='px-2 py-1 text-left'>Origin Key (hash)</th>" +
      "</tr></thead><tbody></tbody>";
    const body = tbl.querySelector("tbody");

    const rows = [];
    (traffic || []).forEach((tx, i) => {
      const req = tx.request || {};
      const host = req.headers?.Host || req.headers?.host || "unknown-host";
      const { path, query } = (function urlPartsLocal(p) {
        const [pp, qq] = String(p || "/").split("?");
        return { path: pp || "/", query: qq || "" };
      })(req.path);
      const vary = String(tx.response?.headers?.Vary || "");
      const { cdnKey, originKey } = computeKeyModels(tx, opts);
      const cdnHash = simpleHash(cdnKey);
      const originHash = simpleHash(originKey);

      rows.push({
        idx: i + 1,
        method: (req.method || "").toUpperCase(),
        host,
        path,
        query,
        vary,
        cdnHash,
        originHash,
        response: tx.response,
        request: req,
      });

      const tr = document.createElement("tr");
      tr.innerHTML =
        `<td class="px-2 py-1">${i + 1}</td>` +
        `<td class="px-2 py-1">${(req.method || "").toUpperCase()}</td>` +
        `<td class="px-2 py-1">${host}</td>` +
        `<td class="px-2 py-1">${path}</td>` +
        `<td class="px-2 py-1">${query}</td>` +
        `<td class="px-2 py-1">${vary || "(none)"}</td>` +
        `<td class="px-2 py-1">${cdnHash}</td>` +
        `<td class="px-2 py-1">${originHash}</td>`;
      body.appendChild(tr);
    });

    tableRoot.appendChild(tbl);

    if (graphSvg) {
      graphSvg.innerHTML = "";
      const width = graphSvg.clientWidth || 800;
      const height = graphSvg.clientHeight || 320;
      const margin = 20;
      const clusters = Array.from(groupBy(rows, (r) => r.cdnHash).entries());
      const colWidth = Math.max(120, (width - margin * 2) / clusters.length);
      const radius = 10;
      clusters.forEach(([hash, group], cidx) => {
        const cx = margin + colWidth * cidx + colWidth / 2;
        group.forEach((r, i) => {
          const cy =
            margin + ((height - margin * 2) / (group.length + 1)) * (i + 1);
          const color = [
            "#60a5fa",
            "#f472b6",
            "#34d399",
            "#f59e0b",
            "#a78bfa",
            "#f87171",
            "#4ade80",
          ][cidx % 7];
          const node = document.createElementNS(
            "http://www.w3.org/2000/svg",
            "circle"
          );
          node.setAttribute("cx", cx);
          node.setAttribute("cy", cy);
          node.setAttribute("r", radius);
          node.setAttribute("fill", color);
          node.setAttribute("opacity", "0.9");
          node.setAttribute("stroke", "#0f172a");
          node.setAttribute("stroke-width", "1");
          graphSvg.appendChild(node);

          const label = document.createElementNS(
            "http://www.w3.org/2000/svg",
            "text"
          );
          label.setAttribute("x", cx + radius + 4);
          label.setAttribute("y", cy + 4);
          label.setAttribute("fill", "#9ca3af");
          label.setAttribute("font-size", "10");
          label.textContent = `#${r.idx}`;
          graphSvg.appendChild(label);
        });
        const hashText = document.createElementNS(
          "http://www.w3.org/2000/svg",
          "text"
        );
        hashText.setAttribute("x", cx);
        hashText.setAttribute("y", height - 4);
        hashText.setAttribute("fill", "#6b7280");
        hashText.setAttribute("font-size", "10");
        hashText.setAttribute("text-anchor", "middle");
        hashText.textContent = hash;
        graphSvg.appendChild(hashText);
      });
    }

    const byCdn = groupBy(rows, (r) => r.cdnHash);
    const byOrigin = groupBy(rows, (r) => r.originHash);
    const renderCollisionBlock = (title, groups, subtitle) => {
      const card = document.createElement("div");
      card.className = "card";
      const head = document.createElement("div");
      head.className = "card-header";
      const t = document.createElement("div");
      t.className = "card-title";
      t.textContent = title;
      const sub = document.createElement("div");
      sub.className = "text-xs text-gray-500";
      sub.textContent = subtitle;
      head.appendChild(t);
      head.appendChild(sub);
      const body = document.createElement("div");
      body.className = "card-body space-y-2";
      let any = false;
      for (const [hash, arr] of groups) {
        if (arr.length < 2) continue;
        any = true;
        const div = document.createElement("div");
        div.className = "text-sm";
        const ids = arr
          .map((r) => `#${r.idx} (${r.method} ${r.path})`)
          .join(", ");
        div.innerHTML = `<b>Hash ${hash}</b>: ${ids}`;
        body.appendChild(div);
      }
      if (!any) {
        body.innerHTML =
          '<div class="text-gray-400 text-sm">No collisions detected.</div>';
      }
      card.appendChild(head);
      card.appendChild(body);
      return card;
    };
    collisionsRoot.appendChild(
      renderCollisionBlock(
        "CDN model collisions",
        byCdn,
        "Two requests with the same CDN key may collide in shared caches."
      )
    );
    collisionsRoot.appendChild(
      renderCollisionBlock(
        "Origin model collisions",
        byOrigin,
        "Upstream may treat requests as identical while CDN does not (or vice versa)."
      )
    );

    const addFlag = (emoji, title, note) => {
        const div = document.createElement("div");
        div.className = "text-sm";
        div.innerHTML = `<span class="mr-2">${emoji}</span><b>${title}</b> — ${note}`;
        return { element: div, key: `${title}|${note}` };
    };
    
    const hintList = [];
    (traffic || []).forEach((tx) => {
      const req = tx.request || {};
      const res = tx.response || {};
      const headersLower = Object.fromEntries(
        Object.entries(req.headers || {}).map(([k, v]) => [k.toLowerCase(), v])
      );
      
      const cl = headersLower["content-length"];
      const te = headersLower["transfer-encoding"];
      const teStr = Array.isArray(te) ? te.join(",") : te;
      if (cl && te) {
        hintList.push(addFlag("❗", "CL + TE", "Both present (classic smuggling)."));
      }
      if (Array.isArray(req.headers?.["Content-Length"])) {
        hintList.push(addFlag("❗", "CL-CL", "Multiple Content-Length headers."));
      }
      if (teStr && /chunked\s*,\s*chunked/i.test(teStr)) {
        hintList.push(addFlag("❗", "TE-TE", "Duplicate chunked values."));
      }
      if (typeof teStr === "string" && /\btransfer-encoding\b/i.test(teStr)) {
        hintList.push(addFlag("⚠️", "TE obfuscation", teStr));
      }
      const connection = res.headers?.["Connection"];
      if (connection) {
        const tokens = connection
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean);
        for (const t of tokens) {
          if (res.headers?.[U.normHeaderName(t)]) {
            hintList.push(
              addFlag("⚠️", "Hop-by-hop leakage", `Connection lists "${t}" and header present.`)
            );
          }
        }
      }
    });

    poisonRoot.innerHTML = "";
    desyncRoot.innerHTML = "";
    const seenHints = new Set();
    const finalHintElements = [];
    hintList.forEach(hint => {
        if (!seenHints.has(hint.key)) {
            seenHints.add(hint.key);
            finalHintElements.push(hint.element);
        }
    });

    if (finalHintElements.length === 0) {
      desyncRoot.innerHTML = '<div class="text-gray-400 text-sm">No obvious desync or poisoning hints.</div>';
    } else {
      finalHintElements.forEach(el => desyncRoot.appendChild(el));
    }


    if (remedRoot) {
      remedRoot.textContent = [
        "# Cache hardening",
        "- Add Vary for user-controlled inputs (or stop reflecting them).",
        "- Avoid caching personalized responses (Cache-Control: no-store/private).",
        "- Do not cache responses that include Set-Cookie.",
        "",
        "# Smuggling/Desync",
        "- Normalize Transfer-Encoding and reject CL+TE at the edge.",
        "- Enforce single, correct Content-Length.",
        "- Strip hop-by-hop headers at boundaries (Connection + listed headers).",
        "",
        "# Origin/CDN agreement",
        "- Agree on canonical path normalization and query param handling.",
        "- Ensure CDN key includes necessary vary dimensions for dynamic content.",
      ].join("\n");
    }
  }

  function buildRawRequest(req, changes) {
    const method = changes.method || req.method || "GET";
    let path = req.path || "/";
    let headers = { ...(req.headers || {}) };
    let body = changes.body ?? req.body ?? "";

    if (changes.appendQuery) path = appendQuery(path, changes.appendQuery);
    if (changes.appendPath) path = path + changes.appendPath;
    for (const [k, v] of Object.entries(changes.headers || {})) headers[k] = v;

    const startLine = `${method} ${path} ${req.httpVersion || "HTTP/1.1"}`;
    const headerLinesArr = [];
    const host = headers.Host || headers.host || "example.com";
    headerLinesArr.push(`Host: ${host}`);
    for (const [k, v] of Object.entries(headers)) {
      if (/^host$/i.test(k)) continue;
      headerLinesArr.push(`${k}: ${Array.isArray(v) ? v.join(", ") : v}`);
    }

    return [startLine, ...headerLinesArr, "", body || ""].join("\r\n");
  }
  function appendQuery(p, q) {
    return p.includes("?") ? `${p}&${q}` : `${p}?${q}`;
  }

  function payloadsForTech(req, tech) {
    const out = [];
    const host = req.headers?.Host || req.headers?.host || "example.com";
    const path = req.path || "/";

    switch (tech) {
      case "unkeyed-header": {
        const token = `t3-${Date.now()}`;
        out.push({
          title: "X-Forwarded-Host reflection",
          raw: buildRawRequest(req, {
            headers: { "X-Forwarded-Host": `${token}.attacker` },
          }),
          why: "If reflected and not in Vary, shared cache poisoning may occur.",
        });
        break;
      }
      case "unkeyed-param": {
        const token = `t3-${Date.now()}`;
        out.push({
          title: "Reflected param",
          raw: buildRawRequest(req, { appendQuery: `x=${token}` }),
        });
        break;
      }
      case "param-cloak": {
        out.push({
          title: "Duplicate param",
          raw: buildRawRequest(req, { appendQuery: "x=1&x=2" }),
        });
        break;
      }
      case "fat-get": {
        out.push({
          title: "GET with body",
          raw: buildRawRequest(req, {
            headers: { "Content-Length": "5" },
            body: "hello",
          }),
        });
        break;
      }
      case "response-split": {
        out.push({
          title: "CRLF in query",
          raw: buildRawRequest(req, {
            appendQuery: "q=%0d%0aSet-Cookie:%20spl=1",
          }),
        });
        break;
      }
      case "smuggling": {
        out.push({
          title: "CL+TE (baseline)",
          raw: [
            `POST ${path} ${req.httpVersion || "HTTP/1.1"}`,
            `Host: ${host}`,
            "Transfer-Encoding: chunked",
            "Content-Length: 4",
            "",
            "0",
            "",
          ].join("\r\n"),
        });
        break;
      }
      case "hho": {
        const big = "A".repeat(20000);
        out.push({
          title: "Header Oversize",
          raw: buildRawRequest(req, { headers: { "X-Big": big } }),
        });
        break;
      }
      case "hmc": {
        out.push({
          title: "Meta char in URL",
          raw: buildRawRequest(req, { appendQuery: "q=%00test" }),
        });
        break;
      }
      case "hmo": {
        out.push({
          title: "Method override",
          raw: buildRawRequest(req, {
            method: req.method || "POST",
            headers: { "X-HTTP-Method-Override": "PUT" },
          }),
        });
        break;
      }
      case "hpp": {
        out.push({
          title: "Param pollution",
          raw: buildRawRequest(req, { appendQuery: "a=1&a=2&a=3" }),
        });
        break;
      }
      case "wcd-path": {
        out.push({
          title: "WCD path parameter",
          raw: buildRawRequest(req, { appendPath: ";.css" }),
        });
        break;
      }
      case "wcd-traversal": {
        out.push({
          title: "WCD traversal",
          raw: buildRawRequest(req, { appendPath: "/..%2f..%2frobots.txt" }),
        });
        break;
      }
      case "wcd-chars": {
        out.push({
          title: "WCD special chars",
          raw: buildRawRequest(req, { appendPath: "%2f" }),
        });
        break;
      }
      default:
        break;
    }
    return out;
  }

  function combineTechniques(req, techniques) {
    const incompatible = new Set(["smuggling", "response-split", "fat-get"]);
    const combined = techniques.filter((t) => !incompatible.has(t));
    if (combined.length === 0) return null;

    const changes = { headers: {}, appendQuery: "", appendPath: "" };

    for (const t of combined) {
      if (t === "unkeyed-header") {
        changes.headers["X-Forwarded-Host"] = `t3-${Date.now()}.attacker`;
      } else if (t === "unkeyed-param") {
        changes.appendQuery = changes.appendQuery
          ? `${changes.appendQuery}&x=t3-${Date.now()}`
          : `x=t3-${Date.now()}`;
      } else if (t === "param-cloak" || t === "hpp") {
        changes.appendQuery = changes.appendQuery
          ? `${changes.appendQuery}&a=1&a=2`
          : "a=1&a=2";
      } else if (t === "hho") {
        changes.headers["X-Big"] = "A".repeat(20000);
      } else if (t === "hmc") {
        changes.appendQuery = changes.appendQuery
          ? `${changes.appendQuery}&q=%00test`
          : "q=%00test";
      } else if (t === "hmo") {
        changes.headers["X-HTTP-Method-Override"] = "PUT";
      } else if (t === "wcd-path") {
        changes.appendPath += ";.css";
      } else if (t === "wcd-traversal") {
        changes.appendPath += "/..%2f..%2frobots.txt";
      } else if (t === "wcd-chars") {
        changes.appendPath += "%2f";
      }
    }

    if (changes.appendQuery)
      changes.appendQuery = changes.appendQuery.replace(/^&+/, "");

    return {
      title: `Combined: ${combined.join(", ")}`,
      raw: buildRawRequest(req, changes),
      why:
        "Combines compatible techniques to maximize signal in one request. " +
        "Use separate payloads for incompatible techniques.",
    };
  }

  function advancedSmugglingPayloads(req) {
    const out = [];
    const host = req.headers?.Host || req.headers?.host || "example.com";
    const path = req.path || "/";

    out.push({
      title: "Smuggling CL.TE",
      raw:
        `POST ${path} ${req.httpVersion || "HTTP/1.1"}\r\n` +
        `Host: ${host}\r\n` +
        `Content-Length: 4\r\n` +
        `Transfer-Encoding: chunked\r\n\r\n` +
        `0\r\n\r\n`,
    });
    out.push({
      title: "Smuggling TE.CL",
      raw:
        `POST ${path} ${req.httpVersion || "HTTP/1.1"}\r\n` +
        `Host: ${host}\r\n` +
        `Transfer-Encoding: chunked\r\n` +
        `Content-Length: 6\r\n\r\n` +
        `0\r\n\r\n`,
    });
    out.push({
      title: "Smuggling TE-TE (duplicate chunked)",
      raw:
        `POST ${path} ${req.httpVersion || "HTTP/1.1"}\r\n` +
        `Host: ${host}\r\n` +
        `Transfer-Encoding: chunked, chunked\r\n\r\n` +
        `0\r\n\r\n`,
    });
    out.push({
      title: "Smuggling obf: space before colon",
      raw:
        `POST ${path} ${req.httpVersion || "HTTP/1.1"}\r\n` +
        `Host: ${host}\r\n` +
        `Transfer-Encoding : chunked\r\n\r\n` +
        `0\r\n\r\n`,
    });
    out.push({
      title: "Smuggling obf: header casing",
      raw:
        `POST ${path} ${req.httpVersion || "HTTP/1.1"}\r\n` +
        `Host: ${host}\r\n` +
        `tRaNsFeR-EnCoDiNg: ChuNkEd\r\n\r\n` +
        `0\r\n\r\n`,
    });
    out.push({
      title: "Smuggling: chunk extension",
      raw:
        `POST ${path} ${req.httpVersion || "HTTP/1.1"}\r\n` +
        `Host: ${host}\r\n` +
        `Transfer-Encoding: chunked\r\n\r\n` +
        `1;ext=1\r\nA\r\n0\r\n\r\n`,
    });

    out.push({
      title: "Smuggling: TE obs-fold",
      raw:
        `POST ${path} ${req.httpVersion || "HTTP/1.1"}\r\n` +
        `Host: ${host}\r\n` +
        `Transfer-Encoding:\r\n\tchunked\r\n\r\n` +
        `0\r\n\r\n`,
    });
    out.push({
      title: "Smuggling: duplicate TE with casing",
      raw:
        `POST ${path} ${req.httpVersion || "HTTP/1.1"}\r\n` +
        `Host: ${host}\r\n` +
        `Transfer-Encoding: chunked\r\n` +
        `tRaNsFeR-EnCoDiNg: chunked\r\n\r\n` +
        `0\r\n\r\n`,
    });
    out.push({
      title: "Smuggling: CL-CL conflict",
      raw:
        `POST ${path} ${req.httpVersion || "HTTP/1.1"}\r\n` +
        `Host: ${host}\r\n` +
        `Content-Length: 6\r\n` +
        `Content-Length: 0\r\n\r\n` +
        `ignore\r\n`,
    });
    out.push({
      title: "Smuggling: TE with extra LWS",
      raw:
        `POST ${path} ${req.httpVersion || "HTTP/1.1"}\r\n` +
        `Host: ${host}\r\n` +
        `Transfer-Encoding:   chunked\r\n\r\n` +
        `0\r\n\r\n`,
    });

    return out;
  }

  function analyzeLabResponse(rawResp, techniques, context) {
    const res =
      window.T3parsers && typeof window.T3parsers.parseResponse === "function"
        ? window.T3parsers.parseResponse(rawResp || "")
        : { headers: {}, body: "", statusCode: 0 };
    const lines = [];

    function add(emoji, title, why, fix) {
      lines.push(`${emoji} ${title}\n- Why: ${why}\n- Fix: ${fix}`);
    }

    const body = String(res.body || "");
    const headers = res.headers || {};
    const sc = res.statusCode;

    const list = Array.isArray(techniques) ? techniques : [techniques];

    for (const technique of list) {
      switch (technique) {
        case "unkeyed-header": {
          const token = /t3-\d+/i;
          const found =
            token.test(body) ||
            Object.values(headers).some((v) => token.test(String(v)));
          if (found) {
            add(
              "❗",
              "Reflected header value detected",
              "User-controlled header appears in the response without cache key protection.",
              "Add Vary for the header or stop reflecting it; avoid caching dynamic content."
            );
          } else {
            lines.push("✅ No reflection indicators found for unkeyed-header.");
          }
          break;
        }
        case "unkeyed-param": {
          const m = context?.urlParamValue || /t3-\d+/i;
          const found =
            (typeof m === "string" && body.includes(m)) ||
            (m instanceof RegExp &&
              (m.test(body) ||
                Object.values(headers).some((v) => m.test(String(v)))));
          lines.push(
            found
              ? "❗ Reflected param value detected (potential poisoning)."
              : "✅ No reflected param value detected."
          );
          break;
        }
        case "smuggling":
        case "CL.TE":
        case "TE.CL":
        case "TE-TE":
        case "obf-space-colon":
        case "obf-casing":
        case "chunk-ext":
        case "obs-fold":
        case "dup-casing":
        case "clcl-conflict":
        case "te-lws": {
          if ([400, 405, 408, 411, 413, 421, 494, 500, 502, 504].includes(sc)) {
            add(
              "⚠️",
              `Unusual status ${sc}`,
              "Servers/proxies may parse requests differently; smuggling suspected.",
              "Normalize TE/CL; block CL+TE; sanitize TE; enforce single framing."
            );
          } else {
            lines.push(
              `ℹ️ No obvious smuggling indicators for ${technique} in this response.`
            );
          }
          break;
        }
        case "response-split": {
          const setCookie = headers["Set-Cookie"];
          if (setCookie) {
            add(
              "❗",
              "Header injection suspected",
              "Injected CRLF caused extra headers (e.g., Set-Cookie).",
              "Sanitize CR/LF; reject encoded %0d%0a in inputs."
            );
          } else {
            lines.push(
              "✅ No injected headers observed for response-splitting payload."
            );
          }
          break;
        }
        default:
          lines.push(
            `ℹ️ Basic checks complete for ${technique}; no specific indicators found.`
          );
      }
    }

    lines.push(
      "\nRemediation:\n" +
        "- Avoid caching personalized responses (no-store/private).\n" +
        "- Add appropriate Vary for user-controlled inputs.\n" +
        "- Normalize TE/CL and strip hop-by-hop headers at trust boundaries."
    );

    return lines.join("\n");
  }

  window.T3cache = {
    runPassiveAnalysis,
    renderCacheLab,
    computeKeyModels,
    payloadsForTech,
    combineTechniques,
    advancedSmugglingPayloads,
    analyzeLabResponse,
  };
})();
