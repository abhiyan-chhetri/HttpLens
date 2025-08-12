(function attachParsers() {
  const U = window.T3utils;

  function parseRequest(rawRequestText) {
    try {
      const { head, body } = U.splitHeadersAndBody(String(rawRequestText || ""));
      const lines = head.split(/\r?\n/);
      const [method, path, httpVersion] =
        U.parseStartLineTokens(lines[0] || "");
      const headers = U.parseHeaderLines(head);
      return {
        method: method || "",
        path: path || "",
        httpVersion: httpVersion || "",
        headers,
        body: body || "",
      };
    } catch (e) {
      return {
        method: "",
        path: "",
        httpVersion: "",
        headers: {},
        body: "",
        parseError: String(e?.message || e),
      };
    }
  }

  function parseResponse(rawResponseText) {
    try {
      const { head, body } = U.splitHeadersAndBody(String(rawResponseText || ""));
      const lines = head.split(/\r?\n/);
      const [httpVersion, statusCode, ...rest] =
        U.parseStartLineTokens(lines[0] || "");
      const statusText = (rest || []).join(" ");
      const headers = U.parseHeaderLines(head);
      return {
        httpVersion: httpVersion || "",
        statusCode: statusCode ? Number(statusCode) : NaN,
        statusText: statusText || "",
        headers,
        body: body || "",
      };
    } catch (e) {
      return {
        httpVersion: "",
        statusCode: NaN,
        statusText: "",
        headers: {},
        body: "",
        parseError: String(e?.message || e),
      };
    }
  }

  function gatherInputTraffic() {
    const reqEl = document.getElementById("request-input");
    const resEl = document.getElementById("response-input");
    const reqText = U.safeTrim(reqEl?.value || "");
    const resText = U.safeTrim(resEl?.value || "");
    if (reqText || resText) {
      const request = reqText ? parseRequest(reqText) : null;
      const response = resText ? parseResponse(resText) : null;
      return [{ request, response }];
    }
    return [];
  }

  function parseHarText(harJsonText) {
    const out = [];
    let har;
    try {
      har = JSON.parse(harJsonText);
    } catch {
      return out;
    }
    const entries = har?.log?.entries || [];
    for (const e of entries) {
      try {
        const rq = e.request || {};
        const rs = e.response || {};
        const u = rq.url ? new URL(rq.url) : null;

        const rh = {};
        for (const h of rq.headers || []) {
          const name = U.normHeaderName(h.name);
          if (!name) continue;
          if (rh[name] !== undefined) {
            const prev = rh[name];
            rh[name] = Array.isArray(prev) ? [...prev, h.value] : [prev, h.value];
          } else {
            rh[name] = h.value;
          }
        }
        if (u && !rh.Host) rh.Host = u.host;

        const req = {
          method: rq.method || "",
          path: u ? u.pathname + (u.search || "") : "",
          httpVersion: rq.httpVersion || "HTTP/1.1",
          headers: rh,
          body:
            rq.postData?.text && typeof rq.postData.text === "string"
              ? rq.postData.text
              : "",
        };

        const sh = {};
        for (const h of rs.headers || []) {
          const name = U.normHeaderName(h.name);
          if (!name) continue;
          if (sh[name] !== undefined) {
            const prev = sh[name];
            sh[name] = Array.isArray(prev) ? [...prev, h.value] : [prev, h.value];
          } else {
            sh[name] = h.value;
          }
        }

        let body = "";
        const content = rs.content || {};
        if (typeof content.text === "string") {
          if (content.encoding === "base64") {
            try {
              body = atob(content.text);
            } catch {
              body = content.text;
            }
          } else {
            body = content.text;
          }
        }

        const res = {
          httpVersion: rs.httpVersion || "HTTP/1.1",
          statusCode: Number(rs.status) || NaN,
          statusText: rs.statusText || "",
          headers: sh,
          body,
        };

        out.push({ request: req, response: res });
      } catch {}
    }
    return out;
  }

  window.T3parsers = {
    parseRequest,
    parseResponse,
    gatherInputTraffic,
    parseHarText,
  };
})();
