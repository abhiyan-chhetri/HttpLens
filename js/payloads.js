(function attachCopyAs() {
  function requestToCurl(req) {
    const host = req.headers?.Host || req.headers?.host || "example.com";
    const scheme =
      (req.headers?.["X-Forwarded-Proto"] || "https").toLowerCase();
    const url = `${scheme}://${host}${req.path || "/"}`;
    const parts = ["curl -i -sS"];
    if ((req.method || "GET").toUpperCase() !== "GET") {
      parts.push("-X", req.method);
    }
    for (const [k, v] of Object.entries(req.headers || {})) {
      parts.push("-H", `'${k}: ${Array.isArray(v) ? v.join(", ") : v}'`);
    }
    if ((req.body || "").length) {
      parts.push("--data-binary", `'${req.body.replace(/'/g, "'\\''")}'`);
    }
    parts.push(`'${url}'`);
    return parts.join(" ");
  }

  function requestToNuclei(req) {
    const host = req.headers?.Host || req.headers?.host || "example.com";
    const scheme =
      (req.headers?.["X-Forwarded-Proto"] || "https").toLowerCase();
    const path = req.path || "/";
    const hdrs = Object.entries(req.headers || {})
      .map(([k, v]) => `        ${k}: "${Array.isArray(v) ? v.join(", ") : v}"`)
      .join("\n");

    return [
      "id: t3-poc",
      "info:",
      "  name: T3 Generated PoC",
      "  author: t3",
      "  severity: info",
      "requests:",
      "  - method: " + (req.method || "GET"),
      "    path:",
      `      - ${scheme}://${host}${path}`,
      "    headers:",
      hdrs || "      {}",
      req.body && req.body.length ? `    body: |\n      ${req.body}` : "",
    ]
      .filter(Boolean)
      .join("\n");
  }

  function requestToPython(req) {
    const host = req.headers?.Host || req.headers?.host || "example.com";
    const scheme =
      (req.headers?.["X-Forwarded-Proto"] || "https").toLowerCase();
    const url = `${scheme}://${host}${req.path || "/"}`;

    const hdrs = JSON.stringify(
      Object.fromEntries(
        Object.entries(req.headers || {}).map(([k, v]) => [
          k,
          Array.isArray(v) ? v.join(", ") : v,
        ])
      ),
      null,
      2
    );

    return [
      "import requests",
      "",
      `url = "${url}"`,
      `headers = ${hdrs}`,
      req.body && req.body.length ? `data = ${JSON.stringify(req.body)}` : "",
      "",
      `resp = requests.request("${(req.method || "GET").toUpperCase()}", url, headers=headers${
        req.body && req.body.length ? ", data=data" : ""
      })`,
      "print(resp.status_code)",
      "print(resp.headers)",
      "print(resp.text[:1000])",
    ]
      .filter(Boolean)
      .join("\n");
  }

  window.T3copyas = {
    requestToCurl,
    requestToNuclei,
    requestToPython,
  };
})();
