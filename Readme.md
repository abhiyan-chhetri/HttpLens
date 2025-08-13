
# HTTP Security Analysis Suite - HttpLens🛡️

A browser-based suite of tools for analyzing HTTP traffic to uncover security vulnerabilities.  
Designed for **security professionals**, **developers**, and **bug bounty hunters** who need to quickly dissect HTTP requests and responses — all **locally**, with **no data ever leaving your machine**.


## ✨ Features

- **Passive Security Analysis** – Automatically scans HTTP traffic for common vulnerabilities.
- **HAR Import** – Import captured traffic directly from browser dev tools or proxy tools.
- **Interactive Labs** – Dedicated modules for:
  - **Cache**
  - **CSP**
  - **CORS**
  - **Payload Generation**
- **Diff Tool** – Compare two responses side-by-side to spot subtle differences.
- **Local Persistence** – Sessions saved automatically in your browser’s local storage.
- **Exporting** – Download findings as a Markdown report for documentation or bug reports.

---

## 🚀 Getting Started

1. **Input Traffic**
   - Go to the **Inputs** tab.
   - Paste a raw HTTP request/response, or import a `.har` file (drag-and-drop or file picker).
   - Add as many transactions as you need to your session.

2. **Analyze**
   - Click the **Analyze** button to process all transactions.

3. **Review Findings**
   - Open the **Findings** tab to see identified issues with severity ratings and details.

4. **Dig Deeper**
   - Use tabs like **Cache**, **Cookies**, or **Diff** for manual deep analysis.

---

## 🔍 Modules Overview

- **Inputs** – Add HTTP requests/responses manually or via HAR import.
- **Findings** – List of discovered security issues. Filter by severity, mark false positives.
- **Cache** – Analyze potential cache poisoning and request smuggling risks.
- **Diff** – Highlight differences between two HTTP responses.
- **Payloads** – Generate custom HTTP requests for vulnerability testing (smuggling, header injection, etc.).
- **Cookies** – Analyze `Set-Cookie` headers for security flags (`Secure`, `HttpOnly`, `SameSite`).
- **CSP** – Audit Content Security Policies for weaknesses, and build stronger ones.
- **CORS** – Simulate and analyze CORS preflight requests for misconfigurations.
- **Project & Report** – Manage session data, export/import JSON, download findings as Markdown.

---

## 🤝 Contributing

Contributions are welcome!  
If you have a new feature idea or spot a bug:

1. **Fork** the repo.
2. Create your feature branch:  
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. Commit your changes:
    ```bash
    git commit -m 'Add some AmazingFeature'
    ```
4. Push to the branch:
    ```bash
    git push origin feature/AmazingFeature
    ```
5. Open a Pull Request.

---

# 📜 License

Distributed under the **MIT License**.  
