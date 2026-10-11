const sampleLogs = `2026-10-11T09:14:21Z firewall deny src=203.0.113.44 dst=10.0.0.12 proto=TCP dpt=22 reason=blocked
2026-10-11T09:14:23Z sshd[982]: Failed password for invalid user admin from 203.0.113.44 port 51544 ssh2
2026-10-11T09:14:28Z sshd[982]: Failed password for invalid user root from 203.0.113.44 port 51549 ssh2
2026-10-11T09:14:33Z sshd[982]: Failed password for invalid user test from 203.0.113.44 port 51551 ssh2
2026-10-11T09:14:41Z sshd[982]: Failed password for invalid user oracle from 203.0.113.44 port 51562 ssh2
2026-10-11T09:15:01Z firewall allow src=198.51.100.22 dst=10.0.0.21 proto=TCP dpt=443
2026-10-11T09:15:02Z firewall allow src=198.51.100.22 dst=10.0.0.21 proto=TCP dpt=80
2026-10-11T09:15:03Z firewall deny src=198.51.100.22 dst=10.0.0.21 proto=TCP dpt=3389 reason=blocked
2026-10-11T09:15:04Z firewall deny src=198.51.100.22 dst=10.0.0.21 proto=TCP dpt=445 reason=blocked
2026-10-11T09:15:05Z firewall deny src=198.51.100.22 dst=10.0.0.21 proto=TCP dpt=23 reason=blocked
2026-10-11T09:15:06Z firewall deny src=198.51.100.22 dst=10.0.0.21 proto=TCP dpt=5900 reason=blocked
2026-10-11T09:16:14Z nginx: 10.0.0.5 - - "GET /login HTTP/1.1" 200 src=192.0.2.18 dst=10.0.0.21 dpt=443
2026-10-11T09:16:18Z nginx: 10.0.0.5 - - "POST /login HTTP/1.1" 401 src=192.0.2.18 dst=10.0.0.21 dpt=443
2026-10-11T09:16:22Z nginx: 10.0.0.5 - - "POST /login HTTP/1.1" 401 src=192.0.2.18 dst=10.0.0.21 dpt=443
2026-10-11T09:16:27Z firewall allow src=10.0.0.8 dst=10.0.0.30 proto=UDP dpt=53`;

const unusualPorts = new Set([21, 22, 23, 25, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200]);
const elements = {
  input: document.querySelector("#logInput"),
  file: document.querySelector("#logFile"),
  analyze: document.querySelector("#analyze"),
  clear: document.querySelector("#clear"),
  loadSample: document.querySelector("#loadSample"),
  exportReport: document.querySelector("#exportReport"),
  totalEvents: document.querySelector("#totalEvents"),
  flaggedEvents: document.querySelector("#flaggedEvents"),
  uniqueSources: document.querySelector("#uniqueSources"),
  riskScore: document.querySelector("#riskScore"),
  findings: document.querySelector("#findings"),
  topSources: document.querySelector("#topSources"),
  table: document.querySelector("#eventsTable"),
  parseQuality: document.querySelector("#parseQuality"),
};

let currentReport = null;
const sampleFiles = {
  mixed: "assets/netscope-mixed-suspicious.log",
  clean: "assets/netscope-clean-traffic.log",
  ssh: "assets/netscope-ssh-bruteforce.log",
};

function parseLogLine(line, index) {
  const timeMatch = line.match(/\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:Z)?)\b/);
  const ips = [...line.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].map((match) => match[0]);
  const srcMatch = line.match(/\b(?:src|source|SRC)=?["']?((?:\d{1,3}\.){3}\d{1,3})/i);
  const dstMatch = line.match(/\b(?:dst|dest|destination|DST)=?["']?((?:\d{1,3}\.){3}\d{1,3})/i);
  const portMatch =
    line.match(/\b(?:dpt|dst_port|destination_port|port)=?["']?(\d{1,5})/i) ||
    line.match(/\bport\s+(\d{1,5})\b/i);
  const protocolMatch = line.match(/\b(TCP|UDP|ICMP|SSH|HTTP|HTTPS)\b/i);
  const denied = /\b(deny|denied|drop|dropped|blocked|reject|rejected|fail|failed|401|403)\b/i.test(line);
  const allowed = /\b(allow|allowed|accept|accepted|200|201|204)\b/i.test(line);
  const failedAuth = /\b(failed password|authentication failure|invalid user|login failed|401)\b/i.test(line);

  const source = srcMatch?.[1] || ips[0] || "unknown";
  const destination = dstMatch?.[1] || (srcMatch ? ips.find((ip) => ip !== source) : ips[1]) || "unknown";
  const port = portMatch ? Number(portMatch[1]) : null;

  return {
    id: index + 1,
    raw: line,
    time: timeMatch?.[1] || "unknown",
    source,
    destination,
    port,
    protocol: protocolMatch?.[1]?.toUpperCase() || "unknown",
    action: denied ? "Denied" : allowed ? "Allowed" : "Observed",
    failedAuth,
    flags: [],
  };
}

function analyzeEvents(events) {
  const bySource = groupBy(events, "source");
  const findings = [];

  for (const [source, sourceEvents] of bySource.entries()) {
    if (source === "unknown") continue;

    const failedAuthCount = sourceEvents.filter((event) => event.failedAuth).length;
    const deniedCount = sourceEvents.filter((event) => event.action === "Denied").length;
    const uniquePorts = new Set(sourceEvents.map((event) => event.port).filter(Boolean));
    const unusualHits = sourceEvents.filter((event) => event.port && unusualPorts.has(event.port));

    if (failedAuthCount >= 3) {
      flagEvents(sourceEvents.filter((event) => event.failedAuth), "Repeated failed authentication");
      findings.push({
        severity: "high",
        title: `Repeated failed logins from ${source}`,
        detail: `${failedAuthCount} failed authentication events were seen from this source.`,
      });
    }

    if (uniquePorts.size >= 5) {
      flagEvents(sourceEvents, "Scan-like activity across multiple ports");
      findings.push({
        severity: "high",
        title: `Port scan-like behaviour from ${source}`,
        detail: `${uniquePorts.size} destination ports were contacted by one source.`,
      });
    }

    if (sourceEvents.length >= 10) {
      flagEvents(sourceEvents, "High event volume from one source");
      findings.push({
        severity: "medium",
        title: `High traffic volume from ${source}`,
        detail: `${sourceEvents.length} events were observed from this source.`,
      });
    }

    if (deniedCount >= 3) {
      flagEvents(sourceEvents.filter((event) => event.action === "Denied"), "Repeated denied traffic");
      findings.push({
        severity: "medium",
        title: `Repeated denied traffic from ${source}`,
        detail: `${deniedCount} denied or blocked events were recorded.`,
      });
    }

    if (unusualHits.length >= 2) {
      flagEvents(unusualHits, "Unusual management or database port");
      findings.push({
        severity: "low",
        title: `Unusual ports contacted by ${source}`,
        detail: `Observed access attempts involving ports ${[...new Set(unusualHits.map((event) => event.port))].join(", ")}.`,
      });
    }
  }

  return findings;
}

function flagEvents(events, reason) {
  events.forEach((event) => {
    if (!event.flags.includes(reason)) event.flags.push(reason);
  });
}

function groupBy(events, key) {
  return events.reduce((map, event) => {
    const value = event[key] || "unknown";
    if (!map.has(value)) map.set(value, []);
    map.get(value).push(event);
    return map;
  }, new Map());
}

function renderReport(report) {
  elements.totalEvents.textContent = report.events.length;
  elements.flaggedEvents.textContent = report.flaggedEvents.length;
  elements.uniqueSources.textContent = report.uniqueSources;
  elements.riskScore.textContent = report.riskScore;
  elements.parseQuality.textContent = `${report.events.length} of ${report.totalLines} non-empty lines parsed`;

  renderFindings(report.findings);
  renderTopSources(report.topSources);
  renderTable(report.events);
}

function renderFindings(findings) {
  if (!findings.length) {
    elements.findings.className = "finding-list empty";
    elements.findings.textContent = "No suspicious patterns were flagged by the current rules.";
    return;
  }

  elements.findings.className = "finding-list";
  elements.findings.innerHTML = findings
    .map(
      (finding) => `
        <div class="finding">
          <strong class="severity-${finding.severity}">${escapeHtml(finding.title)}</strong>
          <p>${escapeHtml(finding.detail)}</p>
        </div>
      `,
    )
    .join("");
}

function renderTopSources(sources) {
  if (!sources.length) {
    elements.topSources.className = "source-list empty";
    elements.topSources.textContent = "No source data yet.";
    return;
  }

  elements.topSources.className = "source-list";
  elements.topSources.innerHTML = sources
    .map(
      ([source, count]) => `
        <div class="source-row">
          <strong>${escapeHtml(source)}</strong>
          <p>${count} event${count === 1 ? "" : "s"}</p>
        </div>
      `,
    )
    .join("");
}

function renderTable(events) {
  if (!events.length) {
    elements.table.innerHTML = `<tr><td colspan="6">No events parsed yet.</td></tr>`;
    return;
  }

  elements.table.innerHTML = events
    .slice(0, 100)
    .map(
      (event) => `
        <tr class="${event.flags.length ? "flagged" : ""}">
          <td>${escapeHtml(event.time)}</td>
          <td>${escapeHtml(event.source)}</td>
          <td>${escapeHtml(event.destination)}</td>
          <td>${event.port || "-"}</td>
          <td class="${event.action === "Denied" ? "action-deny" : event.action === "Allowed" ? "action-allow" : ""}">
            ${event.action}
          </td>
          <td>${event.flags.length ? escapeHtml(event.flags.join("; ")) : "No rule triggered"}</td>
        </tr>
      `,
    )
    .join("");
}

function runAnalysis() {
  const raw = elements.input.value.trim();
  const lines = raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const events = lines.map(parseLogLine).filter((event) => event.source !== "unknown" || event.port || event.action !== "Observed");
  const findings = analyzeEvents(events);
  const sourceCounts = [...groupBy(events, "source").entries()]
    .filter(([source]) => source !== "unknown")
    .map(([source, sourceEvents]) => [source, sourceEvents.length])
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  const flaggedEvents = events.filter((event) => event.flags.length);
  const riskScore = Math.min(100, findings.reduce((score, finding) => score + (finding.severity === "high" ? 28 : finding.severity === "medium" ? 16 : 8), 0));

  currentReport = {
    createdAt: new Date().toISOString(),
    totalLines: lines.length,
    events,
    findings,
    flaggedEvents,
    uniqueSources: new Set(events.map((event) => event.source).filter((source) => source !== "unknown")).size,
    topSources: sourceCounts,
    riskScore,
  };

  renderReport(currentReport);
}

function exportReport() {
  if (!currentReport) runAnalysis();
  if (!currentReport) return;

  const report = [
    "NetScope Log Analyzer Report",
    `Generated: ${new Date(currentReport.createdAt).toLocaleString()}`,
    "",
    `Total events: ${currentReport.events.length}`,
    `Flagged events: ${currentReport.flaggedEvents.length}`,
    `Unique source IPs: ${currentReport.uniqueSources}`,
    `Risk score: ${currentReport.riskScore}/100`,
    "",
    "Findings:",
    ...(currentReport.findings.length
      ? currentReport.findings.map((finding) => `- [${finding.severity.toUpperCase()}] ${finding.title}: ${finding.detail}`)
      : ["- No suspicious patterns were flagged by the current rules."]),
    "",
    "Flagged Events:",
    ...currentReport.flaggedEvents.map((event) => `- ${event.time} ${event.source} -> ${event.destination}:${event.port || "-"} ${event.action} | ${event.flags.join("; ")}`),
  ].join("\n");

  const blob = new Blob([report], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "netscope-report.txt";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

elements.analyze.addEventListener("click", runAnalysis);
elements.loadSample.addEventListener("click", () => {
  elements.input.value = sampleLogs;
  runAnalysis();
});
document.querySelectorAll("[data-sample]").forEach((button) => {
  button.addEventListener("click", async () => {
    const response = await fetch(sampleFiles[button.dataset.sample]);
    elements.input.value = await response.text();
    runAnalysis();
  });
});
elements.clear.addEventListener("click", () => {
  elements.input.value = "";
  currentReport = null;
  renderReport({
    totalLines: 0,
    events: [],
    findings: [],
    flaggedEvents: [],
    uniqueSources: 0,
    topSources: [],
    riskScore: 0,
  });
});
elements.exportReport.addEventListener("click", exportReport);
elements.file.addEventListener("change", async (event) => {
  const [file] = event.target.files;
  if (!file) return;
  elements.input.value = await file.text();
  runAnalysis();
});

elements.input.value = sampleLogs;
runAnalysis();
