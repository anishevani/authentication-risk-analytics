(function () {
  const data = window.AUTH_DATA;
  if (!data) {
    document.querySelector("main").textContent = "Dashboard data is missing. Run python src/build_dashboard.py.";
    return;
  }
  const page = document.body.dataset.page;
  if (page === "overview") renderOverview(data);
  if (page === "high-risk") renderHighRisk(data);
  if (page === "investigate") renderInvestigation(data);
})();

function badge(level, score) {
  const label = score === undefined ? level : level + " " + score;
  return '<span class="badge badge-' + level + '">' + label + "</span>";
}

function renderOverview(data) {
  const meta = data.meta;
  document.getElementById("kpi-attempts").textContent = meta.attempts.toLocaleString();
  document.getElementById("kpi-failed").textContent = meta.failed_logins.toLocaleString();
  document.getElementById("kpi-high").textContent = meta.high_risk_events.toLocaleString();
  document.getElementById("kpi-users").textContent = meta.affected_users.toLocaleString();
  const levels = ["low", "medium", "high", "critical"];
  const host = document.getElementById("distribution");
  host.innerHTML = levels
    .map(function (level) {
      const count = meta.levels[level];
      const width = Math.max(count ? 1.5 : 0, (100 * count) / meta.attempts);
      return (
        '<div class="dist-row"><div>' +
        level +
        '</div><div class="bar"><span class="' +
        level +
        '" style="width:' +
        width +
        '%"></span></div><div>' +
        count.toLocaleString() +
        "</div></div>"
      );
    })
    .join("");
  const queued = data.events.filter(function (row) {
    return row.risk_score >= meta.queue_min_score;
  });
  document.getElementById("queue-count").textContent = String(queued.length);
  fillTable(document.querySelector("#queue-table tbody"), queued);
}

function renderHighRisk(data) {
  const rows = data.events.filter(function (row) {
    return row.risk_score >= data.meta.high_risk_min_score;
  });
  document.getElementById("high-count").textContent = String(rows.length);
  fillTable(document.querySelector("#high-table tbody"), rows);
}

function fillTable(body, rows) {
  body.innerHTML = rows
    .map(function (row) {
      const signals = row.signals.length ? row.signals.join(", ") : "none";
      return (
        "<tr><td>" +
        escapeHtml(row.chicago_time) +
        '</td><td><a href="investigate.html?event=' +
        encodeURIComponent(row.event_id) +
        '">' +
        escapeHtml(row.event_id) +
        "</a></td><td>" +
        escapeHtml(row.username) +
        "</td><td>" +
        escapeHtml(row.auth_result) +
        "</td><td>" +
        escapeHtml(row.ip_address) +
        "</td><td>" +
        escapeHtml(row.country_code) +
        "</td><td>" +
        escapeHtml(row.device || "blank fingerprint") +
        "</td><td>" +
        badge(row.risk_level, row.risk_score) +
        "</td><td>" +
        escapeHtml(signals) +
        "</td></tr>"
      );
    })
    .join("");
}

function renderInvestigation(data) {
  const events = data.events;
  const user = document.getElementById("filter-user");
  const risk = document.getElementById("filter-risk");
  const ip = document.getElementById("filter-ip");
  const device = document.getElementById("filter-device");
  const eventSelect = document.getElementById("filter-event");
  const from = document.getElementById("filter-from");
  const to = document.getElementById("filter-to");

  fillOptions(user, unique(events.map((row) => row.user_id + " " + row.username)));
  fillOptions(ip, unique(events.map((row) => row.ip_address)));
  fillOptions(device, unique(events.map((row) => row.device || "blank fingerprint")));
  ["", "low", "medium", "high", "critical"].forEach(function (level, index) {
    if (index === 0) return;
    risk.insertAdjacentHTML("beforeend", '<option value="' + level + '">' + level + "</option>");
  });

  function matching() {
    return events.filter(function (row) {
      if (user.value && user.value !== row.user_id + " " + row.username) return false;
      if (risk.value && risk.value !== row.risk_level) return false;
      if (ip.value && ip.value !== row.ip_address) return false;
      if (device.value && device.value !== (row.device || "blank fingerprint")) return false;
      const day = row.event_time.slice(0, 10);
      if (from.value && day < from.value) return false;
      if (to.value && day > to.value) return false;
      return true;
    });
  }

  function refillEvents() {
    const rows = matching();
    const current = eventSelect.value;
    eventSelect.innerHTML = '<option value="">Select an event</option>';
    rows.forEach(function (row) {
      const option = document.createElement("option");
      option.value = row.event_id;
      option.textContent =
        row.event_id + " · " + row.chicago_time + " · " + row.risk_level + " " + row.risk_score;
      eventSelect.appendChild(option);
    });
    if (rows.some((row) => row.event_id === current)) eventSelect.value = current;
    const noun = rows.length === 1 ? "event matches" : "events match";
    document.getElementById("match-count").textContent = rows.length + " " + noun + " the filters.";
    const selected = rows.find((row) => row.event_id === eventSelect.value);
    renderDetail(selected || null);
  }

  [user, risk, ip, device, from, to, eventSelect].forEach(function (node) {
    node.addEventListener("change", refillEvents);
  });

  const requested = new URLSearchParams(window.location.search).get("event");
  refillEvents();
  if (requested && events.some((row) => row.event_id === requested)) {
    eventSelect.value = requested;
    renderDetail(events.find((row) => row.event_id === requested));
    const matched = matching().length;
    const noun = matched === 1 ? "event matches" : "events match";
    document.getElementById("match-count").textContent =
      matched + " " + noun + " the filters. Showing " + requested + ".";
  }
}

function renderDetail(row) {
  const host = document.getElementById("detail");
  if (!row) {
    host.innerHTML = '<p class="empty">Select an event to see the facts and the signals behind the score.</p>';
    return;
  }
  const points = row.contributions.reduce(function (sum, item) { return sum + item.points; }, 0);
  const capNote =
    points > row.risk_score
      ? "<p>Rule points add to " + points + ". The reported score is capped at 100. Every signal is still listed.</p>"
      : "";
  const signals = row.contributions.length
    ? row.contributions
        .map(function (item) {
          return (
            '<div class="signal"><strong>' +
            escapeHtml(item.signal) +
            " · +" +
            item.points +
            "</strong><div>" +
            escapeHtml(item.reason) +
            "</div></div>"
          );
        })
        .join("")
    : "<p>No signal fired.</p>";
  const steps = row.explanation.recommended_steps
    .map(function (step) { return "<li>" + escapeHtml(step) + "</li>"; })
    .join("");
  const indicators = row.explanation.relevant_indicators
    .map(function (item) { return "<li>" + escapeHtml(item) + "</li>"; })
    .join("");
  host.innerHTML =
    '<div class="card"><h2>' +
    escapeHtml(row.event_id) +
    " " +
    badge(row.risk_level, row.risk_score) +
    "</h2><dl>" +
    pair("User", row.username + " (" + row.user_id + ")") +
    pair("Time (Chicago)", row.chicago_time) +
    pair("Time (UTC)", row.event_time) +
    pair("Result", row.auth_result) +
    pair("Failure reason", row.failure_reason || "blank") +
    pair("IP", row.ip_address) +
    pair("Place", row.city + ", " + row.country_code) +
    pair("Device", row.device || "blank fingerprint") +
    pair("Client", row.client_app) +
    pair("MFA", row.mfa_result || "blank") +
    pair("Session", row.session_id || "blank") +
    "</dl>" +
    capNote +
    "<h2>Signals</h2>" +
    signals +
    "</div><div class=\"card\"><h2>Incident note</h2><p>" +
    escapeHtml(row.explanation.summary) +
    "</p><h2>Why flagged</h2><p>" +
    escapeHtml(row.explanation.why_flagged) +
    "</p><h2>Relevant indicators</h2><ol>" +
    indicators +
    "</ol><h2>Recommended investigation steps</h2><ol>" +
    steps +
    "</ol></div>";
}

function pair(label, value) {
  return "<dt>" + escapeHtml(label) + "</dt><dd>" + escapeHtml(value) + "</dd>";
}

function fillOptions(select, values) {
  values.forEach(function (value) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    select.appendChild(option);
  });
}

function unique(values) {
  return Array.from(new Set(values)).sort();
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
