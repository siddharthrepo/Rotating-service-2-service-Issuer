(async function () {
  const res = await fetch("/api/graph", { headers: { Accept: "application/json" } });
  if (!res.ok) { document.getElementById("cy").textContent = "failed to load graph"; return; }
  const data = await res.json();

  const calls = data.edges.map(e => e.calls);
  const maxCalls = Math.max(1, ...calls);

  const elements = [];
  for (const n of data.nodes) {
    elements.push({ data: { id: "s" + n.id, label: n.name, status: n.status,
                            team: n.owner_team || "", deg: n.in_degree + n.out_degree } });
  }
  for (const e of data.edges) {
    const from = data.nodes.find(n => n.name === e.caller);
    const to = data.nodes.find(n => n.name === e.target);
    if (!from || !to) continue;
    elements.push({ data: {
      id: "g" + e.grant_id, source: "s" + from.id, target: "s" + to.id,
      width: 1 + 5 * Math.sqrt(e.calls / maxCalls),
      state: e.status !== "active" ? "dead" : (e.calls > 0 ? "live" : "idle"),
      label: e.calls > 0 ? String(e.calls) : "",
      detail: e,
    }});
  }

  const css = getComputedStyle(document.documentElement);
  const v = n => css.getPropertyValue(n).trim();

  const cy = cytoscape({
    container: document.getElementById("cy"),
    elements,
    style: [
      { selector: "node", style: {
        "background-color": v("--panel-2"), "border-width": 2, "border-color": v("--idle"),
        label: "data(label)", color: v("--fg"), "font-size": 11, "font-family": "ui-monospace,monospace",
        "text-valign": "bottom", "text-margin-y": 6,
        width: "mapData(deg, 0, 8, 26, 52)", height: "mapData(deg, 0, 8, 26, 52)" } },
      { selector: 'node[status = "active"]', style: { "border-color": v("--accent") } },
      { selector: 'node[status = "disabled"]', style: { "border-color": v("--danger"), opacity: 0.55 } },
      { selector: "edge", style: {
        width: "data(width)", "curve-style": "bezier", "target-arrow-shape": "triangle",
        "line-color": v("--idle"), "target-arrow-color": v("--idle"),
        label: "data(label)", "font-size": 9, color: v("--muted"),
        "text-background-color": v("--panel"), "text-background-opacity": 1,
        "text-background-padding": 2 } },
      { selector: 'edge[state = "live"]', style: {
        "line-color": v("--ok"), "target-arrow-color": v("--ok") } },
      { selector: 'edge[state = "dead"]', style: {
        "line-color": v("--danger"), "target-arrow-color": v("--danger"),
        "line-style": "dashed", opacity: 0.6 } },
    ],
    layout: { name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 140, padding: 40 },
  });

  const panel = document.getElementById("edge-detail");
  cy.on("tap", "edge", evt => {
    const d = evt.target.data("detail");
    panel.classList.remove("hidden");
    panel.innerHTML = `
      <div class="mono strong">${d.caller} <span class="arrow">→</span> ${d.target}</div>
      <div class="muted small" style="margin-top:6px">
        grant ${d.grant_id} · <span class="pill ${d.status}">${d.status}</span>
        · ${d.calls} calls${d.denies ? ` · ${d.denies} denied` : ""} in the last hour
        ${d.last_seen ? ` · last seen ${new Date(d.last_seen).toLocaleString()}` : " · never seen"}
      </div>
      <div style="margin-top:8px">${(d.scopes || []).map(s => `<code>${s}</code>`).join(" ") || '<span class="muted">no scopes</span>'}</div>`;
  });
  cy.on("tap", evt => { if (evt.target === cy) panel.classList.add("hidden"); });
})();
