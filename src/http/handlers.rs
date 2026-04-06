use super::state::AppState;
use super::views::layout;
use crate::audit;
use crate::objects;
use crate::tailscale::{User, UserClaims};
use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse},
    Extension, Json,
};
use base32;
use base64;
use hex;
use hmac::{Hmac, Mac};
use lmdb::Transaction;
use qrcode::render::svg;
use qrcode::QrCode;
use rand::Rng;
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use v_htmlescape::escape;

// ── Admin dashboard ──────────────────────────────────────────────────────────

pub async fn admin_dashboard(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
) -> impl IntoResponse {
    let admin_user = claims.email.clone().unwrap_or_default();
    let base_dn = &state.config.base_dn;

    // Fetch data in parallel-ish (cached so fast)
    let ts_users = state.tailscale.cached_list_users().await.unwrap_or_default();
    let ts_devices = state.tailscale.cached_list_devices().await.unwrap_or_default();
    let entries = objects::get_all_entries(&state.tailscale, base_dn).await;

    let total_users = ts_users.len();
    let total_devices = ts_devices.len();
    let total_entries = entries.len();
    let online_devices = ts_devices.iter().filter(|d| d.authorized).count();

    // ── Stats cards ──
    let stats_html = format!(
        r#"<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:2rem;">
            <div style="background:var(--light-gray);padding:1.5rem;border:1px solid var(--text);">
                <div style="font-size:2rem;font-weight:bold;">{}</div>
                <div>Users</div>
            </div>
            <div style="background:var(--light-gray);padding:1.5rem;border:1px solid var(--text);">
                <div style="font-size:2rem;font-weight:bold;">{}</div>
                <div>Devices</div>
            </div>
            <div style="background:var(--light-gray);padding:1.5rem;border:1px solid var(--text);">
                <div style="font-size:2rem;font-weight:bold;">{}</div>
                <div>Authorized</div>
            </div>
            <div style="background:var(--light-gray);padding:1.5rem;border:1px solid var(--text);">
                <div style="font-size:2rem;font-weight:bold;">{}</div>
                <div>LDAP Entries</div>
            </div>
        </div>"#,
        total_users, total_devices, online_devices, total_entries
    );

    // ── Users table ──
    let mut users_rows = String::new();
    for u in &ts_users {
        let uid = u.login_name.split('@').next().unwrap_or(&u.login_name);
        let dn = format!("uid={},ou=people,{}", uid, base_dn);
        let has_otp = state.env.begin_ro_txn().ok().map_or(false, |txn| {
            txn.get(state.otp_db, &dn.as_bytes())
                .ok()
                .and_then(|b| serde_json::from_slice::<objects::OtpData>(b).ok())
                .map_or(false, |o| o.password_hmac.is_some() && o.totp_secret.is_some())
        });
        let otp_badge = if has_otp {
            "<span style=\"color:green;\">\u{2713}</span>"
        } else {
            "<span style=\"color:red;\">\u{2717}</span>"
        };
        users_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(uid),
            escape(&u.login_name),
            escape(&u.role),
            escape(&u.status),
            otp_badge
        ));
    }
    let users_table = format!(
        r#"<h2>Users</h2>
        <table>
            <thead><tr><th>UID</th><th>Login</th><th>Role</th><th>Status</th><th>OTP</th></tr></thead>
            <tbody>{}</tbody>
        </table>"#,
        users_rows
    );

    // ── Devices table ──
    let mut devices_rows = String::new();
    for d in &ts_devices {
        let hostname = if d.hostname.is_empty() {
            d.name.trim_end_matches('.').to_string()
        } else {
            d.hostname.clone()
        };
        let addrs = d.addresses.join(", ");
        let auth_badge = if d.authorized {
            "<span style=\"color:green;\">\u{2713}</span>"
        } else {
            "<span style=\"color:red;\">\u{2717}</span>"
        };
        let last_seen = d.last_seen.format("%Y-%m-%d %H:%M").to_string();
        devices_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&hostname),
            escape(&addrs),
            escape(&d.os),
            auth_badge,
            escape(&d.user),
            escape(&last_seen)
        ));
    }
    let devices_table = format!(
        r#"<h2>Devices</h2>
        <table>
            <thead><tr><th>Hostname</th><th>Addresses</th><th>OS</th><th>Auth</th><th>User</th><th>Last Seen</th></tr></thead>
            <tbody>{}</tbody>
        </table>"#,
        devices_rows
    );

    // ── LDAP entries summary ──
    let people_count = entries.keys().filter(|k| k.contains("ou=people")).count();
    let groups_count = entries.keys().filter(|k| k.contains("ou=groups")).count();
    let machines_count = entries.keys().filter(|k| k.contains("ou=machines")).count();
    let ldap_summary = format!(
        r#"<h2>LDAP Directory</h2>
        <p>Base DN: <code>{}</code></p>
        <table>
            <thead><tr><th>OU</th><th>Entry Count</th></tr></thead>
            <tbody>
                <tr><td>ou=people</td><td>{}</td></tr>
                <tr><td>ou=groups</td><td>{}</td></tr>
                <tr><td>ou=machines</td><td>{}</td></tr>
            </tbody>
        </table>"#,
        escape(base_dn), people_count, groups_count, machines_count
    );

    let body = format!(
        r#"<header>
            <strong>dit0</strong>
            <a href="/">Profile</a>
            <a href="/admin" class="active">Admin</a>
            <span style="margin-left:auto;">{}</span>
        </header>
        <div class="main-content">
            <h1>Admin Dashboard</h1>
            {}
            <h2>Audit Log</h2>
            <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;flex-wrap:wrap;" id="cal-controls">
                <button id="cal-zoom-out" title="Zoom out">&minus;</button>
                <span id="cal-level" style="min-width:60px;text-align:center;font-weight:bold;"></span>
                <button id="cal-zoom-in" title="Zoom in">+</button>
                <button id="cal-prev" title="Previous">&larr;</button>
                <span id="cal-title" style="min-width:180px;text-align:center;font-weight:bold;"></span>
                <button id="cal-next" title="Next">&rarr;</button>
                <button id="cal-today">Today</button>
            </div>
            <div class="graph-container" style="min-height:180px;overflow-x:auto;" id="cal-container"></div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin:2rem 0;">
                <div class="graph-container" style="height:280px;" id="chart-types"></div>
                <div class="graph-container" style="height:280px;" id="chart-timeline"></div>
            </div>
            <div id="audit-table-container"></div>
            {}
            {}
            {}
        </div>
        <script src="https://d3js.org/d3.v7.min.js"></script>
        <script>
        (function() {{
            fetch('/admin/api/audit')
                .then(r => r.json())
                .then(events => {{
                    initCalendar(events);
                    renderTypePie(events);
                    renderTimeline(events);
                    renderTable(events);
                }});

            /* ── Interactive Calendar Heatmap ─────────────────────── */
            function initCalendar(events) {{
                const levels = ['year','month','week','day'];
                let levelIdx = 0;
                let anchor = new Date();

                function startOf(date, level) {{
                    const d = new Date(date);
                    if (level === 'year')  {{ d.setMonth(0,1); d.setHours(0,0,0,0); }}
                    if (level === 'month') {{ d.setDate(1); d.setHours(0,0,0,0); }}
                    if (level === 'week')  {{ const day = d.getDay(); d.setDate(d.getDate() - day); d.setHours(0,0,0,0); }}
                    if (level === 'day')   {{ d.setHours(0,0,0,0); }}
                    return d;
                }}

                function addPeriod(date, level, n) {{
                    const d = new Date(date);
                    if (level === 'year')  d.setFullYear(d.getFullYear() + n);
                    if (level === 'month') d.setMonth(d.getMonth() + n);
                    if (level === 'week')  d.setDate(d.getDate() + 7 * n);
                    if (level === 'day')   d.setDate(d.getDate() + n);
                    return d;
                }}

                function titleFor(date, level) {{
                    const fmt = d3.timeFormat;
                    if (level === 'year')  return fmt('%Y')(date);
                    if (level === 'month') return fmt('%B %Y')(date);
                    if (level === 'week')  {{
                        const end = addPeriod(date, 'day', 6);
                        return fmt('%d %b')(date) + ' – ' + fmt('%d %b %Y')(end);
                    }}
                    if (level === 'day')   return fmt('%A, %d %B %Y')(date);
                    return '';
                }}

                function render() {{
                    const level = levels[levelIdx];
                    d3.select('#cal-level').text(level);
                    const base = startOf(anchor, level);
                    d3.select('#cal-title').text(titleFor(base, level));

                    d3.select('#cal-container').selectAll('*').remove();

                    if (level === 'year')  renderYear(base, events);
                    if (level === 'month') renderMonth(base, events);
                    if (level === 'week')  renderWeek(base, events);
                    if (level === 'day')   renderDay(base, events);
                }}

                d3.select('#cal-zoom-in').on('click', () => {{ if (levelIdx < levels.length - 1) {{ levelIdx++; render(); }} }});
                d3.select('#cal-zoom-out').on('click', () => {{ if (levelIdx > 0) {{ levelIdx--; render(); }} }});
                d3.select('#cal-prev').on('click', () => {{ anchor = addPeriod(anchor, levels[levelIdx], -1); render(); }});
                d3.select('#cal-next').on('click', () => {{ anchor = addPeriod(anchor, levels[levelIdx],  1); render(); }});
                d3.select('#cal-today').on('click', () => {{ anchor = new Date(); render(); }});

                render();
            }}

            /* bucket helper: key = YYYY-MM-DD */
            function dayKey(d) {{ return d3.timeFormat('%Y-%m-%d')(d instanceof Date ? d : new Date(d * 1000)); }}
            function hourKey(d) {{ return d3.timeFormat('%Y-%m-%d %H')(d instanceof Date ? d : new Date(d * 1000)); }}

            function bucketByDay(events) {{
                const m = {{}};
                events.forEach(e => {{
                    const k = dayKey(e.ts);
                    if (!m[k]) m[k] = {{total:0, failure:0}};
                    m[k].total++;
                    if (e.result === 'failure') m[k].failure++;
                }});
                return m;
            }}
            function bucketByHour(events) {{
                const m = {{}};
                events.forEach(e => {{
                    const k = hourKey(e.ts);
                    if (!m[k]) m[k] = {{total:0, failure:0}};
                    m[k].total++;
                    if (e.result === 'failure') m[k].failure++;
                }});
                return m;
            }}

            function heatColor(count, maxCount, failRatio) {{
                if (count === 0) return 'var(--light-gray)';
                const intensity = Math.min(count / Math.max(maxCount, 1), 1);
                if (failRatio > 0.5) {{
                    const r = Math.round(200 + 55 * intensity);
                    const g = Math.round(230 - 180 * intensity);
                    const b = Math.round(230 - 180 * intensity);
                    return `rgb(${{r}},${{g}},${{b}})`;
                }}
                const r = Math.round(230 - 180 * intensity);
                const g = Math.round(230 - 30 * intensity);
                const b = Math.round(230 - 180 * intensity);
                return `rgb(${{r}},${{g}},${{b}})`;
            }}

            /* ── Year view: 53 columns x 7 rows like GitHub ───── */
            function renderYear(yearStart, events) {{
                const container = d3.select('#cal-container');
                const cellSize = 16;
                const gap = 2;
                const dayNames = ['S','M','T','W','T','F','S'];
                const yr = yearStart.getFullYear();
                const jan1 = new Date(yr, 0, 1);
                const dec31 = new Date(yr, 11, 31);
                const dayOfWeekJan1 = jan1.getDay();
                const totalDays = Math.round((dec31 - jan1) / 86400000) + 1;
                const weeks = Math.ceil((totalDays + dayOfWeekJan1) / 7);

                const margin = {{left: 24, top: 24}};
                const width = margin.left + weeks * (cellSize + gap) + 20;
                const height = margin.top + 7 * (cellSize + gap) + 20;

                const svg = container.append('svg').attr('width', width).attr('height', height);

                // Day labels
                dayNames.forEach((n, i) => {{
                    svg.append('text').attr('x', margin.left - 4).attr('y', margin.top + i * (cellSize + gap) + cellSize * 0.75)
                       .attr('text-anchor','end').attr('font-size',10).text(n);
                }});

                const buckets = bucketByDay(events);
                const maxCount = Math.max(...Object.values(buckets).map(b => b.total), 1);

                // Month labels
                const months = d3.timeMonths(jan1, new Date(yr + 1, 0, 1));
                months.forEach(m => {{
                    const daysSince = Math.round((m - jan1) / 86400000);
                    const col = Math.floor((daysSince + dayOfWeekJan1) / 7);
                    svg.append('text')
                       .attr('x', margin.left + col * (cellSize + gap))
                       .attr('y', margin.top - 6)
                       .attr('font-size', 10).text(d3.timeFormat('%b')(m));
                }});

                for (let d = 0; d < totalDays; d++) {{
                    const date = new Date(yr, 0, 1 + d);
                    const dow = date.getDay();
                    const weekNum = Math.floor((d + dayOfWeekJan1) / 7);
                    const key = dayKey(date);
                    const bucket = buckets[key] || {{total:0, failure:0}};
                    const failRatio = bucket.total > 0 ? bucket.failure / bucket.total : 0;

                    svg.append('rect')
                       .attr('x', margin.left + weekNum * (cellSize + gap))
                       .attr('y', margin.top + dow * (cellSize + gap))
                       .attr('width', cellSize).attr('height', cellSize)
                       .attr('rx', 2)
                       .attr('fill', heatColor(bucket.total, maxCount, failRatio))
                       .attr('stroke', '#ccc').attr('stroke-width', 0.5)
                       .style('cursor', 'pointer')
                       .on('click', () => {{
                           // Zoom into that day
                           d3.select('#cal-zoom-in').node().__data__ = date;
                           // hack: set anchor & level directly
                           // We rely on closure
                       }})
                       .append('title').text(`${{key}}: ${{bucket.total}} events (${{bucket.failure}} failures)`);
                }}
            }}

            /* ── Month view: grid of days ────────────────────── */
            function renderMonth(monthStart, events) {{
                const container = d3.select('#cal-container');
                const cellSize = 36;
                const gap = 3;
                const yr = monthStart.getFullYear();
                const mo = monthStart.getMonth();
                const daysInMonth = new Date(yr, mo + 1, 0).getDate();
                const startDow = new Date(yr, mo, 1).getDay();
                const cols = 7;
                const rows = Math.ceil((daysInMonth + startDow) / 7);

                const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
                const margin = {{left: 10, top: 30}};
                const width = margin.left + cols * (cellSize + gap) + 10;
                const height = margin.top + rows * (cellSize + gap) + 10;

                const svg = container.append('svg').attr('width', width).attr('height', height);

                // headers
                dayNames.forEach((n, i) => {{
                    svg.append('text').attr('x', margin.left + i * (cellSize + gap) + cellSize / 2)
                       .attr('y', margin.top - 8).attr('text-anchor','middle').attr('font-size',11).text(n);
                }});

                const buckets = bucketByDay(events);
                const maxCount = Math.max(...Object.values(buckets).map(b => b.total), 1);

                for (let d = 0; d < daysInMonth; d++) {{
                    const date = new Date(yr, mo, d + 1);
                    const dow = (d + startDow) % 7;
                    const row = Math.floor((d + startDow) / 7);
                    const key = dayKey(date);
                    const bucket = buckets[key] || {{total:0, failure:0}};
                    const failRatio = bucket.total > 0 ? bucket.failure / bucket.total : 0;

                    const g = svg.append('g').style('cursor','pointer');
                    g.append('rect')
                       .attr('x', margin.left + dow * (cellSize + gap))
                       .attr('y', margin.top + row * (cellSize + gap))
                       .attr('width', cellSize).attr('height', cellSize)
                       .attr('rx', 3)
                       .attr('fill', heatColor(bucket.total, maxCount, failRatio))
                       .attr('stroke', '#aaa').attr('stroke-width', 0.5);
                    g.append('text')
                       .attr('x', margin.left + dow * (cellSize + gap) + cellSize / 2)
                       .attr('y', margin.top + row * (cellSize + gap) + cellSize / 2 + 4)
                       .attr('text-anchor','middle').attr('font-size',11)
                       .text(d + 1);
                    g.append('title').text(`${{key}}: ${{bucket.total}} events (${{bucket.failure}} failures)`);
                }}
            }}

            /* ── Week view: 7 columns x 24 hour rows ─────────── */
            function renderWeek(weekStart, events) {{
                const container = d3.select('#cal-container');
                const cellW = 80;
                const cellH = 18;
                const gap = 2;
                const margin = {{left: 44, top: 28}};
                const width = margin.left + 7 * (cellW + gap) + 10;
                const height = margin.top + 24 * (cellH + gap) + 10;

                const svg = container.append('svg').attr('width', width).attr('height', height);

                const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
                for (let col = 0; col < 7; col++) {{
                    const d = new Date(weekStart);
                    d.setDate(d.getDate() + col);
                    svg.append('text')
                       .attr('x', margin.left + col * (cellW + gap) + cellW / 2)
                       .attr('y', margin.top - 8)
                       .attr('text-anchor','middle').attr('font-size',11)
                       .text(dayNames[d.getDay()] + ' ' + d.getDate());
                }}
                for (let row = 0; row < 24; row++) {{
                    svg.append('text')
                       .attr('x', margin.left - 4)
                       .attr('y', margin.top + row * (cellH + gap) + cellH * 0.75)
                       .attr('text-anchor','end').attr('font-size',9)
                       .text(String(row).padStart(2,'0'));
                }}

                const buckets = bucketByHour(events);
                const maxCount = Math.max(...Object.values(buckets).map(b => b.total), 1);

                for (let col = 0; col < 7; col++) {{
                    for (let row = 0; row < 24; row++) {{
                        const d = new Date(weekStart);
                        d.setDate(d.getDate() + col);
                        d.setHours(row, 0, 0, 0);
                        const key = hourKey(d);
                        const bucket = buckets[key] || {{total:0, failure:0}};
                        const failRatio = bucket.total > 0 ? bucket.failure / bucket.total : 0;

                        svg.append('rect')
                           .attr('x', margin.left + col * (cellW + gap))
                           .attr('y', margin.top + row * (cellH + gap))
                           .attr('width', cellW).attr('height', cellH)
                           .attr('rx', 2)
                           .attr('fill', heatColor(bucket.total, maxCount, failRatio))
                           .attr('stroke', '#ccc').attr('stroke-width', 0.5)
                           .append('title').text(`${{key}}:00 — ${{bucket.total}} events (${{bucket.failure}} failures)`);
                    }}
                }}
            }}

            /* ── Day view: 24 rows with 6x10-min buckets ─────── */
            function renderDay(dayStart, events) {{
                const container = d3.select('#cal-container');
                const cellW = 60;
                const cellH = 22;
                const gap = 2;
                const cols = 6; // 10-min buckets
                const margin = {{left: 44, top: 28}};
                const width = margin.left + cols * (cellW + gap) + 10;
                const height = margin.top + 24 * (cellH + gap) + 10;

                const svg = container.append('svg').attr('width', width).attr('height', height);

                // Column headers: :00, :10, :20, :30, :40, :50
                for (let c = 0; c < cols; c++) {{
                    svg.append('text')
                       .attr('x', margin.left + c * (cellW + gap) + cellW / 2)
                       .attr('y', margin.top - 8)
                       .attr('text-anchor','middle').attr('font-size',10)
                       .text(':' + String(c * 10).padStart(2,'0'));
                }}
                for (let row = 0; row < 24; row++) {{
                    svg.append('text')
                       .attr('x', margin.left - 4)
                       .attr('y', margin.top + row * (cellH + gap) + cellH * 0.7)
                       .attr('text-anchor','end').attr('font-size',10)
                       .text(String(row).padStart(2,'0'));
                }}

                // Bucket by 10-min
                const bucketMap = {{}};
                events.forEach(e => {{
                    const d = new Date(e.ts * 1000);
                    const k = d3.timeFormat('%Y-%m-%d %H')(d) + ':' + String(Math.floor(d.getMinutes() / 10) * 10).padStart(2,'0');
                    if (!bucketMap[k]) bucketMap[k] = {{total:0, failure:0}};
                    bucketMap[k].total++;
                    if (e.result === 'failure') bucketMap[k].failure++;
                }});
                const maxCount = Math.max(...Object.values(bucketMap).map(b => b.total), 1);

                const dayStr = d3.timeFormat('%Y-%m-%d')(dayStart);
                for (let row = 0; row < 24; row++) {{
                    for (let c = 0; c < cols; c++) {{
                        const min = c * 10;
                        const key = dayStr + ' ' + String(row).padStart(2,'0') + ':' + String(min).padStart(2,'0');
                        const bucket = bucketMap[key] || {{total:0, failure:0}};
                        const failRatio = bucket.total > 0 ? bucket.failure / bucket.total : 0;

                        svg.append('rect')
                           .attr('x', margin.left + c * (cellW + gap))
                           .attr('y', margin.top + row * (cellH + gap))
                           .attr('width', cellW).attr('height', cellH)
                           .attr('rx', 2)
                           .attr('fill', heatColor(bucket.total, maxCount, failRatio))
                           .attr('stroke', '#ccc').attr('stroke-width', 0.5)
                           .append('title').text(`${{key}} — ${{bucket.total}} events (${{bucket.failure}} failures)`);
                    }}
                }}
            }}

            /* ── Timeline bar chart (bottom-left) ───────────────── */
            function renderTimeline(events) {{
                const container = d3.select('#chart-timeline');
                const width = container.node().clientWidth;
                const height = container.node().clientHeight;
                const margin = {{top: 20, right: 20, bottom: 40, left: 50}};
                const w = width - margin.left - margin.right;
                const h = height - margin.top - margin.bottom;

                const svg = container.append('svg').attr('width', width).attr('height', height);
                const g = svg.append('g').attr('transform', `translate(${{margin.left}},${{margin.top}})`);

                if (events.length === 0) {{
                    g.append('text').attr('x', w/2).attr('y', h/2).attr('text-anchor','middle').text('No events yet');
                    return;
                }}

                const now = Math.floor(Date.now()/1000);
                const bucketSize = 60;
                const lookback = 3600;
                const minTs = now - lookback;
                const buckets = {{}};
                for (let t = minTs; t <= now; t += bucketSize) buckets[t] = {{success:0, failure:0}};
                events.forEach(e => {{
                    if (e.ts < minTs) return;
                    const key = Math.floor((e.ts - minTs) / bucketSize) * bucketSize + minTs;
                    if (!buckets[key]) buckets[key] = {{success:0, failure:0}};
                    if (e.result === 'failure') buckets[key].failure++;
                    else buckets[key].success++;
                }});
                const data = Object.entries(buckets).map(([k,v]) => ({{t:+k, ...v}})).sort((a,b) => a.t - b.t);

                const x = d3.scaleTime().domain([new Date(minTs*1000), new Date(now*1000)]).range([0, w]);
                const maxY = d3.max(data, d => d.success + d.failure) || 1;
                const y = d3.scaleLinear().domain([0, maxY]).nice().range([h, 0]);

                g.append('g').attr('transform', `translate(0,${{h}})`).call(d3.axisBottom(x).ticks(6).tickFormat(d3.timeFormat('%H:%M')));
                g.append('g').call(d3.axisLeft(y).ticks(5));
                g.append('path').datum(data).attr('fill','#4caf50').attr('fill-opacity',0.6)
                    .attr('d', d3.area().x(d => x(new Date(d.t*1000))).y0(h).y1(d => y(d.success)));
                g.append('path').datum(data).attr('fill','#f44336').attr('fill-opacity',0.6)
                    .attr('d', d3.area().x(d => x(new Date(d.t*1000))).y0(d => y(d.success)).y1(d => y(d.success + d.failure)));

                svg.append('text').attr('x', width/2).attr('y', height - 4).attr('text-anchor','middle').attr('font-size',11).text('Events / minute (last hour)');
            }}

            /* ── Event type donut (bottom-right) ────────────────── */
            function renderTypePie(events) {{
                const container = d3.select('#chart-types');
                const width = container.node().clientWidth;
                const height = container.node().clientHeight;
                const radius = Math.min(width, height) / 2 - 30;

                const svg = container.append('svg').attr('width', width).attr('height', height);
                const g = svg.append('g').attr('transform', `translate(${{width/2}},${{height/2}})`);

                if (events.length === 0) {{
                    g.append('text').attr('text-anchor','middle').text('No events yet');
                    return;
                }}

                const counts = {{}};
                events.forEach(e => {{ counts[e.event] = (counts[e.event]||0) + 1; }});
                const data = Object.entries(counts).map(([k,v]) => ({{key:k, value:v}}));

                const color = d3.scaleOrdinal(d3.schemeTableau10);
                const pie = d3.pie().value(d => d.value).sort(null);
                const arc = d3.arc().innerRadius(radius * 0.4).outerRadius(radius);

                g.selectAll('path').data(pie(data)).enter().append('path')
                    .attr('d', arc).attr('fill', (d,i) => color(i))
                    .attr('stroke', 'var(--background)').attr('stroke-width', 2);

                const labelArc = d3.arc().innerRadius(radius * 0.75).outerRadius(radius * 0.75);
                g.selectAll('text.label').data(pie(data)).enter().append('text')
                    .attr('class','label')
                    .attr('transform', d => `translate(${{labelArc.centroid(d)}})`)
                    .attr('text-anchor','middle').attr('font-size',10)
                    .text(d => d.data.value > 0 ? d.data.key.replace('ldap_','').replace('credentials_','cred_') : '');

                svg.append('text').attr('x', width/2).attr('y', height - 4).attr('text-anchor','middle').attr('font-size',11).text('Event type distribution');
            }}

            /* ── Recent events table ────────────────────────────── */
            function renderTable(events) {{
                const container = d3.select('#audit-table-container');
                const recent = events.slice(-100).reverse();
                if (recent.length === 0) {{
                    container.append('p').text('No audit events recorded yet.');
                    return;
                }}

                container.append('h2').text('Recent Events');
                const table = container.append('table');
                table.append('thead').append('tr').selectAll('th')
                    .data(['Time','Event','Result','Actor','Detail'])
                    .enter().append('th').text(d => d);

                const rows = table.append('tbody').selectAll('tr')
                    .data(recent).enter().append('tr');

                rows.append('td').text(d => new Date(d.ts * 1000).toLocaleString());
                rows.append('td').text(d => d.event);
                rows.append('td').text(d => d.result)
                    .style('color', d => d.result === 'failure' ? 'red' : 'inherit');
                rows.append('td').text(d => d.actor);
                rows.append('td').style('max-width','300px').style('overflow','hidden')
                    .style('text-overflow','ellipsis').style('white-space','nowrap')
                    .text(d => d.detail);
            }}
        }})();
        </script>"#,
        escape(&admin_user),
        stats_html,
        users_table,
        devices_table,
        ldap_summary
    );

    Html(super::views::base_layout("Admin Dashboard", &body)).into_response()
}

/// JSON API: return all audit events so D3 charts can fetch data.
pub async fn admin_audit_api(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let events = state.audit_log.snapshot().await;
    Json(events).into_response()
}

#[derive(Deserialize)]
pub struct SetupForm {
    pub csrf: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct ResetForm {
    pub csrf: Option<String>,
}

fn verify_csrf(cookie: &str, form_csrf: Option<&String>) -> Result<(), Html<String>> {
    let form_csrf =
        form_csrf.ok_or_else(|| Html(layout("Error", "<h1>Missing CSRF token</h1>")))?;
    let cookie_csrf = cookie
        .split(';')
        .filter_map(|part| part.trim().strip_prefix("tsdit_csrf="))
        .next();
    match cookie_csrf {
        Some(val) if val == form_csrf => Ok(()),
        _ => Err(Html(layout("Error", "<h1>Invalid CSRF token</h1>"))),
    }
}

async fn render_profile(state: &AppState, user: &User, csrf_token: Option<&str>) -> String {
    let username = user
        .login_name
        .split('@')
        .next()
        .unwrap_or(&user.login_name);

    let base_dn = &state.config.base_dn;
    let dn = format!("uid={},ou=people,{}", username, base_dn);

    let otp_opt: Option<objects::OtpData> = state.env.begin_ro_txn().ok().and_then(|txn| {
        txn.get(state.otp_db, &dn.as_bytes())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<objects::OtpData>(bytes).ok())
    });

    let is_configured = otp_opt
        .as_ref()
        .map(|o| o.password_hmac.is_some() && o.totp_secret.is_some())
        .unwrap_or(false);

    let csrf = csrf_token.unwrap_or("");

    let body = if is_configured {
        format!(
            r#"<p>Your password and TOTP are configured for LDAP authentication.</p>
            <p>When logging in to LDAP-bound devices, enter your password and 6-digit TOTP code separated by <code>::</code></p>
            <p>For example: <code>mypassword::123456</code></p>
            <form action="/credentials/reset" method="post" style="margin-top: 1rem;" onsubmit="return confirm('This will remove your current password and TOTP. You will need to set them up again.')">
                <input type="hidden" name="csrf" value="{}">
                <button type="submit">Reset Credentials</button>
            </form>"#,
            csrf
        )
    } else {
        format!(
            r#"<p>Set a password to configure LDAP authentication. A TOTP secret will be generated automatically.</p>
            <form action="/credentials/setup" method="post" style="margin-top: 1rem;">
                <input type="hidden" name="csrf" value="{}">
                <label for="password">Password:</label>
                <input type="password" name="password" id="password" required>
                <button type="submit">Setup Credentials</button>
            </form>"#,
            csrf
        )
    };

    super::views::base_layout(
        &format!(
            "Profile: {}",
            escape(user.display_name.as_deref().unwrap_or(""))
        ),
        &format!(
            r#"
            <header>
                <strong>dit0</strong>
                <a href="/" class="active">Profile</a>
                <a href="/admin">Admin</a>
            </header>
            <div class="main-content">
            <div style="max-width: 600px; margin: 2rem auto; padding: 2rem;">
                <div style="display: flex; align-items: center; margin-bottom: 1rem;">
                    <img src="{}" width="64" height="64" style="border-radius: 50%; margin-right: 1rem;">
                    <div>
                        <h2 style="font-size: 1.5rem; font-weight: bold;">{}</h2>
                        <p>{}</p>
                    </div>
                </div>
                <h3>LDAP Credentials</h3>
                {}
            </div>
            </div>
            "#,
            escape(user.profile_pic_url.as_deref().unwrap_or("")),
            escape(user.display_name.as_deref().unwrap_or("")),
            escape(&format!("uid={},ou=people,{}", username, base_dn)),
            body
        ),
    )
}

pub async fn user(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
) -> impl IntoResponse {
    let email = claims
        .email
        .clone()
        .or(claims.email.clone())
        .unwrap_or_default();

    let ts_users = state.tailscale.list_users().await.unwrap_or_default();
    let user_obj = ts_users
        .into_iter()
        .find(|u| u.login_name == email || u.login_name.starts_with(&email));

    let csrf_token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    if let Some(u) = user_obj {
        let body = render_profile(&state, &u, Some(&csrf_token)).await;
        let set_cookie = format!("tsdit_csrf={}; Path=/; Secure; SameSite=Strict", csrf_token);
        return (
            [
                ("Set-Cookie", set_cookie.as_str()),
                ("Content-Security-Policy", "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'"),
                ("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"),
            ],
            Html(body),
        )
            .into_response();
    }

    (
        [
            ("Content-Security-Policy", "default-src 'self';"),
            ("Strict-Transport-Security", "max-age=63072000"),
            ("Set-Cookie", ""),
        ],
        Html(layout(
            "Error",
            "<h1>User not found</h1><p>Please contact your administrator.</p>",
        )),
    )
        .into_response()
}

#[axum::debug_handler]
pub async fn credentials_setup(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Extension(cookie): Extension<String>,
    Form(form): Form<SetupForm>,
) -> impl IntoResponse {
    if let Err(e) = verify_csrf(&cookie, form.csrf.as_ref()) {
        return e.into_response();
    }

    let email = claims
        .email
        .clone()
        .or(claims.preferred_username.clone())
        .unwrap_or_default();
    let username = email.split('@').next().unwrap_or(&email).to_string();
    let base_dn = &state.config.base_dn;
    let dn = format!("uid={},ou=people,{}", username, base_dn);

    let password_plain = form
        .password
        .as_ref()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if password_plain.is_empty() {
        audit::credentials_rejected(&username, "empty password");
        return Html(layout("Error", "<h1>Password required</h1>")).into_response();
    }

    // Password complexity: minimum 8 characters, at least one uppercase,
    // one lowercase, and one digit.
    if password_plain.len() < 8
        || !password_plain.chars().any(|c| c.is_ascii_uppercase())
        || !password_plain.chars().any(|c| c.is_ascii_lowercase())
        || !password_plain.chars().any(|c| c.is_ascii_digit())
    {
        audit::credentials_rejected(&username, "password too weak");
        return Html(layout(
            "Error",
            "<h1>Password too weak</h1><p>Password must be at least 8 characters and include an uppercase letter, a lowercase letter, and a digit.</p>",
        ))
        .into_response();
    }

    // Check if already configured
    if let Ok(txn) = state.env.begin_ro_txn() {
        if let Ok(bytes) = txn.get(state.otp_db, &dn.as_bytes()) {
            if let Ok(existing) = serde_json::from_slice::<objects::OtpData>(bytes) {
                if existing.password_hmac.is_some() && existing.totp_secret.is_some() {
                    audit::credentials_rejected(&username, "already configured");
                    return Html(layout(
                        "Error",
                        "<h1>Credentials already configured</h1><p>Reset your existing credentials first.</p>",
                    ))
                    .into_response();
                }
            }
        }
    }

    // Hash the password
    let hmac_key = match state.config.otp_hmac_key() {
        Some(k) if !k.is_empty() => k,
        _ => {
            tracing::error!("OTP_HMAC_KEY not configured");
            return Html(layout("Error", "<h1>Server misconfiguration</h1>")).into_response();
        }
    };
    let mut mac: Hmac<Sha256> =
        Hmac::new_from_slice(hmac_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(password_plain.as_bytes());
    let password_hashed = hex::encode(mac.finalize().into_bytes());

    // Generate TOTP secret
    let mut secret_bytes = [0u8; 20];
    rand::thread_rng().fill(&mut secret_bytes);
    let secret_b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let otp_data = objects::OtpData {
        status: "configured".to_string(),
        code: None,
        expiry: None,
        requested_at: now,
        device_info: None,
        totp_secret: Some(secret_b32.clone()),
        password_hmac: Some(password_hashed),
    };

    let val = match serde_json::to_vec(&otp_data) {
        Ok(v) => v,
        Err(_) => return Html(layout("Error", "<h1>Internal error</h1>")).into_response(),
    };

    let mut saved = false;
    if let Ok(mut txn) = state.env.begin_rw_txn() {
        if txn
            .put(
                state.otp_db,
                &dn.as_bytes(),
                &val,
                ::lmdb::WriteFlags::empty(),
            )
            .is_ok()
        {
            if txn.commit().is_ok() {
                saved = true;
            }
        }
    }

    if !saved {
        audit::credentials_rejected(&username, "database write failed");
        return Html(layout("Error", "<h1>Failed to save credentials</h1>")).into_response();
    }

    audit::credentials_setup(&username, &dn);

    // Build QR code
    let otpauth = format!(
        "otpauth://totp/DIT:{}?secret={}&issuer=dit0&period=30&digits=6",
        username, secret_b32
    );
    let qr_data_uri = match QrCode::new(otpauth.as_bytes()) {
        Ok(code) => {
            let svg_str = code.render::<svg::Color>().min_dimensions(200, 200).build();
            let b64 = base64::encode(svg_str.as_bytes());
            format!("data:image/svg+xml;base64,{}", b64)
        }
        Err(_) => String::new(),
    };

    let qr_html = if !qr_data_uri.is_empty() {
        format!(
            r#"<div style="text-align:center; margin: 1rem 0;"><img src="{}" alt="TOTP QR"></div>"#,
            qr_data_uri
        )
    } else {
        String::new()
    };

    // Return with Cache-Control: no-store to prevent browsers/proxies caching
    // the page that contains the plaintext TOTP secret.
    (
        [
            ("Cache-Control", "no-store, no-cache, must-revalidate"),
            ("Pragma", "no-cache"),
        ],
        Html(layout(
            "Credentials Configured",
            &format!(
                r#"
                <div style="max-width: 600px; margin: 2rem auto; padding: 2rem;">
                    <h2>Credentials Configured</h2>
                    <p>Your password has been saved and a TOTP secret has been generated.</p>
                    <p>Scan this QR code in your authenticator app, or enter the secret manually:</p>
                    {}
                    <div style="background: var(--light-gray); padding: 1rem; font-family: monospace; font-size: 1rem; text-align: center; border: 1px solid var(--text); margin: 1rem 0;">{}</div>
                    <p>When logging in via LDAP, enter your password and 6-digit TOTP separated by <code>::</code></p>
                    <p>For example: <code>mypassword::123456</code></p>
                    <a href="/">Back to Profile</a>
                </div>
                "#,
                qr_html, secret_b32
            ),
        )),
    )
        .into_response()
}

#[axum::debug_handler]
pub async fn credentials_reset(
    State(state): State<AppState>,
    Extension(claims): Extension<UserClaims>,
    Extension(cookie): Extension<String>,
    Form(form): Form<ResetForm>,
) -> impl IntoResponse {
    if let Err(e) = verify_csrf(&cookie, form.csrf.as_ref()) {
        return e.into_response();
    }

    let email = claims
        .email
        .clone()
        .or(claims.preferred_username.clone())
        .unwrap_or_default();
    let username = email.split('@').next().unwrap_or(&email).to_string();
    let base_dn = &state.config.base_dn;
    let dn = format!("uid={},ou=people,{}", username, base_dn);

    let mut done = false;
    if let Ok(mut txn) = state.env.begin_rw_txn() {
        if txn.del(state.otp_db, &dn.as_bytes(), None).is_ok() {
            if txn.commit().is_ok() {
                done = true;
            }
        }
    }

    if done {
        audit::credentials_reset(&username, &dn);
        Html(layout(
            "Credentials Reset",
            r#"<div style="max-width: 600px; margin: 2rem auto; padding: 2rem;">
                <h2>Credentials Reset</h2>
                <p>Your password and TOTP have been removed. You can set up new credentials from your profile.</p>
                <a href="/">Back to Profile</a>
            </div>"#,
        ))
        .into_response()
    } else {
        audit::credentials_rejected(&username, "reset failed – database error");
        Html(layout("Error", "<h1>Failed to reset credentials</h1>")).into_response()
    }
}
