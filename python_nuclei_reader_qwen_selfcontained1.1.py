import pandas as pd
from pathlib import Path
from datetime import datetime
import glob

def load_nuclei_jsonl(file_paths) -> pd.DataFrame:
    """Load and combine multiple Nuclei JSONL files"""
    if isinstance(file_paths, str):
        file_paths = [file_paths]
    
    all_dfs = []
    for file_path in file_paths:
        path = Path(file_path)
        if not path.exists():
            print(f"⚠️  File not found: {path.name}")
            continue
        try:
            df = pd.read_json(path, lines=True)
            if 'info' in df.columns:
                info_df = pd.json_normalize(df['info'])
                info_df.columns = [f"info.{col}" for col in info_df.columns]
                df = pd.concat([df.drop(columns=['info']), info_df], axis=1)
            
            df['source_file'] = path.name
            all_dfs.append(df)
            print(f"✓ Loaded {len(df):,} findings from {path.name}")
        except Exception as e:
            print(f"❌ Error loading {path.name}: {e}")

    if not all_dfs:
        raise ValueError("No files were loaded successfully.")
    
    combined = pd.concat(all_dfs, ignore_index=True)
    
    # Column mapping
    columns = {
        'template-id': 'Template',
        'info.name': 'Name',
        'info.severity': 'Severity',
        'info.tags': 'Tags',
        'matched-at': 'Matched At',
        'host': 'Host',
        'ip': 'IP',
        'port': 'Port',
        'timestamp': 'Timestamp',
        'info.description': 'Description',
        'source_file': 'Source File'
    }
    
    available = [col for col in columns if col in combined.columns]
    df = combined[available].copy()
    df.rename(columns=columns, inplace=True)
    
    if 'Tags' in df.columns:
        df['Tags'] = df['Tags'].apply(lambda x: ', '.join(x) if isinstance(x, list) else str(x))
    
    # Severity ordering
    severity_order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
    df['Severity'] = pd.Categorical(df['Severity'].str.lower(), categories=severity_order, ordered=True)
    
    df = df.sort_values(by=['Severity', 'Host'])

    # Deduplicate: same template + matched-at URL is the same finding
    dedup_cols = [c for c in ['Template', 'Matched At', 'Severity'] if c in df.columns]
    before = len(df)
    df = df.drop_duplicates(subset=dedup_cols, keep='first')
    removed = before - len(df)
    if removed:
        print(f"🔁 Removed {removed:,} duplicate finding(s) ({before:,} → {len(df):,})")

    return df


def generate_html_report(df: pd.DataFrame, output_file: str = "nuclei_professional_report.html"):  # noqa
    total = len(df)
    severity_counts = df['Severity'].value_counts()

    sev_config = {
        'critical': {'color': '#ff4d4d', 'bg': 'rgba(255,77,77,0.12)', 'border': 'rgba(255,77,77,0.4)'},
        'high':     {'color': '#ff8c42', 'bg': 'rgba(255,140,66,0.12)', 'border': 'rgba(255,140,66,0.4)'},
        'medium':   {'color': '#f5c518', 'bg': 'rgba(245,197,24,0.12)', 'border': 'rgba(245,197,24,0.4)'},
        'low':      {'color': '#4caf82', 'bg': 'rgba(76,175,130,0.12)', 'border': 'rgba(76,175,130,0.4)'},
        'info':     {'color': '#5ba3f5', 'bg': 'rgba(91,163,245,0.12)', 'border': 'rgba(91,163,245,0.4)'},
        'unknown':  {'color': '#9e9e9e', 'bg': 'rgba(158,158,158,0.12)', 'border': 'rgba(158,158,158,0.4)'},
    }

    # Build severity badge CSS
    badge_css = ""
    for sev, cfg in sev_config.items():
        badge_css += f"""
        .sev-{sev} {{ color:{cfg['color']};background:{cfg['bg']};border:1px solid {cfg['border']};
            padding:3px 10px;border-radius:4px;font-size:0.72rem;font-weight:700;
            letter-spacing:0.08em;text-transform:uppercase;font-family:'JetBrains Mono','Courier New',monospace;white-space:nowrap; }}
        .stat-card-{sev} {{ border-left:3px solid {cfg['color']}; }}
        .filter-btn[data-sev="{sev}"] {{ border-color:{cfg['border']};color:{cfg['color']}; }}
        .filter-btn[data-sev="{sev}"].active {{ background:{cfg['bg']}; }}
        """

    # Escape and build table data (Python list → JS JSON for vanilla table)
    def escape_val(val):
        if pd.isna(val):
            return ""
        return str(val).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", "")

    columns = list(df.columns)
    mono_cols = {'Host', 'Matched At', 'IP', 'Port'}

    # Build JS data array
    js_rows = []
    for _, row in df.iterrows():
        cells = []
        for col in columns:
            cells.append(escape_val(row[col]))
        js_rows.append(cells)

    import json
    js_data = json.dumps(js_rows)
    js_cols = json.dumps(columns)
    js_mono = json.dumps(list(mono_cols))
    sev_col_idx = columns.index('Severity') if 'Severity' in columns else -1

    # Stat cards
    stat_cards = f"""
        <div class="stat-card stat-card-total">
            <div class="stat-label">Total Findings</div>
            <div class="stat-value">{total:,}</div>
        </div>
    """
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = int(severity_counts.get(sev, 0))
        stat_cards += f"""
        <div class="stat-card stat-card-{sev}">
            <div class="stat-label">{sev.title()}</div>
            <div class="stat-value" style="color:{sev_config[sev]['color']};">{count:,}</div>
        </div>
        """

    # Filter buttons
    filter_buttons = '<button class="filter-btn active" data-sev="all">All</button>'
    for sev in ['critical', 'high', 'medium', 'low', 'info', 'unknown']:
        count = int(severity_counts.get(sev, 0))
        if count > 0:
            filter_buttons += f'<button class="filter-btn" data-sev="{sev}">{sev.title()} <span class="filter-count">{count}</span></button>'

    generated_at = datetime.now().strftime("%d %B %Y at %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DiscoSec — Vulnerability Scan Report</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

        :root {{
            --bg:        #0d1117;
            --surface:   #161b22;
            --surface2:  #1c2230;
            --border:    rgba(255,255,255,0.07);
            --text:      #e6edf3;
            --text-muted:#7d8590;
            --accent:    #2d7ff9;
            --font-body: 'Inter', system-ui, sans-serif;
            --font-mono: 'JetBrains Mono', 'Courier New', monospace;
        }}

        body {{
            background: var(--bg);
            color: var(--text);
            font-family: var(--font-body);
            font-size: 14px;
            line-height: 1.6;
            min-height: 100vh;
        }}

        /* ── Header ── */
        .site-header {{
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 0 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            height: 60px;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        .logo-area {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .logo-icon {{
            width: 32px; height: 32px;
            background: var(--accent);
            border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            font-size: 16px;
        }}
        .logo-text {{
            font-weight: 700;
            font-size: 1rem;
            letter-spacing: -0.01em;
        }}
        .logo-text span {{ color: var(--accent); }}
        .header-meta {{
            font-size: 0.75rem;
            color: var(--text-muted);
            font-family: var(--font-mono);
        }}

        /* ── Hero / title bar ── */
        .report-hero {{
            padding: 2.5rem 2rem 2rem;
            border-bottom: 1px solid var(--border);
            background: linear-gradient(180deg, rgba(45,127,249,0.05) 0%, transparent 100%);
        }}
        .report-hero h1 {{
            font-size: 1.6rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 0.25rem;
        }}
        .report-hero p {{
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
        .report-hero img {{
            display: block;
            margin-bottom: 1rem;
            max-height: 52px;
            width: auto;
            filter: brightness(0) invert(1);
            opacity: 0.85;
        }}

        /* ── Stat cards ── */
        .stats-bar {{
            display: flex;
            gap: 1rem;
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border);
            flex-wrap: wrap;
        }}
        .stat-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.9rem 1.3rem;
            min-width: 110px;
            flex: 1;
        }}
        .stat-card-total {{ border-left: 3px solid var(--accent); }}
        .stat-label {{
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-muted);
            margin-bottom: 0.3rem;
        }}
        .stat-value {{
            font-size: 1.7rem;
            font-weight: 700;
            font-family: var(--font-mono);
            line-height: 1;
        }}
        {badge_css}

        /* ── Filter bar ── */
        .filter-bar {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 1rem 2rem;
            border-bottom: 1px solid var(--border);
            background: var(--surface);
            flex-wrap: wrap;
        }}
        .filter-label {{
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text-muted);
            margin-right: 0.25rem;
        }}
        .filter-btn {{
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-muted);
            border-radius: 5px;
            padding: 4px 12px;
            font-size: 0.75rem;
            font-family: var(--font-body);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
        }}
        .filter-btn:hover {{ border-color: rgba(255,255,255,0.2); color: var(--text); }}
        .filter-btn.active {{ color: var(--text) !important; }}
        .filter-btn[data-sev="all"].active {{ background: rgba(45,127,249,0.15); border-color: rgba(45,127,249,0.4); color: var(--accent) !important; }}
        .filter-count {{
            font-family: var(--font-mono);
            font-size: 0.7rem;
            opacity: 0.8;
        }}

        /* ── Table container ── */
        .table-section {{
            padding: 1.5rem 2rem 3rem;
        }}
        .table-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
            flex-wrap: wrap;
            gap: 0.75rem;
        }}
        .table-title {{
            font-size: 0.85rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.07em;
        }}
        #finding-count {{
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: var(--text-muted);
        }}

        /* ── Table ── */
        #tbl-wrap {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }}
        #nucleiTable {{
            width: 100%;
            border-collapse: collapse;
        }}
        #nucleiTable thead th {{
            background: var(--surface2);
            color: var(--text-muted);
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            font-weight: 600;
            padding: 10px 14px;
            white-space: nowrap;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
            user-select: none;
            position: relative;
        }}
        #nucleiTable thead th:hover {{ color: var(--text); }}
        #nucleiTable thead th .sort-icon {{
            margin-left: 5px;
            opacity: 0.35;
            font-style: normal;
            font-size: 0.7rem;
        }}
        #nucleiTable thead th.sort-asc .sort-icon,
        #nucleiTable thead th.sort-desc .sort-icon {{
            opacity: 1;
            color: var(--accent);
        }}
        #nucleiTable tbody td {{
            padding: 9px 14px;
            font-size: 0.82rem;
            color: var(--text);
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
            max-width: 320px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        #nucleiTable tbody tr:last-child td {{ border-bottom: none; }}
        #nucleiTable tbody tr:hover td {{ background: rgba(255,255,255,0.03); }}

        code.mono-cell {{
            font-family: var(--font-mono);
            font-size: 0.78rem;
            color: #a8d5ff;
            background: rgba(91,163,245,0.08);
            padding: 1px 6px;
            border-radius: 3px;
        }}

        /* ── Table controls ── */
        .tbl-controls {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }}
        .tbl-left, .tbl-right {{ display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }}

        #search-box {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text);
            border-radius: 6px;
            padding: 6px 12px;
            font-size: 0.82rem;
            font-family: var(--font-body);
            outline: none;
            width: 240px;
            transition: border-color 0.15s;
        }}
        #search-box:focus {{ border-color: rgba(45,127,249,0.5); }}
        #search-box::placeholder {{ color: var(--text-muted); }}

        .export-btn {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-muted);
            border-radius: 5px;
            padding: 6px 14px;
            font-size: 0.75rem;
            font-family: var(--font-body);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
        }}
        .export-btn:hover {{ border-color: rgba(255,255,255,0.25); color: var(--text); }}

        #page-size-select {{
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text-muted);
            border-radius: 5px;
            padding: 5px 8px;
            font-size: 0.75rem;
            font-family: var(--font-body);
            cursor: pointer;
        }}

        /* ── Pagination ── */
        .pagination {{
            display: flex;
            align-items: center;
            gap: 0.35rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }}
        .pg-btn {{
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-muted);
            border-radius: 5px;
            padding: 4px 10px;
            font-size: 0.75rem;
            font-family: var(--font-mono);
            cursor: pointer;
            transition: all 0.15s;
        }}
        .pg-btn:hover:not(:disabled) {{ background: var(--surface2); color: var(--text); }}
        .pg-btn.active {{ background: rgba(45,127,249,0.18); border-color: rgba(45,127,249,0.4); color: var(--accent); }}
        .pg-btn:disabled {{ opacity: 0.3; cursor: not-allowed; }}
        #pg-info {{ font-size: 0.72rem; color: var(--text-muted); font-family: var(--font-mono); margin-left: 0.5rem; }}

        /* ── Footer ── */
        .site-footer {{
            padding: 1.5rem 2rem;
            border-top: 1px solid var(--border);
            background: var(--surface);
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.72rem;
            color: var(--text-muted);
        }}
    </style>
</head>
<body>

<header class="site-header">
    <div class="logo-area">
        <div class="logo-icon">&#9673;</div>
        <div class="logo-text">Disco<span>Sec</span></div>
    </div>
    <div class="header-meta">Generated {generated_at}</div>
</header>

<div class="report-hero">
    <img src="https://discoveryseniorliving.com/wp-content/uploads/2025/09/Discovery-Senior-Living-full.png" alt="Discovery Senior Living">
    <h1>Web Vulnerability Scan Report</h1>
    <p>Security Assessment &nbsp;&#183;&nbsp; {generated_at}</p>
</div>

<div class="stats-bar">
    {stat_cards}
</div>

<div class="filter-bar">
    <span class="filter-label">Filter by severity</span>
    {filter_buttons}
</div>

<div class="table-section">
    <div class="tbl-controls">
        <div class="tbl-left">
            <input id="search-box" type="search" placeholder="Search all columns…">
            <span id="finding-count" style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted);">{total:,} results</span>
        </div>
        <div class="tbl-right">
            <button class="export-btn" id="btn-csv">&#8615; Export CSV</button>
            <button class="export-btn" id="btn-pdf">&#8615; Export PDF</button>
            <select id="page-size-select">
                <option value="25">25 / page</option>
                <option value="50" selected>50 / page</option>
                <option value="100">100 / page</option>
                <option value="999999">All</option>
            </select>
        </div>
    </div>

    <div id="tbl-wrap">
        <table id="nucleiTable">
            <thead><tr id="tbl-head"></tr></thead>
            <tbody id="tbl-body"></tbody>
        </table>
    </div>
    <div class="pagination" id="pagination"></div>
</div>

<footer class="site-footer">
    <span>DiscoSec &mdash; Internal Security Use Only</span>
    <span>Nuclei Scan Report &nbsp;&#183;&nbsp; {generated_at}</span>
</footer>

<script>
(function() {{
    var COLUMNS = {js_cols};
    var RAW_DATA = {js_data};
    var MONO_COLS = new Set({js_mono});
    var SEV_COL = {sev_col_idx};

    var sortCol = SEV_COL >= 0 ? SEV_COL : 0;
    var sortDir = 1;  // 1=asc, -1=desc
    var currentPage = 1;
    var pageSize = 50;
    var searchTerm = '';
    var sevFilter = 'all';

    var SEV_ORDER = {{'critical':0,'high':1,'medium':2,'low':3,'info':4,'unknown':5,'':6}};

    // Build header
    var headRow = document.getElementById('tbl-head');
    COLUMNS.forEach(function(col, i) {{
        var th = document.createElement('th');
        th.innerHTML = col + '<i class="sort-icon">&#8597;</i>';
        if (i === sortCol) {{
            th.classList.add('sort-asc');
            th.querySelector('.sort-icon').innerHTML = '&#8593;';
        }}
        th.addEventListener('click', function() {{
            if (sortCol === i) {{ sortDir *= -1; }}
            else {{ sortCol = i; sortDir = 1; }}
            document.querySelectorAll('#tbl-head th').forEach(function(t, j) {{
                t.classList.remove('sort-asc','sort-desc');
                t.querySelector('.sort-icon').innerHTML = '&#8597;';
            }});
            th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');
            th.querySelector('.sort-icon').innerHTML = sortDir === 1 ? '&#8593;' : '&#8595;';
            currentPage = 1;
            render();
        }});
        headRow.appendChild(th);
    }});

    function getFiltered() {{
        var term = searchTerm.toLowerCase();
        return RAW_DATA.filter(function(row) {{
            if (sevFilter !== 'all') {{
                var sev = SEV_COL >= 0 ? (row[SEV_COL] || '').toLowerCase() : '';
                if (sev !== sevFilter) return false;
            }}
            if (!term) return true;
            return row.some(function(cell) {{ return (cell||'').toLowerCase().includes(term); }});
        }});
    }}

    function getSorted(data) {{
        return data.slice().sort(function(a, b) {{
            var av = a[sortCol] || '', bv = b[sortCol] || '';
            if (sortCol === SEV_COL) {{
                var ai = SEV_ORDER[av.toLowerCase()] ?? 99;
                var bi = SEV_ORDER[bv.toLowerCase()] ?? 99;
                return (ai - bi) * sortDir;
            }}
            return av.localeCompare(bv, undefined, {{numeric:true}}) * sortDir;
        }});
    }}

    function cellHTML(val, col) {{
        var safe = (val||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        if (col === 'Severity') {{
            var cls = 'sev-' + (val||'unknown').toLowerCase();
            return '<span class="' + cls + '">' + safe + '</span>';
        }}
        if (MONO_COLS.has(col)) return '<code class="mono-cell">' + safe + '</code>';
        return safe;
    }}

    function render() {{
        var filtered = getFiltered();
        var sorted   = getSorted(filtered);
        var total    = sorted.length;
        var pages    = Math.max(1, Math.ceil(total / pageSize));
        currentPage  = Math.min(currentPage, pages);
        var start    = (currentPage - 1) * pageSize;
        var slice    = sorted.slice(start, start + pageSize);

        // Count label
        document.getElementById('finding-count').textContent =
            total.toLocaleString() + ' result' + (total !== 1 ? 's' : '');

        // Rows
        var body = document.getElementById('tbl-body');
        body.innerHTML = '';
        slice.forEach(function(row) {{
            var tr = document.createElement('tr');
            var sev = SEV_COL >= 0 ? (row[SEV_COL]||'unknown').toLowerCase() : '';
            tr.dataset.severity = sev;
            COLUMNS.forEach(function(col, i) {{
                var td = document.createElement('td');
                td.innerHTML = cellHTML(row[i], col);
                tr.appendChild(td);
            }});
            body.appendChild(tr);
        }});

        // Pagination
        var pg = document.getElementById('pagination');
        pg.innerHTML = '';
        function pgBtn(label, page, disabled, active) {{
            var b = document.createElement('button');
            b.className = 'pg-btn' + (active ? ' active' : '');
            b.textContent = label;
            b.disabled = disabled;
            b.addEventListener('click', function() {{ currentPage = page; render(); }});
            return b;
        }}
        pg.appendChild(pgBtn('‹ Prev', currentPage - 1, currentPage === 1, false));
        var lo = Math.max(1, currentPage - 2), hi = Math.min(pages, currentPage + 2);
        if (lo > 1) {{ pg.appendChild(pgBtn('1', 1, false, false)); if (lo > 2) pg.insertAdjacentHTML('beforeend','<span style="color:var(--text-muted);padding:0 4px">…</span>'); }}
        for (var p = lo; p <= hi; p++) pg.appendChild(pgBtn(p, p, false, p === currentPage));
        if (hi < pages) {{ if (hi < pages-1) pg.insertAdjacentHTML('beforeend','<span style="color:var(--text-muted);padding:0 4px">…</span>'); pg.appendChild(pgBtn(pages, pages, false, false)); }}
        pg.appendChild(pgBtn('Next ›', currentPage + 1, currentPage === pages, false));
        var info = document.createElement('span');
        info.id = 'pg-info';
        info.textContent = 'Page ' + currentPage + ' of ' + pages;
        pg.appendChild(info);
    }}

    // Search
    document.getElementById('search-box').addEventListener('input', function() {{
        searchTerm = this.value; currentPage = 1; render();
    }});

    // Page size
    document.getElementById('page-size-select').addEventListener('change', function() {{
        pageSize = parseInt(this.value); currentPage = 1; render();
    }});

    // Severity filters
    document.querySelectorAll('.filter-btn').forEach(function(btn) {{
        btn.addEventListener('click', function() {{
            document.querySelectorAll('.filter-btn').forEach(function(b) {{ b.classList.remove('active'); }});
            btn.classList.add('active');
            sevFilter = btn.dataset.sev;
            currentPage = 1;
            render();
        }});
    }});

    // CSV export
    document.getElementById('btn-csv').addEventListener('click', function() {{
        var filtered = getSorted(getFiltered());
        var esc = function(v) {{ return '"' + (v||'').replace(/"/g,'""') + '"'; }};
        var lines = [COLUMNS.map(esc).join(',')];
        filtered.forEach(function(row) {{ lines.push(row.map(esc).join(',')); }});
        var blob = new Blob([lines.join('\\n')], {{type:'text/csv'}});
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'nuclei_findings.csv';
        a.click();
    }});

    // PDF export (print-to-PDF via browser)
    document.getElementById('btn-pdf').addEventListener('click', function() {{
        var filtered = getSorted(getFiltered());
        var rows = filtered.map(function(row) {{
            return '<tr>' + row.map(function(v) {{
                return '<td>' + (v||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</td>';
            }}).join('') + '</tr>';
        }}).join('');
        var w = window.open('','_blank');
        w.document.write('<html><head><title>DiscoSec Report</title><style>'
            + 'body{{font-family:sans-serif;font-size:10px;margin:16px}}'
            + 'h2{{margin-bottom:8px}}table{{border-collapse:collapse;width:100%}}'
            + 'th{{background:#1c2230;color:#fff;padding:5px 8px;text-align:left;font-size:9px;text-transform:uppercase}}'
            + 'td{{border-bottom:1px solid #ddd;padding:4px 8px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}'
            + 'tr:nth-child(even){{background:#f8f9fa}}'
            + '</style></head><body>'
            + '<h2>DiscoSec — Vulnerability Scan Report</h2>'
            + '<p style="color:#666;margin-bottom:12px">Generated {generated_at} &nbsp;|&nbsp; ' + filtered.length + ' findings</p>'
            + '<table><thead><tr>' + COLUMNS.map(function(c){{return '<th>'+c+'</th>';}}).join('') + '</tr></thead>'
            + '<tbody>' + rows + '</tbody></table>'
            + '</body></html>');
        w.document.close();
        setTimeout(function(){{ w.print(); }}, 400);
    }});

    render();
}})();
</script>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n✅ Professional HTML report generated: {output_file}")


# =======================
# Main Interface
# =======================

if __name__ == "__main__":
    print("="*70)
    print("🔍 Nuclei JSONL → Professional Interactive Report")
    print("="*70)
    
    mode = input("\nSelect mode:\n1. Single file\n2. Multiple files (comma separated)\n3. All .jsonl files in a folder\nChoice [3]: ").strip() or "3"
    
    files = []
    if mode == "1":
        files = [input("Enter JSONL file path: ").strip()]
    elif mode == "2":
        print("Enter file paths (comma-separated):")
        paths = input().strip()
        files = [p.strip() for p in paths.split(",") if p.strip()]
    else:  # Default: folder
        folder = input("Enter folder path [current folder]: ").strip() or "."
        files = glob.glob(f"{folder}/**/*.jsonl", recursive=True)
        if not files:
            files = glob.glob(f"{folder}/*.jsonl")

    if not files:
        print("❌ No files found.")
    else:
        try:
            df = load_nuclei_jsonl(files)
            print(f"\nTotal findings across all files: {len(df):,}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"nuclei_report_{timestamp}.html"
            generate_html_report(df, output_file)
            print(f"\n🎉 Report ready! Open '{output_file}' in your browser.")
        except Exception as e:
            print(f"❌ Error: {e}")
