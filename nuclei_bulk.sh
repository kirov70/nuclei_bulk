#!/bin/bash
# ================================================
# Nuclei Bulk Scanner + Rich HTML Report
# Fixed: Concurrency vs max-host-error
# ================================================

# Color Codes for Terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================"
echo -e "    Nuclei Bulk Scanner + Rich HTML Report"
echo -e "=======================================${NC}"

read -p "Enter the path to your targets file (e.g. urls.txt): " TARGETS

if [[ ! -f "$TARGETS" ]]; then
    echo -e "${RED}Error: File '$TARGETS' not found!${NC}"
    exit 1
fi

# Get base name for output files
BASE_NAME=$(basename "$TARGETS" | sed 's/\.[^.]*$//')
OUTPUT_DIR="${BASE_NAME}_nuclei_scan_$(date +%Y%m%d_%H%M)"

# Optimized & Safe Settings
CONCURRENCY=40          # Reduced from 50
RATE_LIMIT=180
MAX_HOST_ERROR=50       # Must be >= concurrency
TIMEOUT=15

mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}Input File     : $TARGETS"
echo -e "Output Folder  : $OUTPUT_DIR"
echo -e "Concurrency    : $CONCURRENCY"
echo -e "Max Host Error : $MAX_HOST_ERROR${NC}"
echo -e "${CYAN}=======================================${NC}"

# Run Scans with fixed parameters
echo -e "${YELLOW}[+] Running Critical & High severity scan...${NC}"
nuclei \
  -l "$TARGETS" \
  -severity critical,high \
  -t http/ \
  -tags wordpress,wp,exposure,misconfig,vuln \
  -concurrency "$CONCURRENCY" \
  -rate-limit "$RATE_LIMIT" \
  -max-host-error "$MAX_HOST_ERROR" \
  -timeout "$TIMEOUT" \
  -stats \
  -jsonl \
  -o "$OUTPUT_DIR/${BASE_NAME}_critical_high.json" \
  -markdown "$OUTPUT_DIR/markdown_reports"

echo -e "${YELLOW}[+] Running WordPress-specific scan...${NC}"
nuclei \
  -l "$TARGETS" \
  -tags wordpress,wp \
  -severity critical,high,medium \
  -concurrency 35 \
  -rate-limit 150 \
  -max-host-error 45 \
  -timeout "$TIMEOUT" \
  -jsonl \
  -o "$OUTPUT_DIR/${BASE_NAME}_wordpress.json"

# Count Findings
CRITICAL=$(jq -r 'select(.severity == "critical")' "$OUTPUT_DIR/${BASE_NAME}_critical_high.json" 2>/dev/null | wc -l || echo 0)
HIGH=$(jq -r 'select(.severity == "high")' "$OUTPUT_DIR/${BASE_NAME}_critical_high.json" 2>/dev/null | wc -l || echo 0)
MEDIUM=$(jq -r 'select(.severity == "medium")' "$OUTPUT_DIR/${BASE_NAME}_wordpress.json" 2>/dev/null | wc -l || echo 0)
TOTAL_FINDINGS=$((CRITICAL + HIGH + MEDIUM))

# Generate HTML Report (same as before, shortened for brevity)
cat > "$OUTPUT_DIR/${BASE_NAME}_Nuclei_Report.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nuclei Scan Report - $(basename "$TARGETS")</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f8f9fa; }
        h1 { color: #2c3e50; }
        .container { max-width: 1400px; margin: auto; }
        .summary { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .severity-badge { padding: 6px 14px; border-radius: 20px; font-weight: bold; }
        .critical { background: #c0392b; color: white; }
        .high     { background: #e67e22; color: white; }
        .medium   { background: #f1c40f; color: #222; }
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 4px 12px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
        th { background: #2c3e50; color: white; padding: 14px; cursor: pointer; }
        td { padding: 12px 14px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f8f9fa; }
        button { padding: 10px 20px; background: #27ae60; color: white; border: none; border-radius: 6px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Nuclei Security Scan Report</h1>
        <p><strong>Input File:</strong> $(basename "$TARGETS")</p>
        <p><strong>Generated on:</strong> $(date)</p>
        <p><strong>Total Targets:</strong> $(wc -l < "$TARGETS")</p>

        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <h3>Total Findings: <strong>$TOTAL_FINDINGS</strong></h3>
            <p>
                <span class="severity-badge critical">Critical: $CRITICAL</span> &nbsp;
                <span class="severity-badge high">High: $HIGH</span> &nbsp;
                <span class="severity-badge medium">Medium: $MEDIUM</span>
            </p>
            <button onclick="exportToCSV()">📥 Export to CSV</button>
        </div>

        <h2>🚨 Critical & High Findings</h2>
        <table id="findingsTable">
            <thead>
                <tr>
                    <th onclick="sortTable(0)">Severity</th>
                    <th onclick="sortTable(1)">Host</th>
                    <th onclick="sortTable(2)">Vulnerability</th>
                    <th onclick="sortTable(3)">Description</th>
                    <th onclick="sortTable(4)">CVSS</th>
                </tr>
            </thead>
            <tbody>
EOF

# Populate findings
if [[ -s "$OUTPUT_DIR/${BASE_NAME}_critical_high.json" ]]; then
    jq -r '
        . | "<tr>
            <td><span class=\"severity-badge \(.severity)\">\(.severity | ascii_upcase)</span></td>
            <td>\(.host)</td>
            <td><strong>\(.info.name)</strong></td>
            <td class=\"description\">\(.info.description // "No description available")</td>
            <td>\(.info.classification.cvss_score // "-")</td>
        </tr>"' "$OUTPUT_DIR/${BASE_NAME}_critical_high.json" >> "$OUTPUT_DIR/${BASE_NAME}_Nuclei_Report.html"
else
    echo '<tr><td colspan="5">No findings detected.</td></tr>' >> "$OUTPUT_DIR/${BASE_NAME}_Nuclei_Report.html"
fi

cat >> "$OUTPUT_DIR/${BASE_NAME}_Nuclei_Report.html" << 'EOF'
            </tbody>
        </table>
    </div>

    <script>
        function sortTable(n) { /* Same sorting function as before */ 
            const table = document.getElementById("findingsTable");
            let rows, switching = true, dir = "asc", switchcount = 0;
            while (switching) {
                switching = false;
                rows = table.rows;
                for (let i = 1; i < (rows.length - 1); i++) {
                    let shouldSwitch = false;
                    let x = rows[i].getElementsByTagName("TD")[n];
                    let y = rows[i + 1].getElementsByTagName("TD")[n];
                    if (dir == "asc") {
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) shouldSwitch = true;
                    } else if (dir == "desc") {
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) shouldSwitch = true;
                    }
                }
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                } else if (switchcount == 0 && dir == "asc") {
                    dir = "desc";
                    switching = true;
                }
            }
        }

        function exportToCSV() {
            const table = document.getElementById("findingsTable");
            let csv = "Severity,Host,Vulnerability,Description,CVSS\n";
            for (let i = 1; i < table.rows.length; i++) {
                let row = table.rows[i];
                let cols = row.querySelectorAll("td");
                let rowData = [];
                cols.forEach(col => rowData.push('"' + col.innerText.replace(/,/g, ' ') + '"'));
                csv += rowData.join(",") + "\n";
            }
            const blob = new Blob([csv], { type: 'text/csv' });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob);
            link.download = "nuclei_findings.csv";
            link.click();
        }
    </script>
</body>
</html>
EOF

echo -e "${GREEN}=======================================${NC}"
echo -e "${GREEN}Scan Completed Successfully!${NC}"
echo -e "📁 Report: ${CYAN}$OUTPUT_DIR/${BASE_NAME}_Nuclei_Report.html${NC}"
echo -e "Open with: ${CYAN}xdg-open $OUTPUT_DIR/${BASE_NAME}_Nuclei_Report.html${NC}"
