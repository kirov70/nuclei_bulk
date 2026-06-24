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
        'info.description': 'Description',
    }
    
    available = [col for col in columns if col in combined.columns]
    df = combined[available].copy()
    df.rename(columns=columns, inplace=True)
    
    if 'Tags' in df.columns:
        df['Tags'] = df['Tags'].apply(lambda x: ', '.join(x) if isinstance(x, list) else str(x))
    
    # Severity ordering
    severity_order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
    df['Severity'] = pd.Categorical(df['Severity'].str.lower(), categories=severity_order, ordered=True)
    
    return df.sort_values(by=['Severity', 'Host'])


def generate_html_report(df: pd.DataFrame, output_file: str = "nuclei_professional_report.html"):
    total = len(df)
    severity_counts = df['Severity'].value_counts()
    
    color_map = {
        'critical': '#d32f2f', 'high': '#f57c00', 'medium': '#fbc02d',
        'low': '#388e3c', 'info': '#0288d1', 'unknown': '#5c6bc0'
    }

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DiscoSec Web Scan Report</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/dataTables.bootstrap5.min.css">
    <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.bootstrap5.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body {{ background-color: #f8f9fa; font-family: 'Segoe UI', system-ui, sans-serif; }}
        .header {{ background: linear-gradient(135deg, #000080, #3498db); color: white; padding: 2rem 0; margin-bottom: 2rem; }}
        .dashboard-card {{ background: white; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); }}
        .severity-card {{ border-radius: 10px; color: white; text-align: center; padding: 1.2rem; transition: transform 0.2s; }}
        .severity-card:hover {{ transform: translateY(-5px); }}
        .table th {{ background-color: #2c3e50; color: white; }}
        .dataTables_wrapper .dt-buttons button {{ margin-right: 8px; }}
    </style>
</head>
<body>
    <div class="header text-center">
        <div class="container">
        <h1><i class="fas fa-shield-alt"></i> DiscoSec Web Vulnerability Scan Report</h1>
            <p class="mb-0">Professional Security Assessment • {datetime.now().strftime("%d %B %Y at %H:%M")}</p>
        </div>
    </div>

    <div class="container-fluid px-4">
        <!-- Dashboard -->
        <div class="dashboard-card p-4 mb-4">
            <h4 class="mb-3"><i class="fas fa-chart-pie"></i> Findings Overview</h4>
            <div class="row g-3">
                <div class="col-md-2">
                    <div class="severity-card" style="background: #343a40;">
                        <h6>Total Findings</h6>
                        <h2 class="mb-0">{total:,}</h2>
                    </div>
                </div>
    """

    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = int(severity_counts.get(sev, 0))
        color = color_map.get(sev, '#6c757d')
        html += f"""
                <div class="col-md-2">
                    <div class="severity-card" style="background: {color};">
                        <h6>{sev.title()}</h6>
                        <h2 class="mb-0">{count}</h2>
                    </div>
                </div>
        """

    html += """
            </div>
        </div>

        <!-- Results Table -->
        <div class="dashboard-card p-4">
            <h4 class="mb-3"><i class="fas fa-table"></i> Detailed Findings</h4>
            <table id="nucleiTable" class="table table-striped table-hover" style="width:100%">
                <thead>
                    <tr>
    """

    for col in df.columns:
        html += f"<th>{col}</th>\n"

    html += """
                    </tr>
                </thead>
                <tbody>
    """

    for _, row in df.iterrows():
        html += "<tr>"
        for col in df.columns:
            val = "" if pd.isna(row[col]) else str(row[col])
            html += f"<td>{val}</td>"
        html += "</tr>\n"

    html += """
                </tbody>
            </table>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.7/js/dataTables.bootstrap5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.bootstrap5.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
    <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.print.min.js"></script>

    <script>
        $(document).ready(function() {
            $('#nucleiTable').DataTable({
                pageLength: 50,
                order: [[2, 'asc']],
                dom: 'Bfrtip',
                buttons: [
                    'copy', 'csv', 'excel', 'pdf', 'print', 'colvis'
                ],
                language: {
                    search: "Search:",
                    lengthMenu: "Show _MENU_ entries"
                }
            });
        });
    </script>
</body>
</html>
    """

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
            generate_html_report(df)
            print("\n🎉 Report ready! Open 'nuclei_professional_report.html' in your browser.")
        except Exception as e:
            print(f"❌ Error: {e}")
