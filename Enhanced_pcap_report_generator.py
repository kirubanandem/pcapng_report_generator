import os
import csv
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import Counter, defaultdict
import concurrent.futures
import pyshark
import requests
import matplotlib.pyplot as plt
import base64
from scapy.all import rdpcap, TCP, IP
import sys
import asyncio

# --- Asyncio / version helper --- #

def get_or_create_event_loop():
    """
    Return an event loop in a way that works across Python versions.
    On 3.14+ it never relies on implicit loop creation.
    """
    major, minor = sys.version_info[:2]

    # Older behavior is fine, just ensure a loop exists
    if major < 3 or (major == 3 and minor < 10):
        try:
            return asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop

    # 3.10–3.13: avoid deprecation warning; prefer running loop, else create
    if major == 3 and 10 <= minor <= 13:
        try:
            return asyncio.get_running_loop()
        except RuntimeError:
            try:
                return asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                return loop

    # 3.14+ : get_event_loop() without a loop is an error; always be explicit
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop

# --- Helpers --- #

def sanitize_for_xml(text):
    return ''.join(c for c in text if (
        c == '\t' or c == '\n' or c == '\r' or
        (0x20 <= ord(c) <= 0xD7FF) or
        (0xE000 <= ord(c) <= 0xFFFD) or
        (0x10000 <= ord(c) <= 0x10FFFF)
    ))

def extract_bind_values(decoded_payload):
    binds = {}
    matches = re.findall(r'(:B?\d+)\s*=\s*\'?([^\'\s;]+)', decoded_payload)
    for var, val in matches:
        binds[var.upper()] = val
    return binds

def replace_bind_variables(sql, bind_map):
    for var, val in bind_map.items():
        sql = sql.replace(var, f"'{val}'")
    return sql

def save_xml_sql_queries(sql_list, out_path):
    root = ET.Element("queries")
    for q in sql_list:
        ET.SubElement(root, "query").text = sanitize_for_xml(q)
    tree = ET.ElementTree(root)
    tree.write(out_path, encoding="utf-8", xml_declaration=True)

def geolocate_ip(ip):
    try:
        resp = requests.get(f'https://ipinfo.io/{ip}/json', timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            loc = data.get('loc', 'Unknown')
            org = data.get('org', 'Unknown Org')
            city = data.get('city', '')
            country = data.get('country', '')
            return f"{loc} ({city}, {country}) - {org}"
    except:
        pass
    return "Geolocation not available"

def capture_tls_info(pkt, tls_info):
    if hasattr(pkt, 'ssl') or hasattr(pkt, 'tls'):
        layer = pkt.ssl if hasattr(pkt, 'ssl') else pkt.tls
        try:
            cipher = layer.ciphersuite if hasattr(layer, 'ciphersuite') else ""
            cert_subject = ""
            cert_issuer = ""
            if hasattr(layer, 'certificate'):
                cert_issuer = getattr(layer.certificate, 'issuer', '')
                cert_subject = getattr(layer.certificate, 'subject', '')
            tls_info.append({
                "frame": pkt.number,
                "cipher": cipher,
                "cert_subject": cert_subject,
                "cert_issuer": cert_issuer
            })
        except Exception:
            pass

def plot_protocols_chart(protocol_counts, out_folder):
    try:
        sorted_items = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)
        protocols, counts = zip(*sorted_items)
        top_n = 15
        if len(protocols) > top_n:
            other_sum = sum(counts[top_n:])
            protocols = list(protocols[:top_n]) + ['Other']
            counts = list(counts[:top_n]) + [other_sum]

        plt.figure(figsize=(12, 1 + 0.5 * len(protocols)))
        plt.barh(protocols, counts, color='skyblue')
        plt.xlabel('Count')
        plt.ylabel('Protocol')
        plt.title('Network Protocol Usage Counts')
        plt.tight_layout(pad=2)

        img_path = os.path.join(out_folder, 'protocol_usage.png')
        plt.savefig(img_path)
        plt.close()
        return img_path
    except Exception as e:
        print(f"⚠️ Failed to generate protocol chart: {e}")
        return None

def write_list(path, data):
    with open(path, "w", encoding="utf-8") as f:
        for item in data:
            f.write(item + "\n")

def write_csv(path, rows, headers):
    with open(path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

# --- TCP Stream Reassembly and Decoding --- #

def reconstruct_tcp_streams(pcap_file, out_folder):
    from collections import defaultdict
    print(f"⏳ Starting TCP stream reassembly for '{pcap_file}' using Scapy...")
    packets = rdpcap(pcap_file)

    streams = defaultdict(list)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            key_fwd = (ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport, 0)
            streams[key_fwd].append(pkt)

    summary_lines = []
    for idx, (stream_key, pkts) in enumerate(streams.items(), start=1):
        try:
            pkts_sorted = sorted(pkts, key=lambda p: p[TCP].seq)
        except Exception:
            pkts_sorted = pkts

        byte_stream = b""
        for p in pkts_sorted:
            if hasattr(p[TCP], 'payload') and bytes(p[TCP].payload):
                byte_stream += bytes(p[TCP].payload)

        src_ip, src_port, dst_ip, dst_port, direction = stream_key
        stream_desc = f"{src_ip}_{src_port}_to_{dst_ip}_{dst_port}_dir{direction}"
        invalid_chars = '<>:"/\\|?*'
        for ch in invalid_chars:
            stream_desc = stream_desc.replace(ch, '_')

        filename = f"tcp_stream_{idx}_{stream_desc}.bin"
        file_path = os.path.join(out_folder, filename)
        with open(file_path, "wb") as outfile:
            outfile.write(byte_stream)
        summary_lines.append(f"{filename}: {len(byte_stream)} bytes from {stream_desc}")

    summary_path = os.path.join(out_folder, 'tcp_streams_summary.txt')
    with open(summary_path, 'w', encoding='utf-8') as f:
        if summary_lines:
            f.write("TCP streams reassembled using Scapy.\n")
            f.write("\n".join(summary_lines))
        else:
            f.write("No TCP streams found or successfully reassembled.\n")
    print(f"✅ TCP stream reassembly done for '{pcap_file}'.")

def decode_tcp_stream_bin_files(report_dir):
    bin_files = [f for f in os.listdir(report_dir) if f.startswith('tcp_stream_') and f.endswith('.bin')]
    if not bin_files:
        print(f"No tcp_stream_*.bin files found in '{report_dir}'")
        return

    for bin_file in bin_files:
        bin_path = os.path.join(report_dir, bin_file)
        txt_path = os.path.join(report_dir, bin_file[:-4] + '.txt')
        try:
            with open(bin_path, 'rb') as f:
                data = f.read()
            text = data.decode('utf-8', errors='replace')
            with open(txt_path, 'w', encoding='utf-8') as f:
                f.write(text)
            print(f"Decoded {bin_file} -> {txt_path}")
        except Exception as e:
            print(f"Failed to decode {bin_file}: {e}")

def decode_all_tcp_streams_in_reports(root_reports_dir="pcap_reports"):
    if not os.path.isdir(root_reports_dir):
        print(f"Reports root directory '{root_reports_dir}' does not exist.")
        return

    subfolders = [os.path.join(root_reports_dir, name) for name in os.listdir(root_reports_dir)
                  if os.path.isdir(os.path.join(root_reports_dir, name))]
    if not subfolders:
        print(f"No subfolders found inside '{root_reports_dir}'")
        return

    print(f"Processing TCP stream decoding in {len(subfolders)} report directories under '{root_reports_dir}':")
    for subfolder in subfolders:
        print(f"\n🔄 Decoding TCP streams in report folder: {subfolder}")
        decode_tcp_stream_bin_files(subfolder)

# --- HTTP File Extraction --- #

def extract_http_files(cap, out_folder):
    import re
    file_counter = 0
    file_dir = os.path.join(out_folder, 'extracted_files')
    os.makedirs(file_dir, exist_ok=True)

    safe_filename_regex = re.compile(r'[\\/*?:"<>|]')  # to sanitize filenames

    file_data_cache = {}

    for pkt in cap:
        try:
            if 'HTTP' in pkt:
                # Only HTTP Response packets
                if hasattr(pkt.http, 'response_code'):
                    # Get content-type and content-disposition headers if any
                    content_type = ''
                    content_disposition = ''
                    # Headers extraction may vary; use pyshark field access
                    for field in pkt.http._all_fields:
                        if field.showname_key.lower() == 'content-type':
                            content_type = field.showname_value.lower()
                        elif field.showname_key.lower() == 'content-disposition':
                            content_disposition = field.showname_value

                    if any(x in content_type for x in ['application/', 'image/', 'audio/', 'video/', 'multipart/']):
                        # Determine filename
                        filename = None
                        if content_disposition:
                            m = re.search(r'filename="?([^\";]+)"?', content_disposition)
                            if m:
                                filename = safe_filename_regex.sub('_', m.group(1))
                        if not filename:
                            filename = f"extracted_file_{file_counter}"

                        tcp_stream = getattr(pkt.tcp, 'stream', None)
                        if tcp_stream is None:
                            tcp_stream = f"nosid_{file_counter}"

                        if tcp_stream not in file_data_cache:
                            file_data_cache[tcp_stream] = {'name': filename, 'data': b''}

                        if hasattr(pkt.tcp, 'payload'):
                            try:
                                raw = pkt.tcp.payload.replace(":", "")
                                payload_bytes = bytes.fromhex(raw)
                                file_data_cache[tcp_stream]['data'] += payload_bytes
                            except Exception:
                                pass

                        file_counter += 1
        except Exception:
            continue

    saved_files = []
    for stream_id, file_info in file_data_cache.items():
        filename = file_info['name']
        full_path = os.path.join(file_dir, filename)
        base, ext = os.path.splitext(full_path)
        suffix = 1
        while os.path.exists(full_path):
            full_path = f"{base}_{suffix}{ext}"
            suffix += 1

        try:
            with open(full_path, 'wb') as f:
                f.write(file_info['data'])
            saved_files.append(full_path)
        except Exception as e:
            print(f"Failed to save extracted file {filename}: {e}")

    print(f"Extracted and saved {len(saved_files)} files to {file_dir}")
    return saved_files

# --- HTML Dashboard --- #

def generate_html_dashboard(base_name, protocol_counts,
                            ip_counter, suspicious_auth_ips,
                            protocol_chart_path,
                            out_folder,
                            tls_info):
    import html

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def read_file_content(filename):
        path = os.path.join(out_folder, filename)
        if not os.path.isfile(path):
            return f"(File {filename} not found)"
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    sql_queries_txt = html.escape(read_file_content("sql_queries.txt"))
    sql_resolved_txt = html.escape(read_file_content("sql_queries_resolved.txt"))
    auth_activity_txt = html.escape(read_file_content("auth_activity.txt"))
    license_activity_txt = html.escape(read_file_content("license_activity.txt"))
    dns_queries_txt = html.escape(read_file_content("dns_queries.txt"))

    top_ips_csv = read_file_content("top_ips.csv")

    def csv_to_html_table(csv_text):
        lines = csv_text.strip().splitlines()
        if not lines:
            return "<p>No data</p>"
        headers = lines[0].split(",")
        rows = [line.split(",") for line in lines[1:]]
        html_table = "<table border='1' cellpadding='4' style='border-collapse: collapse; width: 100%; max-width: 900px;'>\n"
        html_table += "<thead><tr>" + "".join(f"<th>{html.escape(h)}</th>" for h in headers) + "</tr></thead>\n<tbody>\n"
        for row in rows:
            html_table += "<tr>" + "".join(f"<td>{html.escape(cell)}</td>" for cell in row) + "</tr>\n"
        html_table += "</tbody></table>"
        return html_table

    top_ips_html_table = csv_to_html_table(top_ips_csv)

    img_base64 = ""
    if protocol_chart_path and os.path.exists(protocol_chart_path):
        with open(protocol_chart_path, "rb") as img_f:
            img_base64 = base64.b64encode(img_f.read()).decode()

    if tls_info:
        tls_html = "<table border='1' cellpadding='3'><tr><th>Frame</th><th>Cipher Suite</th><th>Certificate Subject</th><th>Certificate Issuer</th></tr>"
        for rec in tls_info:
            tls_html += f"<tr><td>{rec['frame']}</td><td>{html.escape(rec['cipher'])}</td>" \
                        f"<td>{html.escape(rec['cert_subject'])}</td><td>{html.escape(rec['cert_issuer'])}</td></tr>"
        tls_html += "</table>"
    else:
        tls_html = "<p>No TLS/SSL data found.</p>"

    dashboard_html = f"""
    <html>
    <head>
        <title>PCAP Analysis Dashboard - {html.escape(base_name)}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #2F4F4F; }}
            table {{ border-collapse: collapse; margin-top: 15px; width: 100%; max-width: 900px; }}
            th, td {{ padding: 6px 10px; border: 1px solid #ccc; }}
            th {{ background-color: #8fbc8f; }}
            tr:nth-child(even) {{ background-color: #e0eee0; }}
            pre {{
                background-color: #f4f4f4;
                border: 1px solid #ddd;
                padding: 10px;
                overflow-x: auto;
                max-height: 400px;
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
            details {{
                margin-bottom: 20px;
                border: 1px solid #ccc;
                padding: 8px;
                border-radius: 5px;
                max-width: 900px;
            }}
            summary {{
                font-weight: bold;
                cursor: pointer;
            }}
        </style>
    </head>
    <body>
        <h1>PCAP Analysis Dashboard - {html.escape(base_name)}</h1>
        <p><em>Generated on {timestamp}</em></p>

        <h2>Protocol Usage Summary</h2>
        <img src="data:image/png;base64,{img_base64}" alt="Protocol Usage Chart" style="max-width:700px;border:1px solid #ccc;">
        <table>
            <tr><th>Protocol</th><th>Count</th></tr>
            {"".join(f"<tr><td>{html.escape(proto)}</td><td>{count}</td></tr>" for proto, count in protocol_counts.items())}
        </table>

        <h2>Top IP Addresses</h2>
        {top_ips_html_table}

        <h2>Suspicious Authentication Attempts</h2>
        <table>
            <tr><th>IP Address</th><th>Count</th></tr>
            {"".join(f"<tr><td>{ip}</td><td>{cnt}</td></tr>" for ip, cnt in suspicious_auth_ips.items()) or '<tr><td colspan="2">No suspicious auth patterns detected</td></tr>'}
        </table>

        <h2>TLS/SSL Summary</h2>
        {tls_html}

        <details>
            <summary>View SQL Queries (Raw)</summary>
            <pre>{sql_queries_txt}</pre>
        </details>

        <details>
            <summary>View SQL Queries (Resolved with Bind Variables)</summary>
            <pre>{sql_resolved_txt}</pre>
        </details>

        <details>
            <summary>View Authentication Activity Logs</summary>
            <pre>{auth_activity_txt}</pre>
        </details>

        <details>
            <summary>View License Server Activity</summary>
            <pre>{license_activity_txt}</pre>
        </details>

        <details>
            <summary>View DNS Queries</summary>
            <pre>{dns_queries_txt}</pre>
        </details>

    </body>
    </html>
    """

    dashboard_path = os.path.join(out_folder, "dashboard.html")
    with open(dashboard_path, "w", encoding="utf-8") as f:
        f.write(dashboard_html)

# --- Core Analysis --- #

def analyze_pcap(input_file, out_root, filter_ip=None, filter_proto=None):
    # ensure a loop for this thread and pass it explicitly to pyshark
    loop = get_or_create_event_loop()
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    out_folder = os.path.join(out_root, base_name)
    os.makedirs(out_folder, exist_ok=True)
    print(f"\n🔍 Processing '{input_file}'...")

    # Pyshark live FileCapture for analysis
    cap = pyshark.FileCapture(
        input_file,
        use_json=True,
        include_raw=True,
        keep_packets=False,
        eventloop=loop,
    )

    protocol_counts = Counter()
    ip_counter = Counter()
    dns_queries, sql_queries, mssql_queries = [], [], []
    sql_queries_resolved = []
    bind_variable_map, http_logs = [], []
    license_activity, redis_activity = [], []
    auth_activity = []
    auth_grouped_by_ip = defaultdict(list)
    redis_auth_xref = defaultdict(list)
    oracle_auth_xref = defaultdict(list)
    suspicious_auth_ips = defaultdict(int)
    tls_info = []

    bind_pattern = re.compile(r"(:B?\d+)")
    license_keywords = ["LICENSE", "CHECKOUT", "VALIDATE", "ACTIVATION", "DENIED", "TRIAL", "EVALUATION"]
    auth_keywords = ["AUTH", "LOGIN", "PASSWORD", "TOKEN", "SESSION", "UNAUTHORIZED", "DENIED", "INVALID", "FAILED", "403", "401"]
    license_ports = set(str(p) for p in list(range(27000, 27010)) + [5053, 2080, 6001])
    redis_ports = {"6379"}
    oracle_ports = {"1521"}
    mssql_ports = {"1433"}

    last_bind_map = {}

    try:
        for pkt in cap:
            try:
                proto = pkt.highest_layer
                if filter_proto and proto.lower() != filter_proto.lower():
                    continue

                protocol_counts[proto] += 1

                if hasattr(pkt, 'ip'):
                    ip_src, ip_dst = pkt.ip.src, pkt.ip.dst
                    if filter_ip and filter_ip not in (ip_src, ip_dst):
                        continue
                    ip_counter[ip_src] += 1
                    ip_counter[ip_dst] += 1
                else:
                    continue

                capture_tls_info(pkt, tls_info)

                # DNS Queries
                if 'DNS' in proto and hasattr(pkt, 'dns') and hasattr(pkt.dns, 'qry_name'):
                    dns_queries.append(pkt.dns.qry_name)

                # TCP Layer payload parsing for SQL + license + redis + auth events
                if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload'):
                    raw = pkt.tcp.payload.replace(":", "")
                    try:
                        decoded = bytes.fromhex(raw).decode('utf-8', errors='ignore')
                        cleaned = ''.join(c for c in decoded if c.isprintable()).strip()
                        if not cleaned:
                            continue
                        upper = cleaned.upper()
                        sport = pkt.tcp.srcport if hasattr(pkt.tcp, 'srcport') else ""
                        dport = pkt.tcp.dstport if hasattr(pkt.tcp, 'dstport') else ""

                        # SQL detection
                        if any(k in upper for k in ["SELECT", "UPDATE", "DELETE", "INSERT"]):
                            sql_queries.append(cleaned)
                            found = bind_pattern.findall(cleaned)
                            if found:
                                bind_variable_map.append(f"{cleaned} --> {', '.join(found)}")
                            resolved = replace_bind_variables(cleaned, last_bind_map)
                            sql_queries_resolved.append(resolved)

                        # MSSQL query logging
                        if sport in mssql_ports or dport in mssql_ports:
                            mssql_queries.append(f"{ip_src} -> {ip_dst} : {cleaned}")

                        # Bind variable extraction for next replacements
                        new_binds = extract_bind_values(decoded)
                        if new_binds:
                            last_bind_map.update(new_binds)

                        # License server activity
                        if sport in license_ports or dport in license_ports:
                            if any(k in upper for k in license_keywords):
                                license_activity.append(f"{ip_src} -> {ip_dst} : {cleaned}")

                        # Redis activity commands
                        if sport in redis_ports or dport in redis_ports:
                            if any(cmd in upper for cmd in ["AUTH", "INFO", "MODULE", "LICENSE"]):
                                redis_activity.append(f"{ip_src} -> {ip_dst} : {cleaned}")

                        # Authentication related activity
                        if any(auth in upper for auth in auth_keywords):
                            entry = f"{ip_src} -> {ip_dst} : {cleaned}"
                            auth_activity.append(entry)
                            auth_grouped_by_ip[ip_src].append(entry)

                            if sport in redis_ports or dport in redis_ports:
                                redis_auth_xref[ip_src].append(entry)

                            if sport in oracle_ports or dport in oracle_ports:
                                oracle_auth_xref[ip_src].append(entry)

                            if any(err in upper for err in ["DENIED", "INVALID", "FAILED", "401", "403"]):
                                suspicious_auth_ips[ip_src] += 1

                    except Exception:
                        continue

                # HTTP URIs
                if 'HTTP' in proto and hasattr(pkt, 'http') and hasattr(pkt.http, 'request_uri'):
                    http_logs.append(pkt.http.request_uri)

            except Exception:
                continue

        # After collection, extract HTTP files from the entire capture
        files_saved = extract_http_files(cap, out_folder)

    finally:
        cap.close()

    # Deduplicate queries
    sql_queries = list(dict.fromkeys(sql_queries))
    sql_queries_resolved = list(dict.fromkeys(sql_queries_resolved))
    split_sql = [s.strip() + ';' for q in sql_queries for s in q.split(';') if s.strip()]

    # Write output files
    write_csv(os.path.join(out_folder, "protocol_summary.csv"), protocol_counts.items(), ["Protocol", "Count"])
    write_csv(os.path.join(out_folder, "top_ips.csv"), ip_counter.items(), ["IP Address", "Count"])
    write_list(os.path.join(out_folder, "dns_queries.txt"), dns_queries)
    write_list(os.path.join(out_folder, "sql_queries.txt"), sql_queries)
    write_list(os.path.join(out_folder, "sql_queries_resolved.txt"), sql_queries_resolved)
    save_xml_sql_queries(sql_queries_resolved, os.path.join(out_folder, "sql_queries.xml"))
    write_list(os.path.join(out_folder, "oracle_statements.sql"), split_sql)
    write_list(os.path.join(out_folder, "mssql_queries.txt"), mssql_queries)
    write_list(os.path.join(out_folder, "sql_bind_variables.txt"), bind_variable_map)
    write_list(os.path.join(out_folder, "http_uris.txt"), http_logs)
    write_list(os.path.join(out_folder, "license_activity.txt"), license_activity)
    write_list(os.path.join(out_folder, "redis_activity.txt"), redis_activity)
    write_list(os.path.join(out_folder, "auth_activity.txt"), auth_activity)

    with open(os.path.join(out_folder, "auth_activity_grouped_by_ip.txt"), "w", encoding="utf-8") as f:
        for ip, logs in auth_grouped_by_ip.items():
            f.write(f"--- {ip} ---\n")
            f.writelines(l + "\n" for l in logs)
            f.write("\n")

    with open(os.path.join(out_folder, "auth_activity_redis.txt"), "w", encoding="utf-8") as f:
        for ip, logs in redis_auth_xref.items():
            f.write(f"--- Redis Auth from {ip} ---\n")
            f.writelines(l + "\n" for l in logs)
            f.write("\n")

    with open(os.path.join(out_folder, "auth_activity_oracle.txt"), "w", encoding="utf-8") as f:
        for ip, logs in oracle_auth_xref.items():
            f.write(f"--- Oracle Auth from {ip} ---\n")
            f.writelines(l + "\n" for l in logs)
            f.write("\n")

    write_csv(os.path.join(out_folder, "auth_suspicious_ips.txt"), suspicious_auth_ips.items(), ["IP", "Suspicious Auth Count"])

    protocol_chart_path = plot_protocols_chart(protocol_counts, out_folder)

    reconstruct_tcp_streams(input_file, out_folder)

    generate_html_dashboard(base_name, protocol_counts, ip_counter, suspicious_auth_ips, protocol_chart_path, out_folder, tls_info)

    print(f"✅ Finished processing '{input_file}'. Reports saved to '{out_folder}'. HTTP files saved: {len(files_saved)}")

# Wrapper so each worker thread gets its own loop

def analyze_pcap_with_loop(input_file, out_root, filter_ip=None, filter_proto=None):
    get_or_create_event_loop()
    return analyze_pcap(input_file, out_root, filter_ip, filter_proto)

# --- Main --- #

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Enhanced PCAPNG Analysis and Reporting Tool with File Extraction")
    parser.add_argument('-d', '--directory', type=str,
                        default='.', help='Directory containing .pcapng files (default=current)')
    parser.add_argument('--filter_ip', type=str, default=None,
                        help='Analyze packets only involving this IP address')
    parser.add_argument('--filter_proto', type=str, default=None,
                        help='Analyze packets only of this protocol (e.g. HTTP, DNS)')
    parser.add_argument('-p', '--parallel', action='store_true',
                        help='Process multiple pcapng files in parallel')
    args = parser.parse_args()

    pcap_files = [os.path.join(args.directory, f)
                  for f in os.listdir(args.directory)
                  if f.lower().endswith('.pcapng')]

    if not pcap_files:
        print("❌ No .pcapng files found in the specified directory.")
        return

    print(f"📦 Found {len(pcap_files)} PCAPNG file(s): {', '.join(os.path.basename(f) for f in pcap_files)}")

    out_root = os.path.join(args.directory, "pcap_reports")
    os.makedirs(out_root, exist_ok=True)

    if args.parallel and len(pcap_files) > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(analyze_pcap_with_loop, f, out_root, args.filter_ip, args.filter_proto)
                for f in pcap_files
            ]
            for future in concurrent.futures.as_completed(futures):
                future.result()
    else:
        # ensure a loop in main thread as well
        get_or_create_event_loop()
        for f in pcap_files:
            analyze_pcap(f, out_root, args.filter_ip, args.filter_proto)

    print("\n✅ All PCAPNG files processed. Starting TCP stream decoding...")

    decode_all_tcp_streams_in_reports(out_root)

    print("\n🎉 All TCP stream .bin files decoded into readable text files.")

if __name__ == "__main__":
    main()
