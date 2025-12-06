import os
import sys
import tempfile
from collections import Counter, defaultdict
from flask import Flask, request, render_template_string

from scapy.all import PcapReader, Raw, TCP, IP

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size

@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template_string(ERROR_TEMPLATE, error_message="File too large. Maximum file size is 500MB."), 413

UPLOAD_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>PCAP Analysis Report Card</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        .upload-form { background: #f5f5f5; padding: 20px; border-radius: 8px; }
        input[type="file"] { margin: 10px 0; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        .status { margin-top: 10px; padding: 10px; border-radius: 4px; display: none; }
        .status.loading { display: block; background: #e3f2fd; color: #1565c0; }
        .status.error { display: block; background: #ffebee; color: #c62828; }
    </style>
</head>
<body>
    <h1>PCAP Analysis Report Card</h1>
    <div class="upload-form">
        <h3>Upload a PCAP File for Analysis</h3>
        <form id="uploadForm">
            <input type="file" id="pcapFile" name="pcap_file" accept=".pcap,.pcapng" required>
            <br><br>
            <button type="submit" id="submitBtn">Analyze PCAP</button>
        </form>
        <div id="status" class="status"></div>
    </div>
    <script>
        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const fileInput = document.getElementById('pcapFile');
            const statusDiv = document.getElementById('status');
            const submitBtn = document.getElementById('submitBtn');
            
            if (!fileInput.files || fileInput.files.length === 0) {
                statusDiv.className = 'status error';
                statusDiv.textContent = 'Please select a PCAP file first.';
                return;
            }
            
            const formData = new FormData();
            formData.append('pcap_file', fileInput.files[0]);
            
            submitBtn.disabled = true;
            statusDiv.className = 'status loading';
            statusDiv.textContent = 'Analyzing PCAP file... Please wait.';
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const html = await response.text();
                document.open();
                document.write(html);
                document.close();
            } catch (error) {
                statusDiv.className = 'status error';
                statusDiv.textContent = 'Error uploading file: ' + error.message;
                submitBtn.disabled = false;
            }
        });
    </script>
</body>
</html>
"""

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>PCAP Analysis Report Card</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 900px; margin: 50px auto; padding: 20px; }
        h1, h2, h3 { color: #333; }
        .report-card { background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .section { margin: 20px 0; padding: 15px; background: white; border-radius: 4px; border-left: 4px solid #007bff; }
        .warning { border-left-color: #dc3545; background: #fff5f5; }
        .success { border-left-color: #28a745; background: #f5fff5; }
        .info { border-left-color: #17a2b8; background: #e8f7f9; }
        .alert { border-left-color: #ff9800; background: #fff8e1; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        .bold-warning { color: #dc3545; font-weight: bold; font-size: 1.1em; }
        .bold-alert { color: #ff9800; font-weight: bold; font-size: 1.1em; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .total-packets { font-size: 1.5em; color: #007bff; font-weight: bold; }
        .narrative { font-size: 1.1em; line-height: 1.6; color: #555; padding: 15px; background: #e3f2fd; border-radius: 8px; margin: 15px 0; border-left: 4px solid #2196f3; }
        .packet-nums { font-family: monospace; font-size: 0.9em; color: #666; word-break: break-all; }
        .finding-item { margin: 10px 0; padding: 10px; background: #fafafa; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>PCAP Analysis Report Card</h1>
    <a href="/">&larr; Analyze Another File</a>
    
    <div class="report-card">
        <!-- Beginner Narrative -->
        <div class="section info">
            <h2>What's Happening in This Traffic?</h2>
            <p class="narrative">{{ narrative }}</p>
        </div>
        
        <div class="section">
            <h2>Summary</h2>
            <p>File: <strong>{{ filename }}</strong></p>
            <p>Total Packets Analyzed: <span class="total-packets">{{ total_packets }}</span></p>
        </div>
        
        <div class="section">
            <h2>Protocol Summary (Top 3)</h2>
            <table>
                <tr>
                    <th>Rank</th>
                    <th>Protocol</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
                {% for protocol in protocol_summary %}
                <tr>
                    <td>{{ loop.index }}</td>
                    <td>{{ protocol.name }}</td>
                    <td>{{ protocol.count }}</td>
                    <td>{{ protocol.percentage }}%</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        
        <!-- Intrusion & Exfiltration Alerts -->
        <div class="section {% if enumeration_findings or exfiltration_findings %}alert{% else %}success{% endif %}">
            <h2>Intrusion & Exfiltration Alerts</h2>
            
            {% if enumeration_findings %}
            <h3>Port Sweep Detection</h3>
            <p class="bold-alert">WARNING: Potential port scanning activity detected!</p>
            {% for finding in enumeration_findings %}
            <div class="finding-item">
                <p><strong>Source IP:</strong> {{ finding.source_ip }}</p>
                <p><strong>Target IP:</strong> {{ finding.dest_ip }}</p>
                <p><strong>Unique Ports Scanned:</strong> {{ finding.port_count }}</p>
                <p><strong>Packet Numbers:</strong> <span class="packet-nums">{{ finding.packet_numbers|join(', ') }}</span></p>
            </div>
            {% endfor %}
            {% else %}
            <p><strong>No port sweep activity detected.</strong></p>
            {% endif %}
            
            <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
            
            {% if exfiltration_findings %}
            <h3>Data Exfiltration Detection</h3>
            <p class="bold-alert">WARNING: Asymmetrical data flow detected - possible data exfiltration!</p>
            {% for finding in exfiltration_findings %}
            <div class="finding-item">
                <p><strong>Source IP (Internal):</strong> {{ finding.source_ip }}</p>
                <p><strong>Destination IP:</strong> {{ finding.dest_ip }}</p>
                <p><strong>Outbound Bytes:</strong> {{ finding.outbound_bytes }}</p>
                <p><strong>Inbound Bytes:</strong> {{ finding.inbound_bytes }}</p>
                <p><strong>Ratio:</strong> {{ finding.ratio }}:1 (outbound to inbound)</p>
            </div>
            {% endfor %}
            {% else %}
            <p><strong>No suspicious data exfiltration patterns detected.</strong></p>
            {% endif %}
        </div>
        
        <div class="section {% if password_count > 0 %}warning{% else %}success{% endif %}">
            <h2>Security Check: Cleartext Credentials</h2>
            {% if password_count > 0 %}
                <p class="bold-warning">WARNING: Found {{ password_count }} packet(s) containing potential cleartext passwords!</p>
                <p>This indicates sensitive information may be transmitted without encryption. Review these packets immediately.</p>
            {% else %}
                <p><strong>No packets with cleartext passwords detected.</strong></p>
                <p>No packets containing the word "password" were found in packet payloads.</p>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

ERROR_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Error - PCAP Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .error { background: #fff5f5; padding: 20px; border-radius: 8px; border-left: 4px solid #dc3545; }
        a { color: #007bff; }
    </style>
</head>
<body>
    <h1>Error</h1>
    <div class="error">
        <p>{{ error_message }}</p>
    </div>
    <p><a href="/">&larr; Go Back</a></p>
</body>
</html>
"""


def detect_enumeration(scan_data):
    """
    Detect Port Sweep attempts.
    A port sweep is when a single source IP sends TCP SYN packets to multiple
    different destination ports on the same destination IP.
    
    Args:
        scan_data: dict of {(src_ip, dst_ip): {'ports': set(), 'packets': list()}}
    
    Returns:
        List of findings with source IP, dest IP, and packet numbers
    """
    findings = []
    threshold = 15
    
    for (src_ip, dst_ip), data in scan_data.items():
        if len(data['ports']) > threshold:
            findings.append({
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'port_count': len(data['ports']),
                'packet_numbers': sorted(data['packets'][:50])
            })
    
    return findings


def detect_exfiltration(flow_data):
    """
    Detect asymmetrical data flows that may indicate data exfiltration.
    Looks for sessions where outbound bytes significantly exceed inbound bytes.
    
    Args:
        flow_data: dict of {(src_ip, dst_ip): {'outbound': bytes, 'inbound': bytes}}
    
    Returns:
        List of findings with source IP, dest IP, and byte ratio
    """
    findings = []
    ratio_threshold = 50
    min_outbound_bytes = 10000
    
    for (src_ip, dst_ip), data in flow_data.items():
        outbound = data['outbound']
        inbound = data['inbound']
        
        if outbound > min_outbound_bytes and inbound > 0:
            ratio = outbound / inbound
            if ratio > ratio_threshold:
                findings.append({
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'outbound_bytes': outbound,
                    'inbound_bytes': inbound,
                    'ratio': round(ratio, 1)
                })
        elif outbound > min_outbound_bytes and inbound == 0:
            findings.append({
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'outbound_bytes': outbound,
                'inbound_bytes': inbound,
                'ratio': "Infinite (no inbound)"
            })
    
    findings.sort(key=lambda x: x['outbound_bytes'], reverse=True)
    return findings[:10]


def generate_narrative(protocol_summary, destination_counts, total_packets):
    """
    Generate a beginner-friendly narrative describing the network traffic.
    
    Args:
        protocol_summary: list of top protocols
        destination_counts: Counter of destination IPs/hosts
        total_packets: total number of packets analyzed
    
    Returns:
        A human-readable paragraph describing the traffic
    """
    top_destinations = destination_counts.most_common(2)
    
    dest_str = ""
    if len(top_destinations) >= 2:
        dest_str = f"{top_destinations[0][0]} and {top_destinations[1][0]}"
    elif len(top_destinations) == 1:
        dest_str = top_destinations[0][0]
    else:
        dest_str = "various destinations"
    
    protocol_str = ""
    if protocol_summary:
        protocols = [p['name'] for p in protocol_summary[:2]]
        if len(protocols) >= 2:
            protocol_str = f"{protocols[0]} and {protocols[1]}"
        elif len(protocols) == 1:
            protocol_str = protocols[0]
        else:
            protocol_str = "various protocols"
    else:
        protocol_str = "various protocols"
    
    narrative = (
        f"This capture contains {total_packets:,} packets of network traffic. "
        f"The network primarily communicated with {dest_str} "
        f"using {protocol_str} protocols. "
    )
    
    if any(p['name'] == 'DNS' for p in protocol_summary):
        narrative += "DNS queries were used to resolve domain names. "
    
    if any(p['name'] == 'TCP' for p in protocol_summary):
        narrative += "TCP connections indicate web browsing, file transfers, or other application traffic. "
    
    if any(p['name'] == 'UDP' for p in protocol_summary):
        narrative += "UDP traffic may include streaming, gaming, or DNS lookups. "
    
    return narrative


def analyze_pcap_streaming(file_path, max_packets=100000):
    """
    Analyze PCAP file using streaming to avoid memory issues.
    Collects all necessary data for protocol analysis and intrusion detection.
    
    Returns dict with all analysis results
    """
    protocol_counts = Counter()
    destination_counts = Counter()
    password_count = 0
    total_packets = 0
    
    scan_data = defaultdict(lambda: {'ports': set(), 'packets': []})
    flow_data = defaultdict(lambda: {'outbound': 0, 'inbound': 0})
    
    with PcapReader(file_path) as pcap_reader:
        for packet in pcap_reader:
            total_packets += 1
            
            if total_packets > max_packets:
                break
            
            if packet.haslayer('DNS'):
                protocol_counts['DNS'] += 1
            elif packet.haslayer('ICMP'):
                protocol_counts['ICMP'] += 1
            elif packet.haslayer('ARP'):
                protocol_counts['ARP'] += 1
            elif packet.haslayer('TCP'):
                protocol_counts['TCP'] += 1
            elif packet.haslayer('UDP'):
                protocol_counts['UDP'] += 1
            elif packet.haslayer('IP'):
                protocol_counts['IP (Other)'] += 1
            else:
                protocol_counts['Other'] += 1
            
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                destination_counts[dst_ip] += 1
                
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    
                    if tcp_layer.flags & 0x02 and not (tcp_layer.flags & 0x10):
                        dst_port = tcp_layer.dport
                        scan_data[(src_ip, dst_ip)]['ports'].add(dst_port)
                        scan_data[(src_ip, dst_ip)]['packets'].append(total_packets)
                    
                    pkt_len = len(packet)
                    flow_data[(src_ip, dst_ip)]['outbound'] += pkt_len
                    flow_data[(dst_ip, src_ip)]['inbound'] += pkt_len
            
            if packet.haslayer(Raw):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                    if 'password' in payload:
                        password_count += 1
                except Exception:
                    pass
    
    top_3 = protocol_counts.most_common(3)
    protocol_summary = []
    for name, count in top_3:
        percentage = round((count / total_packets) * 100, 1) if total_packets > 0 else 0
        protocol_summary.append({
            'name': name,
            'count': count,
            'percentage': percentage
        })
    
    enumeration_findings = detect_enumeration(scan_data)
    exfiltration_findings = detect_exfiltration(flow_data)
    narrative = generate_narrative(protocol_summary, destination_counts, total_packets)
    
    return {
        'total_packets': total_packets,
        'protocol_summary': protocol_summary,
        'password_count': password_count,
        'enumeration_findings': enumeration_findings,
        'exfiltration_findings': exfiltration_findings,
        'narrative': narrative
    }


@app.route('/')
def index():
    """Render the upload form."""
    return render_template_string(UPLOAD_FORM)


@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle file upload and perform PCAP analysis."""
    print("Starting PCAP analysis...", file=sys.stderr, flush=True)
    
    if 'pcap_file' not in request.files:
        return render_template_string(ERROR_TEMPLATE, error_message="No file uploaded. Please select a PCAP file.")
    
    file = request.files['pcap_file']
    
    if file.filename == '':
        return render_template_string(ERROR_TEMPLATE, error_message="No file selected. Please choose a PCAP file to analyze.")
    
    if not file.filename.lower().endswith(('.pcap', '.pcapng')):
        return render_template_string(ERROR_TEMPLATE, error_message="Invalid file type. Please upload a .pcap or .pcapng file.")
    
    tmp_path = None
    try:
        print(f"Processing file: {file.filename}", file=sys.stderr, flush=True)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
            file.save(tmp_file.name)
            tmp_path = tmp_file.name
        
        print(f"Saved to temp file, analyzing with streaming...", file=sys.stderr, flush=True)
        results = analyze_pcap_streaming(tmp_path)
        print(f"Analyzed {results['total_packets']} packets", file=sys.stderr, flush=True)
        
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        
        if results['total_packets'] == 0:
            return render_template_string(ERROR_TEMPLATE, error_message="The uploaded PCAP file contains no packets.")
        
        print("Analysis complete!", file=sys.stderr, flush=True)
        
        return render_template_string(
            REPORT_TEMPLATE,
            filename=file.filename,
            total_packets=results['total_packets'],
            protocol_summary=results['protocol_summary'],
            password_count=results['password_count'],
            enumeration_findings=results['enumeration_findings'],
            exfiltration_findings=results['exfiltration_findings'],
            narrative=results['narrative']
        )
    
    except Exception as e:
        print(f"Error during analysis: {str(e)}", file=sys.stderr, flush=True)
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return render_template_string(ERROR_TEMPLATE, error_message=f"Error analyzing PCAP file: {str(e)}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
