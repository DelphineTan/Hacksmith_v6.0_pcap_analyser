import os
import sys
import tempfile
from collections import Counter
from flask import Flask, request, render_template_string

from scapy.all import rdpcap, Raw

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

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
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1, h2 { color: #333; }
        .report-card { background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .section { margin: 20px 0; padding: 15px; background: white; border-radius: 4px; border-left: 4px solid #007bff; }
        .warning { border-left-color: #dc3545; background: #fff5f5; }
        .success { border-left-color: #28a745; background: #f5fff5; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        .bold-warning { color: #dc3545; font-weight: bold; font-size: 1.1em; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .total-packets { font-size: 1.5em; color: #007bff; font-weight: bold; }
    </style>
</head>
<body>
    <h1>PCAP Analysis Report Card</h1>
    <a href="/">&larr; Analyze Another File</a>
    
    <div class="report-card">
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


def get_protocol_summary(packets):
    """
    Function 1: Protocol Summary
    Count total packets and list the top 3 most common protocols.
    Check application-layer protocols (DNS) before transport-layer (TCP/UDP).
    """
    protocol_counts = Counter()
    
    for packet in packets:
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
    
    total = len(packets)
    top_3 = protocol_counts.most_common(3)
    
    result = []
    for name, count in top_3:
        percentage = round((count / total) * 100, 1) if total > 0 else 0
        result.append({
            'name': name,
            'count': count,
            'percentage': percentage
        })
    
    return result


def security_check_passwords(packets):
    """
    Function 2: Security Check
    Identify and count all packets containing "password" (case-insensitive) in payload.
    """
    password_count = 0
    
    for packet in packets:
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore').lower()
                if 'password' in payload:
                    password_count += 1
            except Exception:
                pass
    
    return password_count


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
        
        print(f"Saved to temp file, reading packets...", file=sys.stderr, flush=True)
        packets = rdpcap(tmp_path)
        print(f"Read {len(packets)} packets", file=sys.stderr, flush=True)
        
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        
        total_packets = len(packets)
        
        if total_packets == 0:
            return render_template_string(ERROR_TEMPLATE, error_message="The uploaded PCAP file contains no packets.")
        
        print("Analyzing protocols...", file=sys.stderr, flush=True)
        protocol_summary = get_protocol_summary(packets)
        
        print("Checking for passwords...", file=sys.stderr, flush=True)
        password_count = security_check_passwords(packets)
        
        print("Analysis complete!", file=sys.stderr, flush=True)
        
        return render_template_string(
            REPORT_TEMPLATE,
            filename=file.filename,
            total_packets=total_packets,
            protocol_summary=protocol_summary,
            password_count=password_count
        )
    
    except Exception as e:
        print(f"Error during analysis: {str(e)}", file=sys.stderr, flush=True)
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return render_template_string(ERROR_TEMPLATE, error_message=f"Error analyzing PCAP file: {str(e)}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
