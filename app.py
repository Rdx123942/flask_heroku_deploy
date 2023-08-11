from flask import Flask, request, render_template, Response
import whois
import pandas as pd
import io
import requests
import socket
from flask_socketio import SocketIO, emit

app = Flask(__name__, template_folder='C:/Users/ACER/Desktop/cyberAI/')
socketio = SocketIO(app)

# Simple cache to store WHOIS data
whois_cache = {}

# Maintain a list to store recently looked up domains
recently_looked_up = []

# Maximum number of domains to keep in the history
MAX_HISTORY_SIZE = 10

def is_domain_available(domain):
    availability_url = f"https://api.whois.vu/?q={domain}"
    response = requests.get(availability_url)
    return "is available" in response.text

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return f"IP Address of '{domain}': {ip_address}"
    except Exception as e:
        return f"Error getting IP address: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

def get_owner_name(whois_info):
    owner_name = whois_info.get("name") or whois_info.get("registrant_name") or "Unknown"
    return owner_name

@app.route('/lookup', methods=['POST'])
def lookup():
    domain = request.form['domain']
    try:
        if is_domain_available(domain):
            result_with_ip = f"Domain '{domain}' is available."
        else:
            w = whois.whois(domain)
            result = str(w)

            show_ip = "showip" in domain.lower()
            user_ip = request.remote_addr if show_ip else "IP address hidden"

            result_with_ip = f"User IP Address: {user_ip}\n\n{result}"

            # Emit a real-time update using SocketIO
            socketio.emit('lookup_update', {'domain': domain, 'result': result_with_ip})

            # Add the domain to the recently looked up list
            recently_looked_up.insert(0, domain)
            if len(recently_looked_up) > MAX_HISTORY_SIZE:
                recently_looked_up.pop()

            # Cache the WHOIS data
            whois_cache[domain] = result_with_ip
    except Exception as e:
        result_with_ip = f"Error: {str(e)}"
    return result_with_ip

@app.route('/get_ip', methods=['POST'])
def get_ip():
    domain = request.form['domain']
    try:
        ip_result = get_ip_address(domain)
    except Exception as e:
        ip_result = f"Error: {str(e)}"
    return ip_result

@app.route('/download_excel', methods=['POST'])
def download_excel():
    domain = request.form['domain']
    try:
        if domain in whois_cache:
            # Retrieve cached WHOIS data
            result_with_ip = whois_cache[domain]
        else:
            w = whois.whois(domain)
            data = {
                'Domain': [domain],
                'Registrar': [w.registrar],
                'Creation Date': [w.creation_date],
                'Expiration Date': [w.expiration_date],
                'Status': [w.status],
                'Registrant Name': [w.name],
                'Registrant Email': [w.email]
            }
            df = pd.DataFrame(data)

            output = io.BytesIO()
            writer = pd.ExcelWriter(output, engine='xlsxwriter')
            df.to_excel(writer, sheet_name='WHOIS Data', index=False)
            writer.save()
            output.seek(0)

            result_with_ip = Response(output.read(), content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

            # Emit a real-time update using SocketIO
            socketio.emit('lookup_update', {'domain': domain, 'result': result_with_ip})

            # Cache the WHOIS data
            whois_cache[domain] = result_with_ip
    except Exception as e:
        result_with_ip = f"Error: {str(e)}"
    return result_with_ip

@app.route('/recent_history')
def recent_history():
    return render_template('recent_history.html', recently_looked_up=recently_looked_up)

if __name__ == '__main__':
    socketio.run(app, debug=True)
