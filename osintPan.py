import streamlit as st
import socket
import requests
import dns.resolver
import whois
import ssl
import re
from datetime import datetime
import shodan
import ipaddress


# ==========================
# CONFIG
# ==========================

SHODAN_API_KEY = "nptK2ZNCc3EQfjXjt5JHbbWannrOC1oi"



# ==========================
# Utility Functions
# ==========================

def format_date(date_obj):
    if isinstance(date_obj, list):
        date_obj = date_obj[0]
    if not date_obj:
        return "Unknown"
    if isinstance(date_obj, datetime):
        return date_obj.strftime("%Y-%m-%d %H:%M:%S")
    return str(date_obj)


def is_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except:
        return False


def is_email(text: str) -> bool:
    return "@" in text and "." in text


def is_domain(text: str) -> bool:
    pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, text))


def is_username(text: str) -> bool:
    return len(text) >= 3 and "@" not in text and "." not in text



# ==========================
# SSL Certificate Lookup
# ==========================

def get_ssl_info(domain):
    if is_ip(domain):
        return {"SSL Error": "SSL lookup skipped because target is an IP."}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        return {
            "Issuer": dict(x[0] for x in cert["issuer"]).get("organizationName", "N/A"),
            "Subject": dict(x[0] for x in cert["subject"]).get("commonName", "N/A"),
            "Valid From": cert.get("notBefore"),
            "Valid To": cert.get("notAfter"),
        }

    except Exception as e:
        return {"SSL Error": str(e)}



# ==========================
# ASN Lookup
# ==========================

def get_asn_info(ip):
    try:
        data = requests.get(f"https://ipinfo.io/{ip}/json").json()
        return {
            "IP": ip,
            "ASN": data.get("org", "Unknown"),
            "City": data.get("city", "Unknown"),
            "Region": data.get("region", "Unknown"),
            "Country": data.get("country", "Unknown"),
            "Location": data.get("loc", "Unknown"),
        }
    except:
        return {"ASN Error": "Lookup failed"}



# ==========================
# FREE DNS HISTORY LOOKUP
# ==========================

def lookup_dns_history(domain):
    history = {"A Records": [], "NS Records": [], "MX Records": []}

    try:
        url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
        r = requests.get(url, timeout=5).text

        for line in r.splitlines():
            if "A" in line and not line.startswith(";;"):
                parts = line.split()
                if len(parts) >= 3:
                    history["A Records"].append(parts[2])

            if "NS" in line and not line.startswith(";;"):
                parts = line.split()
                if len(parts) >= 3:
                    history["NS Records"].append(parts[2])

            if "MX" in line and not line.startswith(";;"):
                parts = line.split()
                if len(parts) >= 3:
                    history["MX Records"].append(parts[2])

    except:
        history["A Records"] = ["Error loading DNS history"]

    return history



# ==========================
# Shodan Lookup
# ==========================

def lookup_shodan(target):
    if not SHODAN_API_KEY:
        return {"Shodan Error": "Missing API key"}

    api = shodan.Shodan(SHODAN_API_KEY)

    if is_ip(target):
        try:
            result = api.host(target)
            return {
                "IP": result.get("ip_str"),
                "Organisation": result.get("org"),
                "Operating System": result.get("os"),
                "Open Ports": result.get("ports", []),
            }
        except Exception as e:
            return {"Shodan Error": str(e)}

    return {"Shodan Error": "Free API cannot scan domains."}



# ==========================
# OSINT CONFIDENCE SCORING
# ==========================

def compute_username_confidence(availability):
    score = 0
    reasons = []

    exists_count = sum(1 for p in availability.values() if p["status"] == "Exists")
    error_count = sum(1 for p in availability.values() if p["status"] == "Error checking")

    if exists_count >= 8:
        score += 40
        reasons.append("Username found across many major platforms")
    elif exists_count >= 4:
        score += 25
        reasons.append("Username found on several platforms")
    elif exists_count >= 2:
        score += 10
        reasons.append("Username found on a few platforms")
    else:
        score += 2
        reasons.append("Sparse matches — may not represent same user")

    common_usernames = ["alex", "john", "michael", "jessica", "admin", "test", "user"]
    if any(word.lower() == word.lower() for word in common_usernames):
        score -= 20
        reasons.append("Username is extremely common → low uniqueness")
    else:
        score += 15
        reasons.append("Username appears unique")

    if error_count > 3:
        score -= 10
        reasons.append("Multiple platforms returned errors")

    score = max(0, min(100, score))
    return score, reasons



# ==========================
# OSINT Lookups
# ==========================

def lookup_ip(ip):
    results = {"type": "IP", "target": ip, "data": {}, "links": []}

    results["data"]["IP Info"] = get_asn_info(ip)
    results["data"]["Shodan"] = lookup_shodan(ip)
    results["links"].append(f"https://ipinfo.io/{ip}")

    return results



def lookup_domain(domain):
    results = {"type": "Domain", "target": domain, "data": {}, "links": []}

    try:
        w = whois.whois(domain)
        results["data"]["Registrar"] = w.registrar
        results["data"]["Creation Date"] = format_date(w.creation_date)
        results["data"]["Expiration Date"] = format_date(w.expiration_date)
    except:
        results["data"]["WHOIS"] = "WHOIS lookup failed"

    dns_output = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            dns_output[rtype] = [str(r) for r in resolver.resolve(domain, rtype)]
        except:
            dns_output[rtype] = []

    results["data"]["DNS Records"] = dns_output

    results["data"]["SSL Certificate"] = get_ssl_info(domain)

    asn_list = [get_asn_info(ip) for ip in dns_output.get("A", [])]
    results["data"]["ASN Info"] = asn_list

    wordlist = ["mail", "test", "dev", "admin", "portal", "login", "api", "staging", "secure"]
    found = []
    for sub in wordlist:
        try:
            socket.gethostbyname(f"{sub}.{domain}")
            found.append(f"{sub}.{domain}")
        except:
            pass
    results["data"]["Subdomains Found"] = found

    results["data"]["Shodan"] = lookup_shodan(domain)

    results["data"]["DNS History"] = lookup_dns_history(domain)

    return results



def lookup_email(email):
    domain = email.split("@")[1]
    results = {"type": "Email", "target": email, "data": {}, "links": []}

    results["data"]["Valid Format"] = bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))

    try:
        mx = dns.resolver.resolve(domain, "MX")
        parsed = []
        for r in mx:
            p = str(r).split()
            parsed.append({"priority": p[0], "server": p[1].rstrip(".")})
        results["data"]["Mail Servers"] = parsed
    except:
        results["data"]["Mail Servers"] = [{"error": "No MX records found"}]

    results["data"]["Simulated Breach Status"] = {"status": "Demo only — no real breach lookup used."}
    return results



def lookup_username(user):
    results = {"type": "Username", "target": user, "data": {}, "links": []}

    platforms = {
        "GitHub": f"https://github.com/{user}",
        "Reddit": f"https://www.reddit.com/user/{user}",
        "Instagram": f"https://www.instagram.com/{user}",
        "Twitter": f"https://x.com/{user}",
        "TikTok": f"https://www.tiktok.com/@{user}",
        "YouTube": f"https://www.youtube.com/@{user}",
        "Pinterest": f"https://www.pinterest.com/{user}",
        "Twitch": f"https://www.twitch.tv/{user}",
        "SoundCloud": f"https://soundcloud.com/{user}",
        "GitLab": f"https://gitlab.com/{user}",
        "Steam": f"https://steamcommunity.com/id/{user}",
        "Medium": f"https://medium.com/@{user}",
        "DeviantArt": f"https://www.deviantart.com/{user}",
    }

    headers = {"User-Agent": "Mozilla/5.0"}
    availability = {}

    for platform, url in platforms.items():
        try:
            r = requests.get(url, headers=headers)

            if r.status_code == 200:
                availability[platform] = {"status": "Exists", "url": url}
                results["links"].append(url)
            elif r.status_code == 404:
                availability[platform] = {"status": "Not Found", "url": url}
            else:
                availability[platform] = {"status": "Error checking", "url": url}

        except:
            availability[platform] = {"status": "Error checking", "url": url}

    results["data"]["Profiles"] = availability

    score, reasons = compute_username_confidence(availability)

    results["data"]["Confidence Score"] = {
        "score": score,
        "reasons": reasons
    }

    return results



# ==========================
# CLEAN DISPLAY ENGINE
# ==========================

def display_results(result):
    st.markdown(f"## 🔎 OSINT Results for: **{result['target']}**")

    for key, val in result["data"].items():

        with st.expander(f"{key}", expanded=False):

            if isinstance(val, dict) and list(val.keys()) == ["status"]:
                st.markdown(f"**Status:** {val['status']}")
                continue

            if key == "Profiles":
                for platform, info in val.items():
                    status = info["status"]
                    url = info["url"]

                    if status == "Exists":
                        st.markdown(f"🟩 **{platform}** → [Visit Profile]({url})")
                    elif status == "Not Found":
                        st.markdown(f"🟥 **{platform}** → Not Found")
                    else:
                        st.markdown(f"🟨 **{platform}** → Error checking")
                continue

            if key == "Confidence Score":
                score = val["score"]
                reasons = val["reasons"]

                st.markdown(f"### 🔥 Confidence Score: **{score}/100**")

                for r in reasons:
                    st.markdown(f"- {r}")
                continue

            if key == "Mail Servers":
                for entry in val:
                    if isinstance(entry, dict):
                        st.markdown(f"- Priority **{entry.get('priority')}** → `{entry.get('server')}`")
                    else:
                        st.markdown(f"- `{entry}`")
                continue

            if key == "DNS Records":
                for rtype, records in val.items():
                    st.markdown(f"### {rtype}")
                    if records:
                        for r in records:
                            st.markdown(f"- `{r}`")
                    else:
                        st.markdown("*None*")
                continue

            if key == "DNS History":
                for rtype, records in val.items():
                    st.markdown(f"### {rtype}")
                    if records:
                        for r in records:
                            st.markdown(f"- `{r}`")
                    else:
                        st.markdown("*None*")
                continue

            if key == "SSL Certificate":
                st.markdown(f"**Issuer:** {val.get('Issuer')}")
                st.markdown(f"**Subject:** {val.get('Subject')}")
                st.markdown(f"**Valid From:** {val.get('Valid From')}")
                st.markdown(f"**Valid To:** {val.get('Valid To')}")
                continue

            if key == "Subdomains Found":
                if len(val) == 0:
                    st.markdown("*No subdomains found*")
                else:
                    for s in val:
                        st.markdown(f"- `{s}`")
                continue

            if key == "IP Info" and isinstance(val, dict):
                st.markdown(f"- **IP:** {val.get('IP')}")
                st.markdown(f"- **ASN:** {val.get('ASN')}")
                st.markdown(f"- **City:** {val.get('City')}")
                st.markdown(f"- **Region:** {val.get('Region')}")
                st.markdown(f"- **Country:** {val.get('Country')}")
                location = val.get("Location")

                if location and "," in location:
                    st.markdown(f"- **Location:** {location}")
                    st.markdown(f"- 🌍 [Open in Google Maps](https://www.google.com/maps?q={location})")
                continue

            if key == "Shodan":
                st.markdown(f"- **IP:** {val.get('IP')}")
                st.markdown(f"- **Organisation:** {val.get('Organisation')}")
                st.markdown(f"- **Operating System:** {val.get('Operating System')}")

                ports = val.get("Open Ports", [])
                if ports:
                    st.markdown("**Open Ports:** " + ", ".join(str(p) for p in ports))
                else:
                    st.markdown("**Open Ports:** None")
                continue

            if key == "ASN Info":
                if not val:
                    st.markdown("*No ASN info available*")
                    continue

                for i, entry in enumerate(val, start=1):
                    ip = entry.get("IP")
                    asn = entry.get("ASN")
                    loc = entry.get("Location", "")
                    maps_url = f"https://www.google.com/maps?q={loc}" if "," in loc else None

                    st.markdown(f"### Entry {i}")
                    st.markdown(f"- **IP:** {ip}")
                    st.markdown(f"- **ASN:** {asn}")
                    st.markdown(f"- **City:** {entry.get('City')}")
                    st.markdown(f"- **Region:** {entry.get('Region')}")
                    st.markdown(f"- **Country:** {entry.get('Country')}")
                    st.markdown(f"- **Location:** {loc}")

                    st.markdown("#### 🔗 Lookup Links")
                    st.markdown(f"- [IPinfo](https://ipinfo.io/{ip})")
                    st.markdown(f"- [AbuseIPDB](https://www.abuseipdb.com/check/{ip})")

                    if isinstance(asn, str) and asn.startswith("AS") and asn[2:].split(" ")[0].isdigit():
                        num = asn[2:].split(" ")[0]
                        st.markdown(f"- [BGP ASN Lookup](https://bgp.he.net/AS{num})")

                    if maps_url:
                        st.markdown(f"- 🌍 [Open in Google Maps]({maps_url})")

                    st.markdown("---")
                continue

            st.markdown(str(val))



# ==========================
# UI (AUTO-DETECT + URL PARAMS)
# ==========================

def run_streamlit_app():
    st.title("🕵️ OSINT Fusion Panel")
    st.caption("Auto-detects IP, Domain, Email, or Username with OSINT scoring")

    # NEW Streamlit parameter system
    query_params = st.query_params

    # Extract ?q= parameter (auto-runs)
    prefilled = query_params.get("q", "")

    # Pre-fill search box
    user_input = st.text_input("Enter an IP, Domain, Email, or Username", value=prefilled)

    # Auto-run scan if opened with /?q=something
    if prefilled:
        user_input = prefilled.strip()

        if is_ip(user_input):
            st.info("Detected IP Address")
            result = lookup_ip(user_input)
        elif is_email(user_input):
            st.info("Detected Email Address")
            result = lookup_email(user_input)
        elif is_domain(user_input):
            st.info("Detected Domain Name")
            result = lookup_domain(user_input)
        elif is_username(user_input):
            st.info("Detected Username")
            result = lookup_username(user_input)
        else:
            st.error("Could not detect input type.")
            st.stop()

        display_results(result)
        st.stop()

    # Manual scan button
    if st.button("Run OSINT Scan"):
        user_input = user_input.strip()

        if is_ip(user_input):
            st.info("Detected IP Address")
            result = lookup_ip(user_input)
        elif is_email(user_input):
            st.info("Detected Email Address")
            result = lookup_email(user_input)
        elif is_domain(user_input):
            st.info("Detected Domain Name")
            result = lookup_domain(user_input)
        elif is_username(user_input):
            st.info("Detected Username")
            result = lookup_username(user_input)
        else:
            st.error("Could not detect input type.")
            st.stop()

        display_results(result)


if __name__ == "__main__":
    run_streamlit_app()
