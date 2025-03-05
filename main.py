import os
import sys
import requests
import subprocess
import re
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import json


def print_header():
    header = r"""
*******************************************************************
*     ___      _       _   ___    _      _____           _        *
*    / _ \ ___(_)_ __ | |_|_ _|  / \    |_   _|__   ___ | |___    *
*   | | | / __| | '_ \| __|| |  / _ \     | |/ _ \ / _ \| / __|   *
*   | |_| \__ \ | | | | |_ | | / ___ \    | | (_) | (_) | \__ \   *
*    \___/|___/_|_| |_|\__|___/_/   \_\   |_|\___/ \___/|_|___/   *
*                                                                 *
* OsintIA_Tools 1.0.3                                             *
* Coded by Asan Ashirov                                       *
* INHA University                                                 *
* Cybersecurity Research                                          *
* asanashirov24@gmail.com                                        *
*******************************************************************
"""
    print(header)


# Set your Shodan API key (optional, free tier available with limits)
SHODAN_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # Replace with your Shodan key or remove if not using

# List of required dependencies (all free tools)
DEPENDENCIES = [
    "dig", "whois", "nmap", "wget", "poppler-utils", "exiftool", "amass", "sublist3r",
    "whatweb", "theHarvester", "dnsenum", "python3", "photon", "metagoofil"
]


# Function to check and install dependencies
def check_and_install_dependencies():
    print("[+] Checking dependencies...")
    missing = []
    for dep in DEPENDENCIES:
        if subprocess.run(f"which {dep}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0:
            missing.append(dep)

    if missing:
        print(f"[!] Missing dependencies: {', '.join(missing)}")
        if os.geteuid() != 0:
            print("[!] Administrator privileges required to install dependencies. Run as root or with sudo.")
            sys.exit(1)
        print("[+] Installing dependencies...")
        install_command = f"sudo apt update >> install.log 2>&1 && sudo apt install -y {' '.join(missing)} >> install.log 2>&1"
        if subprocess.run(install_command, shell=True).returncode != 0:
            print("[!] Failed to install dependencies. Check 'install.log' for details.")
            sys.exit(1)
        print("[+] All dependencies installed successfully.")
    else:
        print("[+] All dependencies are already installed.")


# Simple rule-based analysis function (replacing OpenAI)
def basic_analysis(data, context):
    if "Error" in data or "not found" in data.lower():
        return f"Analysis for {context}: Unable to perform detailed analysis due to missing or erroneous data."
    keywords = ["vulnerability", "open port", "sensitive", "password", "key", "error"]
    findings = []
    for line in data.split('\n'):
        for keyword in keywords:
            if keyword in line.lower():
                findings.append(f"Potential issue detected in {context}: {line.strip()} (contains '{keyword}')")
    return "\n".join(
        findings) if findings else f"Analysis for {context}: No obvious issues detected based on simple keyword scan."


# Function to execute a command in the terminal
def run_command(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return result.stdout.strip()


# Function to remove ANSI codes
def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


# Function to format text into HTML paragraphs
def format_analysis_text(text):
    paragraphs = text.split('\n')
    return ''.join(f'<p>{paragraph.strip()}</p>' for paragraph in paragraphs if paragraph.strip())


# Function to generate HTML index
def generate_html_index(sections):
    index_html = "<h2>Index</h2><ul>"
    for section_id, section_name in sections.items():
        index_html += f"<li><a href='#{section_id}'>{section_name}</a></li>"
    index_html += "</ul>"
    return index_html


# Function to write a section in the HTML report
def write_section(html_file, section_id, title, content):
    html_file.write(f"<h2 id='{section_id}'>{title}</h2>{content}")


# Main function
def main(domain):
    print_header()
    if not domain:
        print("Usage: python osint_tools.py <domain>")
        sys.exit(1)

    check_and_install_dependencies()

    parsed_domain = urlparse(domain).netloc if "http" in domain else domain
    output_txt = "OsintIA_report.txt"
    output_html = "OsintIA_report.html"

    sections = {
        "ip-resolution": "IP Resolution",
        "ip-analysis": "IP Analysis",
        "shodan-data": "Shodan Data",
        "shodan-analysis": "Shodan Analysis",
        "whois-info": "WHOIS Information",
        "whois-analysis": "WHOIS Analysis",
        "port-scan": "Port Scanning with NMAP",
        "nmap-analysis": "Nmap Analysis",
        "indexed-links": "Indexed Links with Google Dorks and Photon",
        "links-analysis": "Links Analysis",
        "extracted-metadata": "Extracted Metadata with Metagoofil",
        "metadata-analysis": "Metadata Analysis",
        "found-subdomains": "Found Subdomains with Sublist3r",
        "sublist3r-analysis": "Sublist3r Analysis",
        "detected-technologies": "Detected Technologies",
        "whatweb-analysis": "WhatWeb Analysis",
        "collected-data": "Collected Data with TheHarvester",
        "theharvester-analysis": "TheHarvester Analysis",
        "dnsenum-results": "DNSEnum Results",
        "dnsenum-analysis": "DNSEnum Analysis",
        "final-conclusion": "Final Conclusion",
    }

    with open(output_txt, "w") as txt_file, open(output_html, "w") as html_file:
        html_file.write(f"<html><body><h1>OsintIA_Tools Report for {parsed_domain}</h1>")
        html_file.write(generate_html_index(sections))

        # IP Resolution
        print("[+] Resolving the domain's IP...")
        ip = "Error resolving IP"
        try:
            ip = run_command(f"dig +short {parsed_domain}")
            if not ip:
                ip = run_command(f"ping -c 1 {parsed_domain} | grep 'PING' | awk '{{print $3}}' | tr -d '()'")
            if not ip:
                ip = "IP not resolved"
        except Exception as e:
            print(f"[!] Error resolving IP: {e}")
            ip = "Error resolving IP"

        txt_file.write(f"IP: {ip}\n")
        write_section(html_file, "ip-resolution", "IP Resolution", f"<p>IP: {ip}</p>")

        # IP Analysis
        print("[+] Analyzing the resolved IP...")
        ip_analysis = basic_analysis(ip, "IP Resolution")
        formatted_ip_analysis = format_analysis_text(ip_analysis)
        txt_file.write(f"\nIP Analysis:\n{ip_analysis}\n")
        write_section(html_file, "ip-analysis", "IP Analysis", formatted_ip_analysis)

        # Shodan Query (optional, requires key)
        if SHODAN_API_KEY != "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" and ip != "Error resolving IP" and ip != "IP not resolved":
            print("[+] Querying Shodan data for the IP...")
            try:
                shodan_response = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}&minify=true", timeout=10
                )
                if shodan_response.status_code == 200:
                    shodan_result = shodan_response.json()
                    json_filename = f"shodan_{ip.replace('.', '_')}.json"
                    with open(json_filename, "w") as json_file:
                        json.dump(shodan_result, json_file, indent=4)
                    print(f"[+] Full Shodan data saved to {json_filename}")

                    extracted_data = [
                        f"IP: {shodan_result.get('ip_str', 'N/A')}",
                        f"Organization: {shodan_result.get('org', 'N/A')}",
                        f"ISP: {shodan_result.get('isp', 'N/A')}",
                        f"Operating System: {shodan_result.get('os', 'N/A')}"
                    ]
                    if 'data' in shodan_result:
                        extracted_data.append("\n--- Open Ports and Services ---")
                        for service in shodan_result['data']:
                            extracted_data.append(
                                f"Port {service.get('port', 'Unknown')}: {service.get('product', 'Unknown')} {service.get('version', '')}")
                    shodan_result = "\n".join(extracted_data)
                else:
                    shodan_result = f"Shodan returned no results for the IP: {ip}"
            except Exception as e:
                shodan_result = f"Error retrieving Shodan data: {e}"
        else:
            shodan_result = "Shodan skipped (no API key or IP resolution failed)."

        txt_file.write(f"\nShodan Data for IP:\n{shodan_result}\n")
        write_section(html_file, "shodan-data", "Shodan Data", f"<pre>{shodan_result}</pre>")

        # Shodan Analysis
        print("[+] Analyzing Shodan data...")
        shodan_analysis = basic_analysis(shodan_result, "Shodan Data")
        formatted_shodan_analysis = format_analysis_text(shodan_analysis)
        txt_file.write(f"\nShodan Analysis:\n{shodan_analysis}\n")
        write_section(html_file, "shodan-analysis", "Shodan Analysis", formatted_shodan_analysis)

        # WHOIS
        print("[+] Retrieving WHOIS information...")
        whois_info = "WHOIS information not available"
        try:
            whois_info = run_command(f"whois {parsed_domain}")
            if "No match for" in whois_info or not whois_info.strip():
                print("[!] WHOIS returned no results. Trying with Amass...")
                whois_info = run_command(f"amass enum -d {parsed_domain} --timeout 60")
        except Exception as e:
            print(f"[!] Error retrieving WHOIS: {e}")
            whois_info = "Error retrieving WHOIS information."

        txt_file.write(f"\nWHOIS Information:\n{whois_info}\n")
        write_section(html_file, "whois-info", "WHOIS Information", f"<pre>{whois_info}</pre>")

        # WHOIS Analysis
        print("[+] Analyzing WHOIS information...")
        whois_analysis = basic_analysis(whois_info, "WHOIS Information")
        formatted_whois_analysis = format_analysis_text(whois_analysis)
        txt_file.write(f"\nWHOIS Analysis:\n{whois_analysis}\n")
        write_section(html_file, "whois-analysis", "WHOIS Analysis", formatted_whois_analysis)

        # Nmap
        print("[+] Scanning open ports with NMAP...")
        try:
            nmap_result = run_command(f"nmap -F {parsed_domain}")
            if not nmap_result.strip():
                nmap_result = "No active hosts found. Check if the domain is online."
        except Exception as e:
            print(f"[!] Error running Nmap: {e}")
            nmap_result = "Error performing port scan."

        txt_file.write(f"\nPort Scan:\n{nmap_result}\n")
        write_section(html_file, "port-scan", "Port Scanning", f"<pre>{nmap_result}</pre>")

        # Nmap Analysis
        print("[+] Analyzing Nmap results...")
        nmap_analysis = basic_analysis(nmap_result, "Nmap Results")
        formatted_nmap_analysis = format_analysis_text(nmap_analysis)
        txt_file.write(f"\nNmap Analysis:\n{nmap_analysis}\n")
        write_section(html_file, "nmap-analysis", "Nmap Analysis", formatted_nmap_analysis)

        # Indexed Links
        print("[+] Retrieving indexed links with Google Dorks and Photon...")
        dorks = [
            f"site:{parsed_domain}", f"site:{parsed_domain} filetype:pdf", f"site:{parsed_domain} inurl:login"
        ]  # Reduced for simplicity
        all_links = []

        for dork in dorks:
            print(f"[+] Executing Google Dork: {dork}")
            try:
                google_search_url = f"https://www.google.com/search?q={dork}"
                google_response = requests.get(google_search_url, timeout=10)
                soup = BeautifulSoup(google_response.text, "html.parser")
                links = [a["href"] for a in soup.find_all("a", href=True) if "http" in a["href"]]
                all_links.extend(links)
            except Exception as e:
                print(f"[!] Error executing dork {dork}: {e}")

        print("[+] Executing Photon...")
        try:
            photon_command = f"python3 Photon/photon.py -u {parsed_domain} -o photon_output"
            run_command(photon_command)
            photon_output_path = f"photon_output/{parsed_domain}"
            if os.path.exists(f"{photon_output_path}/urls.txt"):
                with open(f"{photon_output_path}/urls.txt", "r") as file:
                    all_links.extend([line.strip() for line in file.readlines()])
        except Exception as e:
            print(f"[!] Error executing Photon: {e}")

        txt_file.write("\nIndexed Links with Google Dorks and Photon:\n")
        write_section(html_file, "indexed-links", "Indexed Links with Google Dorks and Photon", "<ul>")
        for link in set(all_links):
            txt_file.write(f"{link}\n")
            html_file.write(f"<li><a href='{link}'>{link}</a></li>")
        html_file.write("</ul>")

        # Links Analysis
        print("[+] Analyzing links...")
        links_analysis = basic_analysis("\n".join(all_links), "Indexed Links")
        formatted_links_analysis = format_analysis_text(links_analysis)
        txt_file.write(f"\nLinks Analysis:\n{links_analysis}\n")
        write_section(html_file, "links-analysis", "Links Analysis", formatted_links_analysis)

        # Metagoofil
        print("[+] Extracting metadata with Metagoofil...")
        file_types = ["pdf", "doc"]
        metagoofil_results = []
        for file_type in file_types:
            try:
                print(f"[+] Searching for {file_type} files...")
                metagoofil_command = f"metagoofil -d {parsed_domain} -t {file_type} -l 5 -o metagoofil_output"
                result = run_command(metagoofil_command)
                metagoofil_results.append(f"Results for {file_type}:\n{result if result else 'No metadata found'}")
                time.sleep(5)
            except Exception as e:
                metagoofil_results.append(f"[!] Error for {file_type}: {e}")

        metagoofil_result = "\n\n".join(metagoofil_results)
        txt_file.write(f"\nExtracted Metadata with Metagoofil:\n{metagoofil_result}\n")
        write_section(html_file, "extracted-metadata", "Extracted Metadata with Metagoofil",
                      f"<pre>{metagoofil_result}</pre>")

        # Metadata Analysis
        print("[+] Analyzing metadata...")
        metadata_analysis = basic_analysis(metagoofil_result, "Metadata")
        formatted_metadata_analysis = format_analysis_text(metadata_analysis)
        txt_file.write(f"\nMetadata Analysis:\n{metadata_analysis}\n")
        write_section(html_file, "metadata-analysis", "Metadata Analysis", formatted_metadata_analysis)

        # Sublist3r
        print("[+] Running Sublist3r...")
        try:
            sublist3r_result = run_command(f"sublist3r -d {parsed_domain}")
            cleaned_sublist3r_result = remove_ansi_escape_sequences(sublist3r_result)
        except Exception as e:
            cleaned_sublist3r_result = f"[!] Error running Sublist3r: {e}"

        txt_file.write(f"\nFound Subdomains (Sublist3r):\n{cleaned_sublist3r_result}\n")
        write_section(html_file, "found-subdomains", "Found Subdomains with Sublist3r",
                      f"<pre>{cleaned_sublist3r_result}</pre>")

        # Sublist3r Analysis
        print("[+] Analyzing subdomains...")
        sublist3r_analysis = basic_analysis(cleaned_sublist3r_result, "Sublist3r Subdomains")
        formatted_sublist3r_analysis = format_analysis_text(sublist3r_analysis)
        txt_file.write(f"\nSublist3r Analysis:\n{sublist3r_analysis}\n")
        write_section(html_file, "sublist3r-analysis", "Sublist3r Analysis", formatted_sublist3r_analysis)

        # WhatWeb
        print("[+] Detecting technologies with WhatWeb...")
        try:
            whatweb_result = run_command(f"whatweb {parsed_domain}")
            cleaned_whatweb_result = remove_ansi_escape_sequences(whatweb_result)
        except Exception as e:
            cleaned_whatweb_result = f"[!] Error running WhatWeb: {e}"

        txt_file.write(f"\nDetected Technologies:\n{cleaned_whatweb_result}\n")
        write_section(html_file, "detected-technologies", "Detected Technologies",
                      f"<pre>{cleaned_whatweb_result}</pre>")

        # WhatWeb Analysis
        print("[+] Analyzing technologies...")
        whatweb_analysis = basic_analysis(cleaned_whatweb_result, "WhatWeb Technologies")
        formatted_whatweb_analysis = format_analysis_text(whatweb_analysis)
        txt_file.write(f"\nWhatWeb Analysis:\n{whatweb_analysis}\n")
        write_section(html_file, "whatweb-analysis", "WhatWeb Analysis", formatted_whatweb_analysis)

        # TheHarvester
        print("[+] Collecting data with TheHarvester...")
        try:
            theharvester_result = run_command(f"theHarvester -d {parsed_domain} -b bing,duckduckgo")
            cleaned_theharvester_result = remove_ansi_escape_sequences(theharvester_result)
        except Exception as e:
            cleaned_theharvester_result = f"[!] Error running TheHarvester: {e}"

        txt_file.write(f"\nCollected Data (TheHarvester):\n{cleaned_theharvester_result}\n")
        write_section(html_file, "collected-data", "Collected Data with TheHarvester",
                      f"<pre>{cleaned_theharvester_result}</pre>")

        # TheHarvester Analysis
        print("[+] Analyzing TheHarvester data...")
        theharvester_analysis = basic_analysis(cleaned_theharvester_result, "TheHarvester Data")
        formatted_theharvester_analysis = format_analysis_text(theharvester_analysis)
        txt_file.write(f"\nTheHarvester Analysis:\n{theharvester_analysis}\n")
        write_section(html_file, "theharvester-analysis", "TheHarvester Analysis", formatted_theharvester_analysis)

        # DNSEnum
        print("[+] Running DNSEnum...")
        try:
            dnsenum_result = run_command(f"dnsenum --dnsserver 8.8.8.8 {parsed_domain}")
            cleaned_dnsenum_result = remove_ansi_escape_sequences(dnsenum_result)
        except Exception as e:
            cleaned_dnsenum_result = f"[!] Error running DNSEnum: {e}"

        txt_file.write(f"\nCollected Data (DNSEnum):\n{cleaned_dnsenum_result}\n")
        write_section(html_file, "dnsenum-results", "DNSEnum Results", f"<pre>{cleaned_dnsenum_result}</pre>")

        # DNSEnum Analysis
        print("[+] Analyzing DNSEnum data...")
        dnsenum_analysis = basic_analysis(cleaned_dnsenum_result, "DNSEnum Data")
        formatted_dnsenum_analysis = format_analysis_text(dnsenum_analysis)
        txt_file.write(f"\nDNSEnum Analysis:\n{dnsenum_analysis}\n")
        write_section(html_file, "dnsenum-analysis", "DNSEnum Analysis", formatted_dnsenum_analysis)

        # Final Conclusion
        print("[+] Generating final conclusion...")
        with open(output_txt, "r") as report_file:
            full_report = report_file.read()

        conclusion = (
            "Final Conclusion:\n"
            "This report aggregates findings from various free OSINT tools. Key observations include:\n"
            "- IP and subdomain enumeration may reveal network structure.\n"
            "- Open ports or sensitive data in metadata/links could indicate vulnerabilities.\n"
            "Recommendations: Secure exposed services, remove sensitive data from public access, and monitor subdomains.\n"
            f"Review the full report for details:\n{full_report[:500]}..."
        )
        formatted_conclusion = format_analysis_text(conclusion)
        txt_file.write(f"\nFinal Conclusion:\n{conclusion}\n")
        write_section(html_file, "final-conclusion", "Final Conclusion", formatted_conclusion)

        print(f"Reports saved in {output_txt} and {output_html}")


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else None
    main(domain)