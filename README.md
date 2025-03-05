# OSINTAI
OSINT_TOOLS
A free, open-source OSINT (Open Source Intelligence) toolset for cybersecurity research, designed to analyze domains and generate detailed reports without reliance on paid APIs.

## Author
- **Coded by**:Asan Ashirov
- **Affiliation**: INHA University
- **Email**: asanashirov@gmail.com
- **Purpose**: Cybersecurity Research

## Features
- **Domain Analysis**: Resolves IPs, scans ports, enumerates subdomains, and collects metadata.
- **Free Tools**: Utilizes only free, open-source tools like `dig`, `nmap`, `sublist3r`, `theHarvester`, etc.
- **Report Generation**: Outputs findings in both TXT and HTML formats with an index for easy navigation.
- **Basic Analysis**: Performs simple keyword-based analysis instead of AI for cost-free operation.
- **Optional Shodan**: Supports Shodan integration if a free-tier API key is provided.

## Prerequisites
- **Operating System**: Linux (Ubuntu/Debian recommended)
- **Python Version**: Python 3.x
- **Dependencies**: Install required tools listed below via `sudo apt install <tool>`:
  - `dig`, `whois`, `nmap`, `wget`, `poppler-utils`, `exiftool`, `amass`, `sublist3r`, `whatweb`, `theHarvester`, `dnsenum`, `photon`, `metagoofil`
- **Root Access**: Required to install dependencies if not already present.


### How the Code Works

Let’s break down the script’s functionality step-by-step:

#### 1. **Imports and Header**
- **Imports**: Libraries like `os`, `sys`, `requests`, `subprocess`, etc., handle system commands, HTTP requests, and text processing.
- **`print_header()`**: Displays an ASCII art banner with your name, university (INHA), and contact info when the script starts.

#### 2. **Configuration**
- **`SHODAN_API_KEY`**: Placeholder for an optional Shodan key (skipped if not set).
- **`DEPENDENCIES`**: List of free OSINT tools required for the script.

#### 3. **Dependency Management**
- **`check_and_install_dependencies()`**:
  - Checks if each tool in `DEPENDENCIES` is installed using `which`.
  - If any are missing, attempts to install them via `apt` (requires `sudo`).
  - Logs installation output to `install.log`.

#### 4. **Analysis Function**
- **`basic_analysis(data, context)`**:
  - Replaces OpenAI with a simple rule-based approach.
  - Scans input `data` for keywords (e.g., "vulnerability", "open port") and flags potential issues.
  - Returns a text summary with findings or a "no issues" message.

#### 5. **Utility Functions**
- **`run_command(command)`**: Executes shell commands (e.g., `nmap -F example.com`) and returns output.
- **`remove_ansi_escape_sequences(text)`**: Cleans terminal color codes from tool outputs.
- **`format_analysis_text(text)`**: Converts text into HTML paragraphs.
- **`generate_html_index(sections)`**: Creates a clickable index for the HTML report.
- **`write_section(html_file, section_id, title, content)`**: Adds a section to the HTML report.

#### 6. **Main Function (`main(domain)`)**

##### a. **Setup**
- Checks for a domain argument (`sys.argv[1]`).
- Calls `print_header()` and `check_and_install_dependencies()`.
- Parses the domain (e.g., removes `http://`) and sets output file names.

##### b. **Data Collection and Analysis**
The script runs through multiple steps, each using a specific tool:
1. **IP Resolution**:
   - Uses `dig` or `ping` to resolve the domain’s IP.
   - Analyzes with `basic_analysis()` for errors.
2. **Shodan (Optional)**:
   - Queries Shodan if a key is provided, extracts data (e.g., ports, OS), and saves it as JSON.
   - Analyzes with `basic_analysis()`.
3. **WHOIS**:
   - Runs `whois` or falls back to `amass` for domain info.
   - Analyzes with `basic_analysis()`.
4. **Nmap**:
   - Scans ports with `nmap -F`.
   - Analyzes open ports or errors.
5. **Google Dorks and Photon**:
   - Searches Google with basic dorks (e.g., `site:example.com`) and crawls with Photon.
   - Analyzes links for sensitive keywords.
6. **Metagoofil**:
   - Extracts metadata from files (e.g., PDFs).
   - Analyzes for sensitive data.
7. **Sublist3r**:
   - Enumerates subdomains.
   - Analyzes for potential risks.
8. **WhatWeb**:
   - Detects website technologies.
   - Analyzes for known vulnerabilities.
9. **TheHarvester**:
   - Collects emails and hosts.
   - Analyzes for exposed data.
10. **DNSEnum**:
    - Enumerates DNS records.
    - Analyzes for misconfigurations.

##### c. **Reporting**
- Each step writes raw output and analysis to both `OsintIA_report.txt` (plain text) and `OsintIA_report.html` (formatted with sections and links).
- The HTML report includes an index linking to each section.

##### d. **Final Conclusion**
- Reads the full TXT report and generates a static summary recommending basic security measures (e.g., "secure exposed services").

#### 7. **Execution**
- **`if __name__ == "__main__":`**: Runs `main()` with the provided domain argument.

---

### How to Use It
1. **Install**: Ensure all tools are installed (run with `sudo` the first time).
2. **Run**: `python3 osint_tools.py example.com`.
3. **Review**: Check `OsintIA_report.txt` and open `OsintIA_report.html` in a browser.

### Example Workflow
- Input: `python3 osint_tools.py example.com`
- Process:
  - Resolves IP (e.g., `192.0.2.1`).
  - Scans ports (e.g., "80/tcp open").
  - Finds subdomains (e.g., `sub.example.com`).
  - Analyzes: Flags "open port" as a potential issue.
- Output: TXT and HTML files with findings and basic analysis.

This script is now fully free, relying solely on open-source tools and local processing. Let me know if you want to refine it further!
