const questions = [
    {
      question: "During a penetration test engagement, your team has discovered multiple potential vulnerabilities in the target environment through initial scanning and enumeration. Which approach would be MOST appropriate for preparing for the next logical step you should take?",
      options: [
        "Update rules of engagement.",
        "Generate an automated scan report.",
        "Document your findings in vulnerability tracking system.",
        "Create an attack tree diagram."
      ],
      answer: ["Create an attack tree diagram."]
    },
    {
      question: "A penetration tester has been hired to test a global bank's wireless network. During reconnaissance, the tester discovers three SSIDs. Before initiating tests against the networks, the tester consults the statement of work for the project. Which statement describes the reason for the tester's actions?",
      options: [
        "The tester is determining what time the testing can begin.",
        "The tester is determining which networks are in scope.",
        "The tester is determining how to escalate testing issues.",
        "The tester is determining which type of tests are allowed."
      ],
      answer: ["The tester is determining which networks are in scope."]
    },
    {
      question: "A penetration tester is conducting a security assessment for a large financial institution and receives the following output from their reconnaissance tools: Based on the output, which of the following targets should be prioritized as the highest-value asset?",
      options: [
        "Network monitoring system",
        "Core banking application server",
        "Developer workstation",
        "Domain controller"
      ],
      answer: ["Core banking application server"]
    },
    {
      question: "After performing an extensive network scan of a client's infrastructure, a penetration tester needs to verify the scan's completeness before proceeding with vulnerability analysis. Which approach would be MOST effective in validating scan completeness?",
      options: [
        "Monitor system resource utilization during scans.",
        "Configure automated scan scheduling.",
        "Compare scan results across multiple tools and protocols.",
        "Review scan timestamps and duration metrics."
      ],
      answer: ["Compare scan results across multiple tools and protocols."]
    },
    {
      question: "A penetration tester uses an nmap script to return the partial output shown below: What is the tester attempting to perform?",
      options: [
        "Robots.txt inspection",
        "DNS spoofing",
        "A DNS zone transfer",
        "Hostname enumeration"
      ],
      answer: ["Hostname enumeration"]
    },
    {
      question: "During a security assessment of a client's website, a penetration tester discovers the target is running WordPress. They need to identify vulnerable plugins, themes, and user accounts that could be exploited. Which tool would be MOST effective for performing a comprehensive WordPress security assessment?",
      options: [
        "Joomscan with enumeration mode",
        "WPScan with API integration",
        "Nikto with CMS detection",
        "CMSmap with default credentials"
      ],
      answer: ["WPScan with API integration"]
    },
    {
      question: "While performing a wireless network assessment at a large corporate office, a penetration tester needs to identify potential rogue access points and analyze Wi-Fi channel usage. Which tool is MOST effective for wireless channel scanning and signal analysis?",
      options: [
        "Nmap with the -ss flag",
        "TCP dump",
        "Kismet",
        "Burp Suite Professional"
      ],
      answer: ["Kismet"]
    },
    {
      question: "A security team needs to implement continuous security testing during the development of a new financial application. The application handles sensitive customer data, and the team wants to use agents within the application to detect vulnerabilities while the application is running in a test environment. Which testing approach would be MOST effective in identifying security issues during runtime?",
      options: [
        "Dynamic Application Security Testing (DAST)",
        "Interactive Application Security Testing (IAST)",
        "Software Composition Analysis (SCA)",
        "Static Application Security Testing (SAST)"
      ],
      answer: ["Interactive Application Security Testing (IAST)"]
    },
    {
      question: "While performing a test against an API, a penetration tester crafts an API request and receives the response below: What should the tester do NEXT?",
      options: [
        "Specify an account with the correct permissions.",
        "Correct the syntax error in the original API request.",
        "Format the payload in the request properly.",
        "Provide credentials when making the API request."
      ],
      answer: ["Specify an account with the correct permissions."]
    },
    {
      question: "A penetration tester runs a command and receives the following output: Which statement describes the tester's actions?",
      options: [
        "The tester is enumerating service principal names (SPNs) from Microsoft Active Directory.",
        "The tester is using a stolen hash to authenticate as a different user.",
        "The tester is performing a brute force password attack on a user account.",
        "The tester is applying a hashing algorithm to a Windows executable."
      ],
      answer: ["The tester is using a stolen hash to authenticate as a different user."]
    },
    {
      question: "A penetration tester has been tasked with determining if an employee with privileged access can remove intellectual property from the network through covert channels and avoid detection. Which method would the tester MOST likely use accomplish this task?",
      options: [
        "ICMP tunneling",
        "ARP spoofing",
        "Port scanning",
        "SYN Flood"
      ],
      answer: ["ICMP tunneling"]
    },
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
    {
      question: "Which statement explains why a penetration tester would receive the following output during a reconnaissance exercise?",
      options: [
        "The tester ran the nmap -O command.",
        "The tester ran the nmap -Pn command.",
        "The tester ran the nmap -ST command.",
        "The tester ran the nmap -sv command."
      ],
      answer: ["The tester ran the nmap -O command."]
    },
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
    {
      question: "During reconnaissance of a client's wireless network, a penetration tester encounters a captive portal page. Based on this finding, what should the tester do NEXT?",
      options: [
        "Attempt an on-path attack.",
        "Perform DNS spoofing.",
        "Try a buffer overflow attack.",
        "Initiate a DoS attack."
      ],
      answer: ["Attempt an on-path attack."]
    },
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
    {
      question: "A penetration tester needs to validate and analyze results from multiple scanning tools across a large network assessment. Which scripting approaches would be most effective for processing and correlating the scan output data? (Select TWO).",
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
    {
      question: "A penetration test has compromised a workstation within a Windows network. To establish remote code execution on a second machine for lateral movement, the penetration tester decides to execute a malicious payload named malicious.exe on a remote system with IP address 192.168.1.5 using Windows Management Instrumentation (WMI). Which command should the tester use?",
      options: [
        "wmic [node:'192.168.1.5' process call create 'malicious.exe']",
        "wmic /node:'192.168.1.5' service call startservice 'malicious.exe'",
        "wmic /node:'192.168.1.5' process where name='malicious.exe' call start",
        "wmic /node:'192.168.1.5' process call create 'cmd.exe /c malicious.exe'"
      ],
      answer: ["wmic /node:'192.168.1.5' process call create 'cmd.exe /c malicious.exe'"]
    }
  ];
  