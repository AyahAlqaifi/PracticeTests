const questions = [
    {
        question: "A penetration tester needs to confirm the version number of a client's web application server. Which of the following techniques should the penetration tester use?",
        options: [
            "A. SSL certificate inspection",
            "B. URL spidering",
            "C. Banner grabbing",
            "D. Directory brute forcing"
        ],
        answer: "C. Banner grabbing"
    },
    {
        question: "A penetration tester downloads a JAR file that is used in an organization's production environment. The tester evaluates the contents of the JAR file to identify potentially vulnerable components that can be targeted for exploit. Which of the following describes the tester's activities?",
        options: [
            "A. SAST",
            "B. SBOM",
            "C. ICS",
            "D. SCA"
        ],
        answer: "D. SCA"
    },
    {
        question: "A penetration tester performs a service enumeration process and receives the following result after scanning a server using the Nmap tool:\nPORT STATE SERVICE\n22/tcp open ssh\n25/tcp filtered smtp\n111/tcp open rpcbind\n2049/tcp open nfs\nBased on the output, which of the following services provides the best target for launching an attack?",
        options: [
            "A. Database",
            "B. Remote access",
            "C. Email",
            "D. File sharing"
        ],
        answer: "D. File sharing"
    },
    {
        question: "Which of the following components should a penetration tester include in an assessment report?",
        options: [
            "A. User activities",
            "B. Customer remediation plan",
            "C. Key management",
            "D. Attack narrative"
        ],
        answer: "D. Attack narrative"
    },
    {
        question: "During a security assessment, a penetration tester needs to exploit a vulnerability in a wireless network's authentication mechanism to gain unauthorized access to the network. Which of the following attacks would the tester most likely perform to gain access?",
        options: [
            "A. KARMA attack",
            "B. Beacon flooding",
            "C. MAC address spoofing",
            "D. Eavesdropping"
        ],
        answer: "A. KARMA attack"
    },
    {
        question: "A penetration tester gains initial access to a target system by exploiting a recent RCE vulnerability. The patch for the vulnerability will be deployed at the end of the week. Which of the following utilities would allow the tester to reenter the system remotely after the patch has been deployed? (Select two).",
        options: [
            "A. schtasks.exe",
            "B. rundll.exe",
            "C. cmd.exe",
            "D. chgusr.exe",
            "E. sc.exe",
            "F. netsh.exe"
        ],
        answer: ["A. schtasks.exe", "E. sc.exe"]
    },
    {
        question: "A penetration tester needs to complete cleanup activities from the testing lead. Which of the following should the tester do to validate that reverse shell payloads are no longer running?",
        options: [
            "A. Run scripts to terminate the implant on affected hosts.",
            "B. Spin down the C2 listeners.",
            "C. Restore the firewall settings of the original affected hosts.",
            "D. Exit from C2 listener active sessions."
        ],
        answer: "A. Run scripts to terminate the implant on affected hosts."
    },
    {
        question: "A penetration tester creates a list of target domains that require further enumeration. The tester writes the following script to perform vulnerability scanning across the domains:\nline 1: #!/usr/bin/bash\nline 2: DOMAINS_LIST = \"/path/to/list.txt\"\nline 3: while read -r i; do\nline 4: nikto -h $i -o scan-$i.txt &\nline 5: done\nThe script does not work as intended. Which of the following should the tester do to fix the script?",
        options: [
            "A. Change line 2 to {\"domain1\", \"domain2\", \"domain3\", }.",
            "B. Change line 3 to while true; read -r i; do.",
            "C. Change line 4 to nikto $i | tee scan-$i.txt.",
            "D. Change line 5 to done < \"$DOMAINS_LIST\"."
        ],
        answer: "D. Change line 5 to done < \"$DOMAINS_LIST\"."
    },
    {
        question: "A penetration tester is performing network reconnaissance. The tester wants to gather information about the network without causing detection mechanisms to flag the reconnaissance activities. Which of the following techniques should the tester use?",
        options: [
            "A. Sniffing",
            "B. Banner grabbing",
            "C. TCP/UDP scanning",
            "D. Ping sweeps"
        ],
        answer: "A. Sniffing"
    },
    {
        question: "During a penetration test, the tester gains full access to the application's source code. The application repository includes thousands of code files. Given that the assessment timeline is very short, which of the following approaches would allow the tester to identify hard-coded credentials most effectively?",
        options: [
            "A. Run TruffleHog against a local clone of the application",
            "B. Scan the live web application using Nikto",
            "C. Perform a manual code review of the Git repository",
            "D. Use SCA software to scan the application source code"
        ],
        answer: "A. Run TruffleHog against a local clone of the application"
    }
];
