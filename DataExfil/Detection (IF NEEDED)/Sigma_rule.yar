title: DNS Exfiltration
description: Detects base64 in DNS queries
logsource:
    category: dns
detection:
    keywords:
        - "*.example.com"
    condition: keywords