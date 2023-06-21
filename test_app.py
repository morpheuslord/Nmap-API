from app import chunk_output

data = """
{
    "127.0.0.1": {
        "hostnames": [
            {
                "name": "kubernetes.docker.internal",
                "type": "PTR"
            }
        ],
        "addresses": {
            "ipv4": "127.0.0.1"
        },
        "vendor": {},
        "status": {
            "state": "up",
            "reason": "user-set"
        },
        "uptime": {
            "seconds": "130186",
            "lastboot": "Sun Jun 18 20:15:24 2023"
        },
        "tcp": {
            "80": {
                "state": "open",
                "reason": "syn-ack",
                "name": "http",
                "product": "Werkzeug/2.2.3 Python/3.10.0",
                "version": "",
                "extrainfo": "",
                "conf": "10",
                "cpe": ""
            },
            "135": {
                "state": "open",
                "reason": "syn-ack",
                "name": "msrpc",
                "product": "Microsoft Windows RPC",
                "version": "",
                "extrainfo": "",
                "conf": "10",
                "cpe": "cpe:/o:microsoft:windows"
            },
            "445": {
                "state": "open",
                "reason": "syn-ack",
                "name": "microsoft-ds",
                "product": "",
                "version": "",
                "extrainfo": "",
                "conf": "3",
                "cpe": ""
            }
        },
        "portused": [
            {
                "state": "open",
                "proto": "tcp",
                "portid": "80"
            },
            {
                "state": "closed",
                "proto": "tcp",
                "portid": "7"
            },
            {
                "state": "closed",
                "proto": "udp",
                "portid": "41433"
            }
        ],
        "osmatch": [
            {
                "name": "Microsoft Windows 10 1607",
                "accuracy": "100",
                "line": "69748",
                "osclass": [
                    {
                        "type": "general purpose",
                        "vendor": "Microsoft",
                        "osfamily": "Windows",
                        "osgen": "10",
                        "accuracy": "100",
                        "cpe": [
                            "cpe:/o:microsoft:windows_10:1607"
                        ]
                    }
                ]
            }
        ]
    }
}
"""
d = str(data)
return_d = chunk_output(d, 10)
print(return_d)
print(type(return_d))
