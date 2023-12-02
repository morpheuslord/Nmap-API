from flask import Flask
from flask_restful import Api, Resource
import nmap

app = Flask(__name__)
api = Api(app)
nm = nmap.PortScanner()


def get_scan_argument(scan_type):
    scan_args = {
        "p1": '-Pn -sV -T4 -O -F',
        "p2": '-Pn -T4 -A -v',
        "p3": '-Pn -sS -sU -T4 -A -v',
        "p4": '-Pn -p- -T4 -A -v',
        "p5": '-Pn -sS -sU -T4 -A -PE -PP -PY -g 53 --script=vuln',
        "p6": '-Pn -sV -p- -A',
        "p7": '-Pn -sS -sV -O -T4 -A',
        "p8": '-Pn -sC',
        "p9": '-Pn -p 1-65535 -T4 -A -v',
        "p10": '-Pn -sU -T4',
        "p11": '-Pn -sV --top-ports 100',
        "p12": '-Pn -sS -sV -T4 --script=default,discovery,vuln',
        "p13": '-Pn -F'
    }
    return scan_args.get(scan_type, '-Pn -T4 -A -v')


class ScanAPI(Resource):
    def get(self, scan_type, url):
        argument = get_scan_argument(scan_type)
        nm.scan(url, arguments=argument)
        scan_data = nm.analyse_nmap_xml_scan()
        return scan_data


api.add_resource(ScanAPI, "/api/<string:scan_type>/<string:url>")

if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
