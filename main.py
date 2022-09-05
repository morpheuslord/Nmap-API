from flask import Flask
import subprocess
import json
import xmltodict
import json2html
import lxml
from lxml import etree
from flask_restful import Api, Resource

app = Flask(__name__)
api = Api(app)


# Effective  Scan
class p1(Resource):
    def get(self, url):
        ip = url
        # Nmap Execution command
        command = 'nmap {} -Pn -sV -T4 -O -F -oX {}.xml'.format(ip, ip)
        subprocess.run(command, shell=True)
        # Xml Write
        scan_file = open("{}.xml".format(ip))
        scan_xml = scan_file.read()
        scan_file.close()
        xslt_doc = etree.parse("nmap.xsl")
        xslt_transformer = etree.XSLT(xslt_doc)
        source_doc = etree.parse("{}.xml".format(ip))
        output_doc = xslt_transformer(source_doc)
        output_doc.write("{}.html".format(ip), pretty_print=True)
        json_data = json.dumps(xmltodict.parse(scan_xml), indent=4, sort_keys=True)
        return json_data

# Simple Scan
class p2(Resource):
    def get(self, url):
        ip = url
        command = 'nmap {} -Pn -T4 -A -v -oX {}.xml'.format(ip, ip)
        subprocess.run(command, shell=True)
        scan_file = open("{}.xml".format(ip))
        scan_xml = scan_file.read()
        scan_file.close()
        xslt_doc = etree.parse("nmap.xsl")
        xslt_transformer = etree.XSLT(xslt_doc)
        source_doc = etree.parse("{}.xml".format(ip))
        output_doc = xslt_transformer(source_doc)
        output_doc.write("{}.html".format(ip), pretty_print=True)
        json_data = json.dumps(xmltodict.parse(scan_xml), indent=4, sort_keys=True)
        return json_data


# Low Power Scan
class p3(Resource):
    def get(self, url):
        ip = url
        command = 'nmap {} -Pn -sS -sU -T4 -A -v -oX {}.xml'.format(ip, ip)
        subprocess.run(command, shell=True)
        scan_file = open("{}.xml".format(ip))
        scan_xml = scan_file.read()
        scan_file.close()
        xslt_doc = etree.parse("nmap.xsl")
        xslt_transformer = etree.XSLT(xslt_doc)
        source_doc = etree.parse("{}.xml".format(ip))
        output_doc = xslt_transformer(source_doc)
        output_doc.write("{}.html".format(ip), pretty_print=True)
        json_data = json.dumps(xmltodict.parse(scan_xml), indent=4, sort_keys=True)
        return json_data

#partial Intense Scan
class p4(Resource):
    def get(self, url):
        ip = url
        command = 'nmap {} -Pn -p- -T4 -A -v -oX {}.xml'.format(ip, ip)
        subprocess.run(command, shell=True)
        scan_file = open("{}.xml".format(ip))
        scan_xml = scan_file.read()
        scan_file.close()
        xslt_doc = etree.parse("nmap.xsl")
        xslt_transformer = etree.XSLT(xslt_doc)
        source_doc = etree.parse("{}.xml".format(ip))
        output_doc = xslt_transformer(source_doc)
        output_doc.write("{}.html".format(ip), pretty_print=True)
        json_data = json.dumps(xmltodict.parse(scan_xml), indent=4, sort_keys=True)
        return json_data


# Complete Intense scan
class p5(Resource):
    def get(self, url):
        ip = url
        command = 'nmap {} -Pn -sS -sU -T4 -A -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script=vuln -oX {}.xml'.format(ip, ip)
        subprocess.run(command, shell=True)
        scan_file = open("{}.xml".format(ip))
        scan_xml = scan_file.read()
        scan_file.close()
        xslt_doc = etree.parse("nmap.xsl")
        xslt_transformer = etree.XSLT(xslt_doc)
        source_doc = etree.parse("{}.xml".format(ip))
        output_doc = xslt_transformer(source_doc)
        output_doc.write("{}.html".format(ip), pretty_print=True)
        json_data = json.dumps(xmltodict.parse(scan_xml), indent=4, sort_keys=True)
        return json_data


api.add_resource(p1, "/api/p1/<string:url>")
api.add_resource(p2, "/api/p2/<string:url>")
api.add_resource(p3, "/api/p3/<string:url>")
api.add_resource(p4, "/api/p4/<string:url>")
api.add_resource(p5, "/api/p5/<string:url>")

if __name__ == '__main__':
    app.run(debug=True)
