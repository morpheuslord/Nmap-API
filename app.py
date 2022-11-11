from flask import Flask, request
import subprocess
import json
import xmltodict
import lxml
import sqlite3
from lxml import etree
from flask_restful import Api, Resource

app = Flask(__name__)
api = Api(app)


# User Database Implimentation
def db_connection():
    conn = None
    try:
        conn = sqlite3.connect("db.sqlite")
    except sqlite3.error as e:
        print(e)
    return conn

# Add Userdata
@app.route('/adduser/<uid>/<username>/<passwd>', methods=['POST'])
def add_user(uid, username, passwd):
    conn = db_connection()
    cursor = conn.cursor()
    new_id = uid
    new_user = username
    new_passwd = passwd
    sql = """INSERT INTO users (id, username, passwd) VALUES (?, ?, ?)"""
    cursor = cursor.execute(sql, (new_id, new_user, new_passwd))
    conn.commit()
    return f'["added": {[{"ID":new_id}], [{"Username":new_user}], [{"Password": new_passwd}]} ]'

@app.route('/altusername/<uid>/<username>', methods=['POST'])
def alt_user(uid, username):
    conn = db_connection()
    cursor = conn.cursor()
    new_id = uid
    new_user = username
    sql = """UPDATE users SET (username=?) WHERE id=?"""
    cursor = cursor.execute(sql, (new_user, new_id))
    conn.commit()
    return f'Updated {[{new_id : new_user}]} '

@app.route('/altpasswd/<username>/<passwd>', methods=['POST'])
def alt_passwd(username, passwd):
    conn = db_connection()
    cursor = conn.cursor()
    new_user = username
    new_passwd = passwd
    sql = """UPDATE users SET passwd=? WHERE username=?"""
    cursor = cursor.execute(sql, ( new_passwd, new_user))
    conn.commit()
    return f'Updated {[{new_user : new_passwd}]} '

@app.route('/altid/<uid>/<usern>', methods=['POST'])
def alt_id(uid, usern):
    conn = db_connection()
    cursor = conn.cursor()
    new_id = uid
    username = usern
    sql = """UPDATE users SET id=? WHERE username=?"""
    cursor = cursor.execute(sql, ( new_id, username))
    conn.commit()
    return f'Updated {[{new_id : username}]} '


@app.route('/deluser/<uname>/<upass>', methods=['POST'])
def deluser(uname, upass):
    conn = db_connection()
    cursor = conn.cursor()
    username = uname
    passwd = upass
    sql = """DELETE from users where username=? AND passwd=?"""
    cursor = cursor.execute(sql, (username, passwd))
    conn.commit()
    return f'Removed {[{"Username":username}]} '

# class altpasswd2(Resource):
#     def POST(self, username, password):
#         conn = db_connection()
#         cursor = conn.cursor()
#         new_user = request.form[username]
#         new_passwd = request.form[password]
#         sql = """UPDATE users SET passwd=? WHERE username=?"""
#         cursor = cursor.execute(sql, ( new_passwd, new_user))
#         conn.commit()
#         return f'added {cursor.lastrowid} '

# def user_auth(username, password):
#     conn = db_connection()
#     cursor = conn.cursor()
#     sql = """ SELECT COUNT(*) FROM users WHERE username = ? AND passwd = ?"""
#     usernamecheck = cursor.execute(sql, (username,password))
#     # usernamecheck = cursor.execute("SELECT COUNT(*) FROM users WHERE username = :username AND password = :password", username=username, password=password)
#     print(usernamecheck)
#     if usernamecheck is None:
#         return 400
#     else:
#         return 200

# Effective  Scan
class p1(Resource):
    def get(self, username, password, url):
        ip = url
        # Nmap Execution command
        conn = db_connection()
        cursor = conn.cursor()
        sql = """ SELECT username, passwd FROM users WHERE username = ? AND passwd = ?"""
        usernamecheck = cursor.execute(sql, (username,password))
        if not usernamecheck.fetchone():
            return [{"error":"passwd or username error"}]
        else:
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
    def get(self, username, password, url):
        ip = url
        # Nmap Execution command
        conn = db_connection()
        cursor = conn.cursor()
        sql = """ SELECT COUNT(*) FROM users WHERE username = ? AND passwd = ?"""
        usernamecheck = cursor.execute(sql, (username,password))
        if not usernamecheck.fetchone():
            return [{"error":"passwd or username error"}]
        else:
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
    def get(self, username, password, url):
        ip = url
        # Nmap Execution command
        conn = db_connection()
        cursor = conn.cursor()
        sql = """ SELECT COUNT(*) FROM users WHERE username = ? AND passwd = ?"""
        usernamecheck = cursor.execute(sql, (username,password))
        if not usernamecheck.fetchone():
            return [{"error":"passwd or username error"}]
        else:
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
    def get(self, username, password, url):
        ip = url
        # Nmap Execution command
        conn = db_connection()
        cursor = conn.cursor()
        sql = """ SELECT COUNT(*) FROM users WHERE username = ? AND passwd = ?"""
        usernamecheck = cursor.execute(sql, (username,password))
        if not usernamecheck.fetchone():
            return [{"error":"passwd or username error"}]
        else:
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
    def get(self, username, password, url):
        ip = url
        # Nmap Execution command
        conn = db_connection()
        cursor = conn.cursor()
        sql = """ SELECT COUNT(*) FROM users WHERE username = ? AND passwd = ?"""
        usernamecheck = cursor.execute(sql, (username,password))
        if not usernamecheck.fetchone():
            return [{"error":"passwd or username error"}]
        else:
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


api.add_resource(p1, "/api/p1/<string:username>:<string:password>/<string:url>")
api.add_resource(p2, "/api/p2/<string:username>:<string:password>/<string:url>")
api.add_resource(p3, "/api/p3/<string:username>:<string:password>/<string:url>")
api.add_resource(p4, "/api/p4/<string:username>:<string:password>/<string:url>")
api.add_resource(p5, "/api/p5/<string:username>:<string:password>/<string:url>")
# api.add_resource(altpasswd2, "/altpasswd2/<string:username>/<string:password>")

if __name__ == '__main__':
    app.run(host="127.0.0.1", port="5010")