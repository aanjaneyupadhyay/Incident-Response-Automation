from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
import os
from django.core.files.storage import FileSystemStorage
import pymysql
from datetime import date
import numpy as np
import pyshark
import hashlib
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime
import traceback
import asyncio
loop = asyncio.ProactorEventLoop()
asyncio.set_event_loop(loop)

global uname, alertsList

def analyze_pcap(pcap_file):
    suspicious_packets = []
    try:
        capture = pyshark.FileCapture(pcap_file,eventloop=loop)
        for packet in capture:
            # Check for large packets (potential data exfiltration)
            if hasattr(packet, 'tcp'):
                try:
                    if int(packet.tcp.flags, 16) & 0x02 and not int(packet.tcp.flags, 16) & 0x10:
                        suspicious_packets.append((packet.number, "Unauthorised Access", packet.ip.src, packet.ip.dst, packet.tcp.srcport, packet.tcp.dstport))
                except Exception:
                    pass        
            if int(packet.length) > 1990:
                suspicious_packets.append((packet.number, "DDoS", "none", "none", "none", "none"))
            else:
                suspicious_packets.append((packet.number, "Normal", "none", "none", "none", "none"))
            # Check for unusual protocols or ports
            if 'IP' in packet:
                ip_packet = packet.ip
                if hasattr(packet, 'udp'):
                    if ip_packet.proto == '17' and int(packet.udp.dstport) > 1023:
                        suspicious_packets.append((packet.number, "Hack Attempt", packet.ip.src, packet.ip.dst, packet.udp.srcport, packet.udp.dstport))
                if hasattr(packet, 'proto'):
                    if ip_packet.proto == '6':
                        if int(packet.tcp.dstport) not in [21, 22, 23, 80, 443, 3389]:
                            suspicious_packets.append((packet.number, "Hack Attempt", packet.ip.src, packet.ip.dst, packet.tcp.srcport, packet.tcp.dstport))

            # Check for HTTP traffic with potentially malicious content
            if 'HTTP' in packet:
                http_packet = packet.http
                if hasattr(http_packet, 'file_data'):
                  file_hash = hashlib.sha256(http_packet.file_data.raw_value.encode()).hexdigest()
                  suspicious_packets.append((packet.number, "Virus Attack", packet.ip.src, packet.ip.dst, packet.tcp.srcport, packet.tcp.dstport))        
    except Exception:
        pass
    return suspicious_packets

def AlertAnalysis(request):
    if request.method == 'GET':
        global alertsList
        data = []
        for key, value in alertsList.items():
            if key == 'DDoS':
                data.append([key, value*100])
            else:
                data.append([key, value])
        data = pd.DataFrame(data, columns=['Cyber Alert', 'Detected Count'])
        print(data)
        plt.figure(figsize=(6,3))
        sns.barplot(data=data,x="Cyber Alert", y="Detected Count")
        plt.title("Different Alerts Analysis Graph")
        plt.xticks(rotation=70)
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        #plt.close()
        img_b64 = base64.b64encode(buf.getvalue()).decode()
        plt.clf()
        plt.cla()
        context= {'data':'<font size="3" color="blue">Cyber Attack Analysis Graph</font>', 'img': img_b64}     
        return render(request, 'UserScreen.html', context)
        

def AnalyzeTrafficAction(request):
    if request.method == 'POST':
        global alertsList
        alertsList = {}
        filename = request.FILES['t1'].name
        myfile = request.FILES['t1'].read()
        if os.path.exists("ResponseApp/static/"+filename):
            os.remove("ResponseApp/static/"+filename)
        with open("ResponseApp/static/"+filename, "wb") as file:
            file.write(myfile)
        file.close()
        suspicious = analyze_pcap("ResponseApp/static/"+filename)
        output = '<table border=1 align=center>'
        output+='<tr><th><font size=3 color=black>Packet No</font></th>'
        output+='<th><font size=3 color=black>Description</font></th>'
        output+='<th><font size=3 color=black>Source IP</font></th>'
        output+='<th><font size=3 color=black>Destination IP</font></th>'
        output+='<th><font size=3 color=black>Source Port</font></th>'
        output+='<th><font size=3 color=black>Destination Port</font></th>'
        output+='<th><font size=3 color=black>Destination Port</font></th></tr>'
        for i in range(len(suspicious)):
            data = suspicious[i]
            if data[1] in alertsList.keys():
                alertsList[data[1]] = alertsList.get(data[1]) + 1
            else:
                alertsList[data[1]] = 1
            output+='<tr><td><font size=3 color=black>'+data[0]+'</font></td>'
            output+='<td><font size=3 color=black>'+data[1]+'</font></td>'
            output+='<td><font size=3 color=black>'+data[2]+'</font></td>'
            output+='<td><font size=3 color=black>'+data[3]+'</font></td>'
            output+='<td><font size=3 color=black>'+data[4]+'</font></td>'
            output+='<td><font size=3 color=black>'+data[5]+'</font></td>'
            if data[1] == "Normal":
                output+='<td><font size=3 color=green>Access Allowed</font></td></tr>'
            else:
                output+='<td><font size=3 color=red>Access Blocked</font></td></tr>'    
        output += "</table><br/><br/><br/><br/>"
        context= {'data':output}        
        return render(request,'UserScreen.html', context)              

def DetectionAnalysis(request):
    if request.method == 'GET':
       return render(request, 'DetectionAnalysis.html', {})

def UserLogin(request):
    if request.method == 'GET':
       return render(request, 'UserLogin.html', {})  

def index(request):
    if request.method == 'GET':
       return render(request, 'index.html', {})

def Register(request):
    if request.method == 'GET':
       return render(request, 'Register.html', {})

def UserLoginAction(request):
    if request.method == 'POST':
        global uname
        username = request.POST.get('username', False)
        password = request.POST.get('password', False)
        page = "UserLogin.html"
        status = "Invalid login"
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'incident',charset='utf8')
        with con:
            cur = con.cursor()
            cur.execute("select username,password FROM register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == username and password == row[1]:
                    uname = username
                    status = "Welcome "+username
                    page = "UserScreen.html"
                    break		
        context= {'data': status}
        return render(request, page, context)

def RegisterAction(request):
    if request.method == 'POST':
        username = request.POST.get('username', False)
        password = request.POST.get('password', False)
        contact = request.POST.get('contact', False)
        email = request.POST.get('email', False)
        address = request.POST.get('address', False)
        output = "none"
        con = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'incident',charset='utf8')
        with con:
            cur = con.cursor()
            cur.execute("select username FROM register")
            rows = cur.fetchall()
            for row in rows:
                if row[0] == username:
                    output = username+" Username already exists"
                    break
        if output == 'none':
            db_connection = pymysql.connect(host='127.0.0.1',port = 3306,user = 'root', password = '', database = 'incident',charset='utf8')
            db_cursor = db_connection.cursor()
            student_sql_query = "INSERT INTO register VALUES('"+username+"','"+password+"','"+contact+"','"+email+"','"+address+"')"
            db_cursor.execute(student_sql_query)
            db_connection.commit()
            print(db_cursor.rowcount, "Record Inserted")
            if db_cursor.rowcount == 1:
                output = 'Signup Process Completed'
        context= {'data':output}
        return render(request, 'Register.html', context)
      
