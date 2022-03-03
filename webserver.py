from flask import Flask, render_template, request, redirect
from threading import Thread
import sys
import os
import sqlite3
import webview
import datetime
from html import escape, unescape
import urllib.parse
import random

appSecret=str(random.randint(111111, 999999))
app=Flask(__name__)
window=None

def get_blacklisted_applications():
    with sqlite3.connect(os.path.join(os.path.expanduser("~"), 'wiresnitch/storage.db')) as SQLconnection:
        SQLcursor=SQLconnection.cursor()
        SQLcursor.execute('SELECT path FROM blacklistedApplications;')
        d=SQLcursor.fetchall()
        return d

def get_usage_access_by_application(timeframeStart=0, timeframeEnd=253402261199):
    if timeframeStart==None:
        timeframeStart=0
    if timeframeEnd==None:
        timeframeEnd=253402261199
    with sqlite3.connect(os.path.join(os.path.expanduser("~"), 'wiresnitch/storage.db')) as SQLconnection:
        SQLcursor=SQLconnection.cursor()
        SQLcursor.execute('SELECT path, programicon, SUM(sent), SUM(received) FROM connectionLogs WHERE ctime BETWEEN {} and {} GROUP BY path;'.format(timeframeStart, timeframeEnd))
        d=SQLcursor.fetchall()
        return d

def get_total_send_receive_in_bytes(application=None):
    with sqlite3.connect(os.path.join(os.path.expanduser("~"), "wiresnitch/storage.db")) as SQLconnection:
        SQLcursor=SQLconnection.cursor()
        if application==None:
            SQLcursor.execute('SELECT SUM(sent), SUM(received) FROM connectionLogs;')
        else:
            SQLcursor.execute('SELECT SUM(sent), SUM(received) FROM connectionLogs WHERE path=\'{}\';'.format(escape(application)))
        d=SQLcursor.fetchall()
        return d

def get_full_application_usage(application, timeframeStart=0, timeframeEnd=253402261199):
    if timeframeStart==None:
        timeframeStart=0
    if timeframeEnd==None:
        timeframeEnd=253402261199
    with sqlite3.connect(os.path.join(os.path.expanduser("~"), "wiresnitch/storage.db")) as SQLconnection:
        SQLcursor=SQLconnection.cursor()
        SQLcursor.execute('SELECT ctime, path, args, programicon, sent, received, user, device, networkssid FROM connectionLogs WHERE ctime BETWEEN {} and {} AND path=\'{}\''.format(timeframeStart, timeframeEnd, escape(application)))
        d=SQLcursor.fetchall()
        return d

def getAlerts():
    with sqlite3.connect(os.path.join(os.path.expanduser("~"), "wiresnitch/storage.db")) as SQLconnection:
        SQLcursor=SQLconnection.cursor()
        alertsList=[]
        SQLcursor.execute("SELECT path FROM blacklistedApplications;")
        for i in SQLcursor.fetchall():
            SQLcursor.execute('SELECT ctime, path, args, programicon, sent, received, user, device, networkssid FROM connectionLogs WHERE path=\'{}\''.format(escape(i[0])))
            d=SQLcursor.fetchall()
            newd=[]
            for x in d:
                newd.append([str(datetime.datetime.fromtimestamp(int(x[0].split(".")[0])))]+list(x[1:]))
            alertsList.append(newd)
        return alertsList

def remove_from_blacklist(path):
    with sqlite3.connect(os.path.join(os.path.expanduser("~"), "wiresnitch/storage.db")) as SQLconnection:
        SQLcursor=SQLconnection.cursor()
        SQLcursor.execute("DELETE FROM blacklistedApplications WHERE path=\'{}\';".format(path))
        SQLconnection.commit()

def add_to_blacklist(path):
    with sqlite3.connect(os.path.join(os.path.expanduser("~"), "wiresnitch/storage.db")) as SQLconnection:
        SQLcursor=SQLconnection.cursor()
        SQLcursor.execute("INSERT INTO blacklistedApplications VALUES(\'{}\');".format(path))
        SQLconnection.commit()

def validateAccess(request):
    tsecret=request.args.get('appSecret')
    return tsecret==appSecret

@app.route('/closeapp')
def closeapp_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    window.destroy()
    sys.exit()

@app.route('/')
def home_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    return render_template('home.html', appsecret=appSecret)

@app.route('/graph')
def graph_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    return render_template('graph.html', appsecret=appSecret)

@app.route('/alerts')
def alerts_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    try:
        alerts=getAlerts()
    except Exception as err:
        return {'error': str(err)}, 500
    return render_template('alerts.html', alerts=alerts, appsecret=appSecret)

@app.route('/blacklist')
def blacklist_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    return render_template('blacklist.html', blacklistedApplications=get_blacklisted_applications(), appsecret=appSecret)

@app.route('/blacklist/remove/')
def remove_from_blacklist_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    applicationpath=request.args.get('application')
    applicationpath=urllib.parse.unquote(applicationpath)
    try:
        remove_from_blacklist(applicationpath)
    except Exception as err:
        return {'error': str(err)}, 500
    return render_template('blacklist.html', blacklistedApplication=get_blacklisted_applications(), appsecret=appSecret)

@app.route('/blacklist/add', methods=['POST'])
def add_to_blacklist_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    applicationpath=request.form.get('applicationpath')
    try:
        add_to_blacklist(applicationpath)
    except Exception as err:
        return {'error': str(err)}, 500
    return redirect('/blacklist?appSecret='+appSecret)

@app.route('/api/addToBlackList')
def addToBlackList_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    application=request.args.get('application')
    if application==None:
        return {'error': 'Please specify application.'}, 400
    with sqlite3.connect(os.path.join(os.path.expanduser("~"), "wiresnitch/storage.db")) as SQLconnection:
        SQLcursor=SQLconnection.cursor()
        SQLcursor.execute("INSERT INTO blacklistedApplications VALUES(\'{}\');".format(application))
        SQLconnection.commit()
    return {'message': 'Success'}, 200

@app.route('/api/getUsageByAllApplications/')
def getUsageByApplication_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    timeframeStart=request.args.get('timeframeStart')
    timeframeEnd=request.args.get('timeframeEnd')
    try:
        return {'result': get_usage_access_by_application(timeframeStart, timeframeEnd)}, 200
    except Exception as err:
        return {'error': str(err)}, 500

@app.route('/api/getTotalSendReceive')
def getTotalSendReceive_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    application=request.args.get('application')
    try:
        return {'result': get_total_send_receive_in_bytes(application)}, 200
    except Exception as err:
        return {'error': str(err)}, 500

@app.route('/api/getFullApplicationUsage')
def getFullApplicationUsage_web():
    if not validateAccess(request):
        return render_template('error.html', message="Not Authorised")
    application=request.args.get('application')
    timeframeStart=request.args.get('timeframeStart')
    timeframeEnd=request.args.get('timeframeEnd')
    if application==None:
        return {'error': 'Invalid Application Name'}, 400
    try:
        return {'result': get_full_application_usage(application, timeframeStart, timeframeEnd)}, 200
    except Exception as err:
        return {'error': str(err)}, 500


if __name__=="__main__":
    def start_server():
        app.run(host='0.0.0.0', port=6684)
    t=Thread(target=start_server)
    t.daemon=True
    t.start()
    window=webview.create_window('WireSnitch', 'http://localhost:6684/?appSecret='+appSecret, frameless=True)
    webview.start()
    sys.exit()