import ctypes
import signal
import datetime
import threading
import subprocess
import pwd
import sqlite3
from html import escape, unescape

import os
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gio

iconCache={}

def resolve_icon_path(filename, iconSize = -1):
    if filename in iconCache.keys():
        return iconCache[filename]
    iconName=filename.split('/')[-1]
    iconTheme = Gtk.IconTheme.get_default()
    if iconSize >= 16:
        iconFile = iconTheme.lookup_icon(iconName, iconSize, 0)
        if iconFile:
            iconCache[filename]=iconFile.get_filename()
            return iconFile.get_filename()
    else:
        for resolution in [16, 20, 22, 24, 28, 32, 36, 48, 64, 72, 96, 128, 192, 256, 480, 512, 1024]:
            iconFile = iconTheme.lookup_icon(iconName, resolution, 0)
            if iconFile:
                iconCache[filename]=iconFile.get_filename()
                return iconFile.get_filename()
    if os.path.exists(filename):
        file = Gio.File.new_for_path(filename)
        info = file.query_info('standard::icon' , 0 , Gio.Cancellable())
        icon = info.get_icon().get_names()[0]

        icon_theme = Gtk.IconTheme.get_default()
        icon_file = icon_theme.lookup_icon(icon , 512 , 0)
        if icon_file != None:
            final_filename = icon_file.get_filename()
        iconCache[filename]=final_filename
        return final_filename

device_names = []

LIBRARY_NAME = 'libnethogs.so.0.8.6'
FILTER = None

if not os.path.exists(os.path.join(os.path.expanduser("~"), 'wiresnitch')):
    os.mkdir(os.path.join(os.path.expanduser("~"), 'wiresnitch'))
SQLconnection=sqlite3.connect(os.path.join(os.path.expanduser("~"), 'wiresnitch/storage.db'))
SQLcursor=SQLconnection.cursor()
try:
    td=SQLcursor.execute("SELECT path from connectionLogs;")
except:
    SQLcursor.execute("CREATE TABLE connectionLogs (ctime TEXT, path TEXT, args TEXT, programicon TEXT, sent FLOAT, received FLOAT, user TEXT, device TEXT, networkssid TEXT);")
    SQLcursor.execute('CREATE TABLE applicationLogs (activity TEXT, starttime TEXT);')
    SQLcursor.execute('CREATE TABLE applicationConfigs (key TEXT, value TEXT);')
    SQLcursor.execute('CREATE TABLE blacklistedApplications (path TEXT);')
    SQLconnection.commit()

SQLcursor.execute("INSERT INTO applicationLogs VALUES(\'MONITORING STARTED\', \'{}\');".format(datetime.datetime.now().timestamp()))
SQLconnection.commit()

SQLcursor.execute("SELECT path from blacklistedApplications;")
blacklistedApplications=set()
for i in SQLcursor.fetchall():
    blacklistedApplications.add(i[0])

SQLconnection.close()

def log_connection_to_sqlite(ctime, path, args, programicon, sent, received, user, device, networdssid):
    with sqlite3.connect(os.path.join(os.path.expanduser("~"), 'wiresnitch/storage.db')) as SQLconnection_:
        SQLcursor_=SQLconnection_.cursor()
        SQLcursor_.execute("INSERT INTO connectionLogs VALUES (\'{}\', \'{}\', \'{}\', \'{}\', {}, {}, \'{}\', \'{}\', \'{}\');".format(ctime, path, args, programicon, sent, received, user, device, networdssid))
        SQLconnection_.commit()

class Action():
    SET = 1
    REMOVE = 2

    MAP = {SET: 'SET', REMOVE: 'REMOVE'}

class LoopStatus():
    OK = 0
    FAILURE = 1
    NO_DEVICE = 2

    MAP = {OK: 'OK', FAILURE: 'FAILURE', NO_DEVICE: 'NO_DEVICE'}

class NethogsMonitorRecord(ctypes.Structure):
    _fields_ = (('record_id', ctypes.c_int),
                ('name', ctypes.c_char_p),
                ('pid', ctypes.c_int),
                ('uid', ctypes.c_uint32),
                ('device_name', ctypes.c_char_p),
                ('sent_bytes', ctypes.c_uint64),
                ('recv_bytes', ctypes.c_uint64),
                ('sent_kbs', ctypes.c_float),
                ('recv_kbs', ctypes.c_float),
                )

def signal_handler(signal, frame):
    print('SIGINT received; requesting exit from monitor loop.')
    lib.nethogsmonitor_breakloop()

def remove_args(filename):
    fargs=" ".join(filename.split("/")[-1].split(" ")[1:])
    fname=filename.replace(fargs, '')
    while '--' in fname:
        t=fname.split('--')
        fname=t[0]
        fargs="--".join(t[1:])+" "+fargs
    fname=fname.strip()
    return fname, fargs

def get_wifi_network_ssid(devicename):
    output=subprocess.check_output('iwconfig | grep {}'.format(devicename), shell=True, text=True)
    for line in output.split(" "):
        if 'ESSID' in line:
            return line.split(":")[-1].rstrip("\"").lstrip("\"")
    return None

def get_user_name(uid):
    return pwd.getpwuid(uid).pw_name

def dev_args(devnames):
    devc = len(devnames)
    devnames_type = ctypes.c_char_p * devc
    devnames_arg = devnames_type()
    for idx, val in enumerate(devnames):
        devnames_arg[idx] = (val + chr(0)).encode('ascii')
    return ctypes.c_int(devc), ctypes.cast(
        devnames_arg, ctypes.POINTER(ctypes.c_char_p)
    )

def run_monitor_loop(lib, devnames):
    CALLBACK_FUNC_TYPE = ctypes.CFUNCTYPE(
        ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(NethogsMonitorRecord)
    )

    filter_arg = FILTER
    if filter_arg is not None:
        filter_arg = ctypes.c_char_p(filter_arg.encode('ascii'))

    if len(devnames) < 1:
        # monitor all devices
        rc = lib.nethogsmonitor_loop(
            CALLBACK_FUNC_TYPE(network_activity_callback),
            filter_arg
        )
    else:
        devc, devicenames = dev_args(devnames)
        rc = lib.nethogsmonitor_loop_devices(
            CALLBACK_FUNC_TYPE(network_activity_callback),
            filter_arg,
            devc,
            devicenames,
            ctypes.c_bool(False)
        )

    if rc != LoopStatus.OK:
        print('nethogsmonitor_loop returned {}'.format(LoopStatus.MAP[rc]))
    else:
        print('exiting monitor loop')
        with sqlite3.connect(os.path.join(os.path.expanduser("~"), 'wiresnitch/storage.db')) as SQLconnection_:
            SQLcursor_=SQLconnection_.cursor()
            SQLcursor_.execute('INSERT INTO applicationLogs VALUES(\'MONITOR EXITED DUE TO LOOPBREAK\', \'{}\');'.format(datetime.datetime.now().timestamp()))


def network_activity_callback(action, data):
    print(datetime.datetime.now().strftime('%m/%d/%Y, %H:%M:%S'))

    action_type = Action.MAP.get(action, 'Unknown')

    print('Action: {}'.format(action_type))
    print('Record id: {}'.format(data.contents.record_id))
    print('Name: {}'.format(data.contents.name.decode()))
    filename, args=remove_args(data.contents.name.decode())
    print('Icon Path: {}'.format(resolve_icon_path(filename)))
    print('PID: {}'.format(data.contents.pid))
    print('UID: {}'.format(data.contents.uid))
    print('Device name: {}'.format(data.contents.device_name.decode('ascii')))
    if len(data.contents.device_name.decode('ascii'))>0 and data.contents.device_name.decode('ascii')[0]=='w':
        print('Network name: {}'.format(get_wifi_network_ssid(data.contents.device_name.decode('ascii'))))
    print('Sent/Recv bytes: {} / {}'.format(data.contents.sent_bytes, data.contents.recv_bytes))
    print('Sent/Recv kbs: {} / {}'.format(data.contents.sent_kbs, data.contents.recv_kbs))
    print('-' * 30)

    if len(data.contents.device_name.decode('ascii'))>0 and data.contents.device_name.decode('ascii')[0]=='w':
        network_ssid=get_wifi_network_ssid(data.contents.device_name.decode('ascii'))
    else:
        network_ssid=''
    
    if data.contents.pid==0 and data.contents.name.decode()=='Unknown TCP':
        return
    
    log_connection_to_sqlite(datetime.datetime.now().timestamp(), escape(filename), escape(args), escape(str(resolve_icon_path(filename))), data.contents.sent_bytes, data.contents.recv_bytes, get_user_name(data.contents.uid), data.contents.device_name.decode('ascii'), escape(network_ssid))
    if filename in blacklistedApplications:
        os.system("notify-send -u normal \"A black-listed application connected to the internet.\n{} connected sent {} bytes and received {} bytes.\"".format(data.contents.name.decode(), data.contents.sent_bytes, data.contents.recv_bytes))

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

lib = ctypes.CDLL(LIBRARY_NAME)

monitor_thread = threading.Thread(
    target=run_monitor_loop, args=(lib, device_names,)
)

monitor_thread.start()

done = False
while not done:
    monitor_thread.join(0.3)
    done = not monitor_thread.is_alive()