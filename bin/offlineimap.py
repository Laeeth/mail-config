#!/usr/bin/env python2
import os
import libkeepass

DYNAMO_DB = "~/.mutt/accounts/Dynamo.kdbx"
DYNAMO_KEY = "~/.mutt/accounts/keepass.key"
DYNAMO_PASS = "~/.mutt/accounts/password"


def get_keepass(method="user",
                dbpath=DYNAMO_DB, keypath=DYNAMO_KEY, passpath=DYNAMO_PASS,
                group_name="", title=""):
    # Get real path of each file
    dbpath = os.path.expanduser(dbpath)
    keypath = os.path.expanduser(keypath)
    passpath = os.path.expanduser(passpath)
    if os.path.islink(dbpath):
        dbpath = os.readlink(dbpath)
    if os.path.islink(keypath):
        keypath = os.readlink(keypath)
    if os.path.islink(passpath):
        keypath = os.readlink(passpath)
    if not os.path.isfile(dbpath):
        return ""
    try:
        # password = getpass.getpass("Password for '" + dbpath + "': ")
        with open(passpath, 'r') as file:
            password = file.readline().strip()
        if not password:
            credentials = {'keyfile': keypath}
        else:
            credentials = {'keyfile': keypath, 'password': password}
        with libkeepass.open(dbpath, **credentials) as kdbx:
            # Remove history to not show when search pass
            for history in kdbx.obj_root.findall('.//History'):
                history.getparent().remove(history)

            # Scan all group
            for group in kdbx.obj_root.findall('.//Group'):
                if group.find('./Name').text != group_name:
                    continue
                for entry in group.findall('.//Entry'):
                    if entry.find('.//String[Key="Title"]/Value').text \
                            != title:
                        continue
                    if method == "user":
                        return entry.find('.//String[Key="UserName"]/Value')\
                                .text
                    if method == "pass":
                        return entry.find('.//String[Key="Password"]/Value')\
                                .text
                    if method == "client_id":
                        r = entry.find('.//String[Key="Client ID"]/Value')
                        if r:
                            return r.text
                    if method == "client_secret":
                        r = entry.find('.//String[Key="Client Secret"]/Value')
                        if r:
                            return r.text
                    if method == "refresh_token":
                        r = entry.find('.//String[Key="Refresh Token"]/Value')
                        if r:
                            return r.text
                    if method == "app_pass":
                        r = entry.find('.//String[Key="Application Password"]'
                                       + '/Value')
                        if r:
                            return r.text
            return ""
    except IOError:
        print('Authentication is invalid')
        return ""
