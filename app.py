# -*- coding: utf-8 -*-
# Copyright 2018 Alessio Gerace.
#
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).

import argparse
import json
import logging
import os
import uuid

import yaml
from flask import (Flask, request, render_template, redirect, session,
                   make_response, send_file, url_for, jsonify)

from urllib.parse import urlparse

from flask_login import (
    LoginManager,
    UserMixin,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_bootstrap import Bootstrap
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from config import *

from spid_saml import get_saml_auth, prepare_request

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SPID_SP_PUBLIC_CERT = os.path.join(BASE_DIR, 'saml/certs/sp.crt')
SPID_SP_PRIVATE_KEY = os.path.join(BASE_DIR, 'saml/certs/sp.key')

metadata_url_for = {}

app = Flask(__name__, static_folder='static')

Bootstrap(app)
app.secret_key = str(uuid.uuid4())  # Replace with your secret key

login_manager = LoginManager()
login_manager.init_app(app)

logging.basicConfig(level=logging.DEBUG)
spConfig = None
user_store = {}

app.config['SAML_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'saml')

ATTRIBUTES_MAP = {
    'familyName': 'last_name',
    'name': 'first_name'
}


# TODO
# metadata
# https://forum.italia.it/t/contactperson-extensions/18024/3
# https://www.agid.gov.it/sites/default/files/repository_files/spid-avviso-n29v3-specifiche_sp_pubblici_e_privati.pdf
# Gestire i metadati degli IDP :
# https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml
# Spid TEST Agid:
# https://idptest.spid.gov.it/
# IDP di validazione (https://validator.spid.gov.it)


def init_saml_auth(request, idp):
    local_config = None
    if not idp or 'test' in idp:
        idp = ""
        local_config = app.config['SAML_PATH']
    auth = get_saml_auth(request, idp, local_config_path=local_config)
    return auth


def process_user(attributes):
    attrs = {}
    try:
        for attr in attributes:
            if attr in REQUESTED_ATTRIBUTES:
                key = ATTRIBUTES_MAP.get(attr, attr)
                attrs[key] = attributes[attr][0]
        username = attr['name']
        if username not in user_store:
            user_store[username] = attrs.copy()

        user = User(username)
        session['saml_attributes'] = attrs
        session[username] = True
        login_user(user)
        return user
    except (KeyError, ValueError):
        return


class User(UserMixin):
    def __init__(self, user_id):
        user = {}
        self.id = None
        self.first_name = None
        self.last_name = None
        try:
            user = user_store[user_id]
            self.id = str(user_id)
            self.first_name = user['first_name']
            self.last_name = user['last_name']
        except:
            pass


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route("/user")
def user():
    return render_template('main_page.html', session=session)


@app.route("/")
def main_page():
    loginEp = "/login"
    session['formActionUrl'] = loginEp
    return render_template('main_page.html', idp_dict=metadata_url_for)


@app.route("/login", methods=['GET', 'POST'])
def login():
    """
        Handle login action ( SP -> IDP )
    """
    req = prepare_request(request)
    print("")
    print("req")
    print(req)
    print("")
    print("")
    print("")
    idp = req['get_data'].get('idp') or "test"
    session['idp'] = idp
    auth = init_saml_auth(req, idp)
    args = []
    if 'next' in req['get_data']:
        args.append(req['get_data'].get('next'))
    return redirect(auth.login(*args))



@app.route("/acs", methods=['POST'])
def acs():
    """
        Handle login action ( IDP -> SP )
    """
    req = prepare_request(request)
    # if "idp" in req.get('post_data'):
    idp = None
    auth = init_saml_auth(req, idp)
    request_id = None
    if 'AuthNRequestID' in session:
        request_id = session['AuthNRequestID']
    auth.process_response(request_id=request_id)
    errors = auth.get_errors()
    not_auth_warn = not auth.is_authenticated()
    if len(errors) == 0:
        if 'AuthNRequestID' in session:
            del session['AuthNRequestID']
        session['samlUserdata'] = auth.get_attributes()
        session['samlNameId'] = auth.get_nameid()
        session['samlNameIdFormat'] = auth.get_nameid_format()
        session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
        session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
        session['samlSessionIndex'] = auth.get_session_index()
        self_url = OneLogin_Saml2_Utils.get_self_url(req)
        if 'RelayState' in request.form and self_url != request.form['RelayState']:
            return redirect(auth.redirect_to(request.form['RelayState']))
    elif auth.get_settings().is_debug_active():
        error_reason = auth.get_last_error_reason()
        return make_response(error_reason)


@app.route('/metadata')
@app.route('/metadata/<idp_name>')
def metadata(idp_name=None):
    req = prepare_request(request)
    auth = init_saml_auth(req, idp_name)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    return resp


@app.route("/logout")
def logout():
    """
         Logout
         Handle SLO ( SP -> IDP )
     """
    req = prepare_request(request)
    idp = None
    auth = init_saml_auth(req, idp)
    name_id = None
    session_index = None
    if 'samlNameId' in session:
        name_id = session['samlNameId']
    if 'samlSessionIndex' in session:
        session_index = session['samlSessionIndex']
    else:
        return redirect(url_for('login'))
    return redirect(
        auth.logout(
            name_id=name_id,
            session_index=session_index,
        )
    )


@app.route("/sls")
def sls_logout():
    """
        Logout
        Handle SLS ( IDP -> SP )
    """
    req = prepare_request(request)
    idp = session.get('idp')
    auth = init_saml_auth(req, idp)
    errors = []
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False
    dscb = lambda: session.clear()
    url = auth.process_slo(delete_session_cb=dscb)
    errors = auth.get_errors()
    redirect_to = '/'
    if len(errors) == 0:
        if url is not None:
            redirect_to = url
        else:
            success_slo = True
            logout_user()
    return redirect(redirect_to)


@app.route('/img/<filename>', methods=['GET'])
def get_file_img(filename):
    return send_file("static/img/%s" % filename)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
