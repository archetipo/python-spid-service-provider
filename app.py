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
from flask import (
    Flask,
    redirect,
    render_template,
    request,
    Response,
    session,
    url_for,
    send_from_directory, send_file)
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
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
    saml, valid_instance, samlp)
from saml2.authn_context import requested_authn_context
from saml2.metadata import metadata_tostring_fix, sign_entity_descriptor, entities_descriptor, entity_descriptor
from saml2.pack import http_redirect_message
from saml2.saml import NAME_FORMAT_BASIC, NAMEID_FORMAT_TRANSIENT, NameIDType_, Issuer
# from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config, Config
import requests


from saml2.sigver import security_context
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256, SIG_RSA_SHA1

from client_base_spid import Saml2ClientSpid

metadata_url_for = {}

app = Flask(__name__, static_folder='static')
Bootstrap(app)
app.secret_key = str(uuid.uuid4())  # Replace with your secret key
login_manager = LoginManager()
login_manager.init_app(app)
logging.basicConfig(level=logging.DEBUG)
spConfig = None
user_store = {}

def create_metadata_string(configfile, config=None, valid=None, cert=None,
                           keyfile=None, mid=None, name=None, sign=None):
    valid_for = 0
    nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}

    if valid:
        valid_for = int(valid)  # Hours

    eds = []
    if config is None:
        if configfile.endswith(".py"):
            configfile = configfile[:-3]
        config = Config().load_file(configfile, metadata_construction=True)
    eds.append(entity_descriptor(config))

    conf = Config()
    conf.key_file = config.key_file or keyfile
    conf.cert_file = config.cert_file or cert
    conf.debug = 1
    conf.xmlsec_binary = config.xmlsec_binary
    secc = security_context(conf)

    if mid:
        eid, xmldoc = entities_descriptor(eds, valid_for, name, mid,
                                          sign, secc)
    else:
        eid = eds[0]
        if sign:
            eid, xmldoc = sign_entity_descriptor(eid, mid, secc)
        else:
            xmldoc = None

    valid_instance(eid)
    return metadata_tostring_fix(eid, nspair, xmldoc)


def saml_client_for(idp_name=None):
    '''
    Given the name of an IdP, return a configuation.
    The configuration is a hash for use by saml2.config.Config
    '''

    if idp_name not in metadata_url_for:
        raise Exception("Settings for IDP '{}' not found".format(idp_name))
    acs_url = url_for(
        "idp_initiated",
        idp_name=idp_name,
        _external=True)
    https_acs_url = url_for(
        "idp_initiated",
        idp_name=idp_name,
        _external=True,
        _scheme='https')

    rv = requests.get(metadata_url_for[idp_name], verify=False)

    settings = {
        "entityid": config.get('hostname'),
        # "name_id_format_allow_create": True,
        "name": config.get('hostname'),
        'metadata': {
            'inline': [rv.text],
        },
        'service': {
            'sp': {
                'nameid_format': config.get('hostname'),
                'endpoints': {
                    "name": "Spid SP Testenv",
                    "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                    "assertion_consumer_service": [
                        (acs_url, BINDING_HTTP_REDIRECT),
                        (acs_url, BINDING_HTTP_POST),
                        (https_acs_url, BINDING_HTTP_REDIRECT),
                        (https_acs_url, BINDING_HTTP_POST)
                    ],

                    "identifier": NAME_FORMAT_BASIC,
                    "policy": {
                        "default": {
                            "name_form": NAME_FORMAT_BASIC,
                        },
                    },
                    "name_id_format": [
                        NAMEID_FORMAT_TRANSIENT,
                    ]
                },
                "requested_attribute_name_format": NAME_FORMAT_BASIC,
                "required_attributes": config.get('required_attributes'),
                'allow_unsolicited': True,
                # "name_id_format_allow_create": True,
                'authn_requests_signed': True,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
                'requested_authn_context': True
            },
        },
        "key_file": config.get('key_file') or "",
        "cert_file": config.get('cert_file') or "",
        "organization": {
            "display_name":  config.get('name'),
            "name":  config.get('name'),
            "url":  config.get('hostname'),
        },
    }

    spConfig = Saml2Config()
    spConfig.load(settings)
    spConfig.allow_unknown_attributes = True
    saml_client = Saml2ClientSpid(config=spConfig)
    return saml_client


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


@app.route("/")
def main_page():
    loginEp = "%s/%s" % (
        config.get('hostname'),
        config.get('endpoints').get('login')
    )
    session['idpName'] = config.get('test_idp_name')
    session['formActionUrl'] = loginEp
    return render_template('main_page.html', idp_dict=metadata_url_for)

@app.route("/saml/login", methods=['POST'])
def requstLogin():
    return redirect("http://spid-sp-test:5000/saml/login/%s" % config.get('test_idp_name'))


@app.route("/saml/sso/<idp_name>", methods=['POST'])
def idp_initiated(idp_name):
    saml_client = saml_client_for(idp_name)
    authn_response = saml_client.parse_authn_request_response(
        request.form['SAMLResponse'],
        entity.BINDING_HTTP_POST)
    authn_response.get_identity()
    user_info = authn_response.get_subject()
    username = user_info.text

    # This is what as known as "Just In Time (JIT) provisioning".
    # What that means is that, if a user in a SAML assertion
    # isn't in the user store, we create that user first, then log them in
    if username not in user_store:
        user_store[username] = {
            'first_name': authn_response.ava['name'][0],
            'last_name': authn_response.ava['familyName'][0],
            }
    user = User(username)
    session['saml_attributes'] = authn_response.ava
    login_user(user)
    url = url_for('user')
    if 'RelayState' in request.form:
        url = request.form['RelayState']
    return redirect(url)


@app.route("/saml/login/<idp_name>")
def sp_initiated(idp_name):

    app.logger.debug('Space key: {}'.format(""))
    app.logger.debug('idp_name key: {}'.format(idp_name))
    saml_client = saml_client_for(idp_name)

    reqCtx = requested_authn_context(
        [config.get('authn_request_level')], comparison='exact')

    srvs = saml_client.metadata.single_sign_on_service(
        config.get('test_idp_url'), BINDING_HTTP_POST)

    reqid, req = saml_client.create_authn_request_spid(
        srvs[0]["location"],
        requested_authn_context=reqCtx,
        issuer=Issuer(
            name_qualifier=saml_client.config.getattr('organization').get('url'),
            format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
            text=config.get('hostname')
        ),
        sign=False, allow_create=None,
        nsprefix={"saml": saml.NAMESPACE, "samlp": samlp.NAMESPACE}
    )

    app.logger.debug('reqid: {}'.format(reqid))
    app.logger.debug('req: {}'.format(req))
    redirect_url = None

    # Select the IdP URL to send the AuthN request to

    signer = saml_client.sec.sec_backend.get_signer(SIG_RSA_SHA256)
    # signer = saml_client.sec.sec_backend.get_signer(SIG_RSA_SHA1)

    info = http_redirect_message(
        req, srvs[0]["location"], relay_state="user",
        typ="SAMLRequest", sigalg=SIG_RSA_SHA256, signer=signer)

    # info = http_redirect_message(
    #     req, srvs[0]["location"], relay_state="RS",
    #     typ="SAMLRequest")

    app.logger.debug('info: {}'.format(info))
    for key, value in info['headers']:
        if key is 'Location':
            redirect_url = value

    response = redirect(redirect_url, code=302)
    response.headers['Cache-Control'] = 'no-cache, no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route("/user")
@login_required
def user():
    return render_template('main_page.html', session=session)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main_page"))

@app.route("/metadata/<idp_name>", methods=['GET'])
def metadata(idp_name):
    saml_client = saml_client_for(idp_name)
    metadata = create_metadata_string(
        __file__,
        saml_client.config
    )
    return Response(metadata, mimetype='text/xml')


@app.route('/img/<filename>',  methods=['GET'])
def get_file_img(filename):
    return send_file("static/img/%s" % filename)

@app.route('/img/idp-logos/<filename>', methods=['GET'])
def get_file_img_logo(filename):
    return send_file("static/img/idp-logos/%s" % filename)

@app.route('/dev/<filename>', methods=['GET'])
def get_file_dev(filename):
    return send_file("static/dev/%s" % filename)

@app.route('/src/data/<filename>', methods=['GET'])
def get_file(filename):
    return send_file("static/src/data/%s" % filename)

def _get_config(f_name, f_type='yaml'):
    """
    Read server configuration from a json file
    """
    with open(f_name, 'r') as fp:
        if f_type == 'yaml':
            return yaml.load(fp)
        elif f_type == 'json':
            return json.loads(fp.read())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', dest='path', help='Path to configuration file.', default='./config.yaml')
    parser.add_argument('-ct', dest='configuration_type', help='Configuration type [yaml|json]', default='yaml')
    args = parser.parse_args()
    # Init server
    config = _get_config(args.path, args.configuration_type)
    port = int(config.get('port'))
    if port == 5000:
        app.debug = True
    metadata_url_for[config.get('test_idp_name')] = config.get('test_idp_metadata_url')
    app.run(host=config.get('host'), port=port, debug=config.get('debug'))
