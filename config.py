# -*- coding: utf-8 -*-
import pkg_resources
import os
from xml.etree import ElementTree as et
import json

SPID_IDENTITY_PROVIDERS = [
    ('arubaid', 'Aruba ID'),
    ('infocertid', 'Infocert ID'),
    ('namirialid', 'Namirial ID'),
    ('posteid', 'Poste ID'),
    ('sielteid', 'Sielte ID'),
    ('spiditalia', 'SPIDItalia Register.it'),
    ('timid', 'Tim ID')
]
REQUESTED_ATTRIBUTES = ['name', 'familyName', 'email', 'spidCode']

SAML_METADATA_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:metadata"
BINDING_REDIRECT_URN = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
XML_SIGNATURE_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
BASE_DIR = os.path.dirname(os.path.dirname(__file__))


def get_idp_config(id, name=None):
    # xml_path = pkg_resources.resource_filename('spid-idp-metadata/spid-idp-%s.xml' % id)
    xml_path = os.path.join(BASE_DIR, 'python-spid-service-provider/spid-idp-metadata/spid-idp-%s.xml' % id)
    idp_metadata = et.parse(xml_path).getroot()
    sso_path = './/{%s}SingleSignOnService[@Binding="%s"]' % \
               (SAML_METADATA_NAMESPACE, BINDING_REDIRECT_URN)
    slo_path = './/{%s}SingleLogoutService[@Binding="%s"]' % \
               (SAML_METADATA_NAMESPACE, BINDING_REDIRECT_URN)

    try:
        sso_location = idp_metadata.find(sso_path).attrib['Location']
    except (KeyError, AttributeError) as err:
        raise ValueError("Missing metadata SingleSignOnService for %r: %r" % (id, err))

    try:
        slo_location = idp_metadata.find(slo_path).attrib['Location']
    except (KeyError, AttributeError) as err:
        raise ValueError("Missing metadata SingleLogoutService for %r: %r" % (id, err))

    return {
        'name': name,
        'idp': {
            "entityId": idp_metadata.get("entityID"),
            "singleSignOnService": {
                "url": sso_location,
                "binding": BINDING_REDIRECT_URN
            },
            "singleLogoutService": {
                "url": slo_location,
                "binding": BINDING_REDIRECT_URN
            },
            "x509cert": idp_metadata.find(".//{%s}X509Certificate" % XML_SIGNATURE_NAMESPACE).text
        }
    }


class SpidConfig(object):
    name = 'spid'
    verbose_name = "SPID Authentication"

    identity_providers = {
        id: get_idp_config(id, name) for id, name in SPID_IDENTITY_PROVIDERS
    }

    @staticmethod
    def config():
        config = {
            "strict": "",
            "debug": "",
            "sp": {
                "entityId": "",
                "singleSignOnService": {
                    "url": "",
                    "respurl": "",
                    "binding": "",
                },
                "singleLogoutService": {
                    "url": "",
                    "respurl": "",
                    "binding": "",
                },
                "attributeConsumingService": {
                    "serviceName": "",
                    "serviceDescription": "",
                    "requestedAttributes": []
                },
                "NameIDFormat": "",
                "x509cert": "",
                "privateKey": ""
            },
            "idp": {
                "entityId": "",
                "singleSignOnService": {
                    "url": "",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "singleLogoutService": {
                    "url": "",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": (
                    ""
                )
            }
        }
        if SpidConfig.extra_settings():
            config.update(SpidConfig.extra_settings())
        return config.copy()

    @staticmethod
    def extra_settings():
        return {
            "security": {
                "nameIdEncrypted": True,
                "authnRequestsSigned": True,
                "logoutRequestSigned": False,
                "logoutResponseSigned": False,
                "signMetadata": False,
                "wantMessagesSigned": False,
                "wantAssertionsSigned": False,
                "wantNameId": True,
                "wantNameIdEncrypted": False,
                "wantAssertionsEncrypted": False,
                "signatureAlgorithm": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                "digestAlgorithm": "http://www.w3.org/2000/09/xmldsig#sha1",
                "requestedAuthnContext": [
                    "https://spid-testenv-identityserver/SpidL2"
                ]
            },
            "contactPerson": {
                "other": {
                    "Extensions": {
                        "IPACode": False,
                        "VATNumber": False,
                        "FiscalCode": False,
                        "Exttype": [
                            "Public",
                            "Private"
                        ]
                    },
                    "givenName": "",
                    "emailAddress": "",
                    "telephoneNumber": ""
                },
                "billing": {
                    "Extension_type": [],
                    "Extensions": {
                        "FpaExt": [
                            "CessionarioCommittente"
                        ],
                        "CessionarioCommittente": {
                            "DatiAnagrafici": {
                                "IdFiscaleIVA": {
                                    "IdPaese": "",
                                    "IdCodice": ""
                                },
                                "Anagrafica": {
                                    "Denominazione": ""
                                }
                            },
                            "Sede": {
                                "Indirizzo": "",
                                "NumeroCivico": "",
                                "CAP": "",
                                "Comune": "",
                                "Provincia": "",
                                "Nazione": ""
                            }
                        },
                        "TerzoIntermediarioSoggettoEmittente": {
                            "DatiAnagrafici": {
                                "IdFiscaleIVA": {
                                    "IdPaese": "",
                                    "IdCodice": ""
                                },
                                "Anagrafica": {
                                    "Denominazione": ""
                                }
                            },
                            "Sede": {
                                "Indirizzo": "",
                                "NumeroCivico": "",
                                "CAP": "",
                                "Comune": "",
                                "Provincia": "",
                                "Nazione": ""
                            }
                        }
                    },
                    "Company": "",
                    "emailAddress": "",
                    "telephoneNumber": ""
                }
            },
            "organization": {
                "en-US": {
                    "name": "sp_test",
                    "displayname": "SP test",
                    "url": "http://sp.example.com"
                }
            }
        }.copy()

    @staticmethod
    def get_saml_settings(idp_id=None, local_config=None):

        if local_config:
            return None
        else:
            saml_settings = SpidConfig.config()
            saml_settings.update({'idp': SpidConfig.identity_providers[idp_id]['idp']})
            return saml_settings
