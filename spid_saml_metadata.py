# -*- coding: utf-8 -*-
# 2021 Alessio Gerace.
#
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).

from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from time import gmtime, strftime, time
from datetime import datetime
from onelogin.saml2 import compat
from spid_saml_template import *
import re
import uuid


try:
    import ujson as json
except ImportError:
    import json

basestring = str

url_regex = re.compile(
    r'^(?:[a-z0-9\.\-]*)://'  # scheme is validated separately
    r'(?:(?:[A-Z0-9_](?:[A-Z0-9-_]{0,61}[A-Z0-9_])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
url_schemes = ['http', 'https', 'ftp', 'ftps']

def validate_url(url):
    """
    Auxiliary method to validate an urllib
    :param url: An url to be validated
    :type url: string
    :returns: True if the url is valid
    :rtype: bool
    """

    scheme = url.split('://')[0].lower()
    if scheme not in url_schemes:
        return False
    if not bool(url_regex.search(url)):
        return False
    return True

class SpidOneLogin_Saml2_Metadata(OneLogin_Saml2_Metadata):
    """

    A class that contains methods related to the metadata of the SP

    """

    TIME_VALID = 172800  # 2 days
    TIME_CACHED = 604800  # 1 week

    @staticmethod
    def builder(sp, authnsign=False, wsign=False, valid_until=None, cache_duration=None, contacts=None,
                organization=None):
        """
        Builds the metadata of the SP

        :param sp: The SP data
        :type sp: string

        :param authnsign: authnRequestsSigned attribute
        :type authnsign: string

        :param wsign: wantAssertionsSigned attribute
        :type wsign: string

        :param valid_until: Metadata's expiry date
        :type valid_until: string|DateTime|Timestamp

        :param cache_duration: Duration of the cache in seconds
        :type cache_duration: int|string

        :param contacts: Contacts info
        :type contacts: dict

        :param organization: Organization info
        :type organization: dict
        """
        if valid_until is None:
            valid_until = int(time()) + SpidOneLogin_Saml2_Metadata.TIME_VALID
        if not isinstance(valid_until, basestring):
            if isinstance(valid_until, datetime):
                valid_until_time = valid_until.timetuple()
            else:
                valid_until_time = gmtime(valid_until)
            valid_until_str = strftime(r'%Y-%m-%dT%H:%M:%SZ', valid_until_time)
        else:
            valid_until_str = valid_until

        if cache_duration is None:
            cache_duration = SpidOneLogin_Saml2_Metadata.TIME_CACHED
        if not isinstance(cache_duration, compat.str_type):
            cache_duration_str = 'PT%sS' % cache_duration  # Period of Time x Seconds
        else:
            cache_duration_str = cache_duration

        if contacts is None:
            contacts = {}
        if organization is None:
            organization = {}

        sls = ''
        if 'singleLogoutService' in sp and 'url' in sp['singleLogoutService']:
            sls = OneLogin_Saml2_Templates.MD_SLS % \
                  {
                      'binding': sp['singleLogoutService']['binding'],
                      'location': sp['singleLogoutService']['url'],
                      'resplocation': sp['singleLogoutService']['respurl'],
                  }
        str_authnsign = 'true' if authnsign else 'false'
        str_wsign = 'true' if wsign else 'false'

        str_organization = ''
        if len(organization) > 0:
            organization_names = []
            organization_displaynames = []
            organization_urls = []
            for (lang, info) in organization.items():
                organization_names.append(
                    """        <md:OrganizationName xml:lang="%s">%s</md:OrganizationName>""" % (lang, info['name']))
                organization_displaynames.append(
                    """        <md:OrganizationDisplayName xml:lang="%s">%s</md:OrganizationDisplayName>""" % (
                        lang, info['displayname']))
                organization_urls.append(
                    """        <md:OrganizationURL xml:lang="%s">%s</md:OrganizationURL>""" % (lang, info['url']))
            org_data = '\n'.join(organization_names) + '\n' + '\n'.join(organization_displaynames) + '\n' + '\n'.join(
                organization_urls)
            str_organization = """    <md:Organization>\n%(org)s\n    </md:Organization>""" % {'org': org_data}

        str_contacts = ''
        if len(contacts) > 0:
            contacts_info = []
            for (ctype, info) in contacts.items():
                datadict = info
                datadict.update(info.get('Extensions'))
                datadict.pop('Extensions')
                if ctype == "other":
                    info['ctype'] = ctype
                    if datadict.get('IPACode'):
                        ipacode = f"<spid:IPACode>{datadict['IPACode']}</spid:IPACode>"
                        datadict['IPACode'] = ipacode
                        info['Exttype'] = "Public"
                        datadict['VATNumber'] = ""
                        datadict['FiscalCode'] = ""
                    elif datadict.get('VATNumber') or info.get('FiscalCode'):
                        VATNumber = f"            <spid:VATNumber>{datadict['VATNumber']}/spid:VATNumber>"
                        FiscalCode = f"            <spid:FiscalCode>{datadict['FiscalCode']}</spid:FiscalCode>"
                        datadict['VATNumber'] = VATNumber
                        datadict['FiscalCode'] = FiscalCode
                        datadict['Exttype'] = "Private"
                    contact = OneLogin_Saml2_Templates.MD_CONTACT_PERSON % datadict
                    contacts_info.append(contact)
                if ctype == "billing":
                    pass
            str_contacts = '\n'.join(contacts_info)

        str_attribute_consuming_service = ''
        if 'attributeConsumingService' in sp and len(sp['attributeConsumingService']):
            attr_cs_desc_str = ''
            if "serviceDescription" in sp['attributeConsumingService']:
                attr_cs_desc_str = """            <md:ServiceDescription xml:lang="it">%s</md:ServiceDescription>
""" % sp['attributeConsumingService']['serviceDescription']

            requested_attribute_data = []
            for req_attribs in sp['attributeConsumingService']['requestedAttributes']:
                req_attr_nameformat_str = req_attr_friendlyname_str = req_attr_isrequired_str = ''
                req_attr_aux_str = ' />'

                if 'nameFormat' in req_attribs.keys() and req_attribs['nameFormat']:
                    req_attr_nameformat_str = " NameFormat=\"%s\"" % req_attribs['nameFormat']
                if 'friendlyName' in req_attribs.keys() and req_attribs['friendlyName']:
                    req_attr_friendlyname_str = " FriendlyName=\"%s\"" % req_attribs['friendlyName']
                if 'isRequired' in req_attribs.keys() and req_attribs['isRequired']:
                    req_attr_isrequired_str = " isRequired=\"%s\"" % 'true' if req_attribs['isRequired'] else 'false'
                if 'attributeValue' in req_attribs.keys() and req_attribs['attributeValue']:
                    if isinstance(req_attribs['attributeValue'], basestring):
                        req_attribs['attributeValue'] = [req_attribs['attributeValue']]

                    req_attr_aux_str = ">"
                    for attrValue in req_attribs['attributeValue']:
                        req_attr_aux_str += """
                <saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%(attributeValue)s</saml:AttributeValue>""" % \
                                            {
                                                'attributeValue': attrValue
                                            }
                    req_attr_aux_str += """
            </md:RequestedAttribute>"""

                requested_attribute = """            <md:RequestedAttribute Name="%(req_attr_name)s"%(req_attr_nameformat_str)s%(req_attr_friendlyname_str)s%(req_attr_isrequired_str)s%(req_attr_aux_str)s""" % \
                                      {
                                          'req_attr_name': req_attribs['name'],
                                          'req_attr_nameformat_str': req_attr_nameformat_str,
                                          'req_attr_friendlyname_str': req_attr_friendlyname_str,
                                          'req_attr_isrequired_str': req_attr_isrequired_str,
                                          'req_attr_aux_str': req_attr_aux_str
                                      }

                requested_attribute_data.append(requested_attribute)

            str_attribute_consuming_service = """        <md:AttributeConsumingService index="0">
            <md:ServiceName xml:lang="it">%(service_name)s</md:ServiceName>
%(attr_cs_desc)s%(requested_attribute_str)s
        </md:AttributeConsumingService>
""" % \
                                              {
                                                  'service_name': sp['attributeConsumingService']['serviceName'],
                                                  'attr_cs_desc': attr_cs_desc_str,
                                                  'requested_attribute_str': '\n'.join(requested_attribute_data)
                                              }

        metadata = OneLogin_Saml2_Templates.MD_ENTITY_DESCRIPTOR % \
                   {
                       'valid': ('validUntil="%s"' % valid_until_str) if valid_until_str else '',
                       "uuid": str(uuid.uuid4()),
                       'cache': ('cacheDuration="%s"' % cache_duration_str) if cache_duration_str else '',
                       'entity_id': sp['entityId'],
                       'authnsign': str_authnsign,
                       'wsign': str_wsign,
                       'name_id_format': sp['NameIDFormat'],
                       'binding': sp['assertionConsumerService']['binding'],
                       'location': sp['assertionConsumerService']['url'],
                       'sls': sls,
                       'organization': str_organization,
                       'contacts': str_contacts,
                       'attribute_consuming_service': str_attribute_consuming_service
                   }

        return metadata