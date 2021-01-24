# -*- coding: utf-8 -*-
# 2021 Alessio Gerace.
#
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).

from onelogin.saml2.xml_templates import OneLogin_Saml2_Templates

OneLogin_Saml2_Templates.AUTHN_REQUEST = """
<samlp:AuthnRequest
        xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%(id)s"
        Version="2.0"
        IssueInstant="%(issue_instant)s" Destination="%(destination)s"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        AssertionConsumerServiceURL="%(assertion_url)s"%(attr_consuming_service_str)s>
<saml:Issuer NameQualifier="%(entity_id)s" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">%(entity_id)s</saml:Issuer>%(subject_str)s%(nameid_policy_str)s
        %(requested_authn_context_str)s
</samlp:AuthnRequest>"""

OneLogin_Saml2_Templates.LOGOUT_REQUEST = """\
<samlp:LogoutRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="%(id)s"
  Version="2.0"
  IssueInstant="%(issue_instant)s"
  Destination="%(single_logout_url)s">
  <saml:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="%(entity_id)s" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">%(entity_id)s</saml:Issuer>
  <saml:NameID xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="%(entity_id)s">%(entity_id)s</saml:NameID>  
    %(session_index)s
</samlp:LogoutRequest>"""

OneLogin_Saml2_Templates.MD_ENTITY_DESCRIPTOR = """\
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="https://spid.gov.it/saml-extensions"
                     %(valid)s
                     %(cache)s
                     entityID="%(entity_id)s">
    <md:SPSSODescriptor AuthnRequestsSigned="%(authnsign)s" WantAssertionsSigned="%(wsign)s" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
%(sls)s        <md:NameIDFormat>%(name_id_format)s</md:NameIDFormat>
        <md:AssertionConsumerService Binding="%(binding)s" 
                                     Location="%(location)s" index="0" isDefault="true"/>
%(attribute_consuming_service)s    </md:SPSSODescriptor>
%(organization)s
%(contacts)s
</md:EntityDescriptor>"""

OneLogin_Saml2_Templates.MD_CONTACT_PERSON = """\
    <md:ContactPerson contactType="%(ctype)s">
        <md:Extensions>
            %(IPACode)s
            %(VATNumber)s
            %(FiscalCode)s
            <spid:%(Exttype)s/>
        </md:Extensions>
        <md:Company>%(givenName)s</md:Company>
        <md:EmailAddress>%(emailAddress)s</md:EmailAddress>
        <md:TelephoneNumber>%(telephoneNumber)s</md:TelephoneNumber>
    </md:ContactPerson>"""

OneLogin_Saml2_Templates.MD_CONTACT_PERSON_BILLING_DATA = """\
<fpa:%(billing_type)s>
    <fpa:DatiAnagrafici>
        <fpa:IdFiscaleIVA>
            <fpa:IdPaese>%(IdPaese)s</fpa:IdPaese>
            <fpa:IdCodice>%(IdPaese)s</fpa:IdPaese>
        </fpa:IdFiscaleIVA>
        <fpa:Anagrafica>
            <fpa:Denominazione>%(Denominazione)s</fpa:Denominazione>
        </fpa:Anagrafica>
    </fpa:DatiAnagrafici>
    <fpa:Sede>
        <fpa:Indirizzo>%(Indirizzo)s</fpa:Indirizzo>
        <fpa:NumeroCivico>%(NumeroCivico)s</fpa:NumeroCivico>
        <fpa:CAP>%(CAP)s</fpa:CAP>
        <fpa:Comune>%(Comune)s</fpa:Comune>
        <fpa:Provincia>%(Provincia)s</fpa:Provincia>
        <fpa:Nazione>%(Nazione)s</fpa:Nazione>
    </fpa:Sede>
</fpa:CessionarioCommittente>
"""

OneLogin_Saml2_Templates.MD_CONTACT_PERSON_BILLING = """\
    <md:ContactPerson contactType="%(type)s"
        <md:Extensions xmlns:fpa="https://spid.gov.it/invoicing-extensions">
             %(person_billing_data)s
        </md:Extensions>
        <md:Company>Destinatario_Fatturazione</md:Company>
        <md:EmailAddress>email@fatturazione.it</md:EmailAddress>
        <md:TelephoneNumber>telefono_fatture</md:TelephoneNumber>
    </md:ContactPerson>"""

OneLogin_Saml2_Templates.MD_SLS = """\
        <md:SingleLogoutService Binding="%(binding)s"
                                Location="%(location)s"
                                ResponseLocation="%(resplocation)s" />\n"""

OneLogin_Saml2_Templates.MD_SSO = """\
        <md:SingleSignOnService Binding="%(binding)s"
                                Location="%(location)s" />\n"""