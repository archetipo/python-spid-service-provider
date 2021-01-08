import saml2
from saml2 import BINDING_PAOS, saml, attributemaps, samlp, SamlBase, NAMESPACE
from saml2.client_base import Base
from saml2.extension import sp_type, requested_attributes
from saml2.samlp import AuthnRequest
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.samlp import RequestedAuthnContext, Extensions


class SpidBase(Base):

    def create_authn_request_spid(self, destination, vorg="", scoping=None,
            binding=saml2.BINDING_HTTP_POST,
            nameid_format=None,
            service_url_binding=None, message_id=0,
            consent=None, extensions=None, sign=None,
            allow_create=None, sign_prepare=False, sign_alg=None,
            digest_alg=None, **kwargs):
        """ Creates an authentication request.

        :param destination: Where the request should be sent.
        :param vorg: The virtual organization the service belongs to.
        :param scoping: The scope of the request
        :param binding: The protocol to use for the Response !!
        :param nameid_format: Format of the NameID
        :param service_url_binding: Where the reply should be sent dependent
            on reply binding.
        :param message_id: The identifier for this request
        :param consent: Whether the principal have given her consent
        :param extensions: Possible extensions
        :param sign: Whether the request should be signed or not.
        :param sign_prepare: Whether the signature should be prepared or not.
        :param allow_create: If the identity provider is allowed, in the course
            of fulfilling the request, to create a new identifier to represent
            the principal.
        :param kwargs: Extra key word arguments
        :return: tuple of request ID and <samlp:AuthnRequest> instance
        """
        client_crt = None
        if "client_crt" in kwargs:
            client_crt = kwargs["client_crt"]

        args = {}

        if self.config.getattr('hide_assertion_consumer_service', 'sp'):
            args["assertion_consumer_service_url"] = None
            binding = None
        else:
            try:
                args["assertion_consumer_service_url"] = kwargs[
                    "assertion_consumer_service_urls"][0]
                del kwargs["assertion_consumer_service_urls"]
            except KeyError:
                try:
                    args["assertion_consumer_service_url"] = kwargs[
                        "assertion_consumer_service_url"]
                    del kwargs["assertion_consumer_service_url"]
                except KeyError:
                    try:
                        args["assertion_consumer_service_index"] = str(
                            kwargs["assertion_consumer_service_index"])
                        del kwargs["assertion_consumer_service_index"]
                    except KeyError:
                        if service_url_binding is None:
                            service_urls = self.service_urls(binding)
                        else:
                            service_urls = self.service_urls(service_url_binding)
                        args["assertion_consumer_service_url"] = service_urls[0]

        try:
            args["provider_name"] = kwargs["provider_name"]
        except KeyError:
            if binding == BINDING_PAOS:
                pass
            else:
                args["provider_name"] = self._my_name()

        # Allow argument values either as class instances or as dictionaries
        # all of these have cardinality 0..1
        _msg = AuthnRequest()
        for param in ["scoping", "requested_authn_context", "conditions",
                      "subject"]:
            try:
                _item = kwargs[param]
            except KeyError:
                pass
            else:
                del kwargs[param]
                # either class instance or argument dictionary
                if isinstance(_item, _msg.child_class(param)):
                    args[param] = _item
                elif isinstance(_item, dict):
                    args[param] = RequestedAuthnContext(**_item)
                else:
                    raise ValueError("%s or wrong type expected %s" % (_item,
                                                                       param))

        try:
            args["name_id_policy"] = kwargs["name_id_policy"]
            del kwargs["name_id_policy"]
        except KeyError:
            if allow_create is None:
                allow_create = self.config.getattr("name_id_format_allow_create", "sp")
                if allow_create is None:
                    allow_create = "false"
                else:
                    if allow_create is True:
                        allow_create = "true"
                    else:
                        allow_create = "false"

            if nameid_format == "":
                name_id_policy = None
            else:
                if nameid_format is None:
                    nameid_format = self.config.getattr("name_id_format", "sp")

                    # If no nameid_format has been set in the configuration
                    # or passed in then transient is the default.
                    if nameid_format is None:
                        nameid_format = NAMEID_FORMAT_TRANSIENT

                    # If a list has been configured or passed in choose the
                    # first since NameIDPolicy can only have one format specified.
                    elif isinstance(nameid_format, list):
                        nameid_format = nameid_format[0]

                    # Allow a deployer to signal that no format should be specified
                    # in the NameIDPolicy by passing in or configuring the string 'None'.
                    elif nameid_format == 'None':
                        nameid_format = None

                    name_id_policy = NameIDPolicySpid(format=nameid_format)

            if name_id_policy and vorg:
                try:
                    name_id_policy.sp_name_qualifier = vorg
                    name_id_policy.format = saml.NAMEID_FORMAT_PERSISTENT
                except KeyError:
                    pass
            args["name_id_policy"] = name_id_policy

        try:
            nsprefix = kwargs["nsprefix"]
        except KeyError:
            nsprefix = None

        try:
            force_authn = kwargs['force_authn']
        except KeyError:
            force_authn = self.config.getattr('force_authn', 'sp')
        finally:
            if force_authn:
                args['force_authn'] = 'true'

        conf_sp_type = self.config.getattr('sp_type', 'sp')
        conf_sp_type_in_md = self.config.getattr('sp_type_in_metadata', 'sp')
        if conf_sp_type and conf_sp_type_in_md is False:
            if not extensions:
                extensions = Extensions()
            item = sp_type.SPType(text=conf_sp_type)
            extensions.add_extension_element(item)

        requested_attrs = self.config.getattr('requested_attributes', 'sp')
        if requested_attrs:
            if not extensions:
                extensions = Extensions()

            attributemapsmods = []
            for modname in attributemaps.__all__:
                attributemapsmods.append(getattr(attributemaps, modname))

            items = []
            for attr in requested_attrs:
                friendly_name = attr.get('friendly_name')
                name = attr.get('name')
                name_format = attr.get('name_format')
                is_required = str(attr.get('required', False)).lower()

                if not name and not friendly_name:
                    raise ValueError(
                        "Missing required attribute: '{}' or '{}'".format(
                            'name', 'friendly_name'))

                if not name:
                    for mod in attributemapsmods:
                        try:
                            name = mod.MAP['to'][friendly_name]
                        except KeyError:
                            continue
                        else:
                            if not name_format:
                                name_format = mod.MAP['identifier']
                            break

                if not friendly_name:
                    for mod in attributemapsmods:
                        try:
                            friendly_name = mod.MAP['fro'][name]
                        except KeyError:
                            continue
                        else:
                            if not name_format:
                                name_format = mod.MAP['identifier']
                            break

                items.append(requested_attributes.RequestedAttribute(
                    is_required=is_required,
                    name_format=name_format,
                    friendly_name=friendly_name,
                    name=name))

            item = requested_attributes.RequestedAttributes(
                extension_elements=items)
            extensions.add_extension_element(item)

        if kwargs:
            _args, extensions = self._filter_args(AuthnRequest(), extensions,
                                                  **kwargs)
            args.update(_args)

        try:
            del args["id"]
        except KeyError:
            pass

        if sign is None:
            sign = self.authn_requests_signed
        if (sign and self.sec.cert_handler.generate_cert()) or \
                        client_crt is not None:
            with self.lock:
                self.sec.cert_handler.update_cert(True, client_crt)
                if client_crt is not None:
                    sign_prepare = True
                return self._message(AuthnRequest, destination, message_id,
                                     consent, extensions, sign, sign_prepare,
                                     protocol_binding=binding,
                                     scoping=scoping, nsprefix=nsprefix,
                                     sign_alg=sign_alg, digest_alg=digest_alg,
                                     **args)
        return self._message(AuthnRequest, destination, message_id, consent,
                             extensions, sign, sign_prepare,
                             protocol_binding=binding,
                             scoping=scoping, nsprefix=nsprefix,
                             sign_alg=sign_alg, digest_alg=digest_alg, **args)

class Saml2ClientSpid(SpidBase):
    def __init__(self, *args, **kwargs):
        super(Saml2ClientSpid, self).__init__(*args, **kwargs)

class NameIDPolicyTypeSpid_(SamlBase):
    """The urn:oasis:names:tc:SAML:2.0:protocol:NameIDPolicyType element """

    c_tag = 'NameIDPolicyType'
    c_namespace = NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_attributes['Format'] = ('format', 'anyURI', False)
    c_attributes['SPNameQualifier'] = ('sp_name_qualifier', 'string', False)

    def __init__(self,
                 format=None,
                 sp_name_qualifier=None,
                 text=None,
                 extension_elements=None,
                 extension_attributes=None,
                 ):
        SamlBase.__init__(self,
                          text=text,
                          extension_elements=extension_elements,
                          extension_attributes=extension_attributes,
                          )
        self.format = format
        self.sp_name_qualifier = sp_name_qualifier


class NameIDPolicySpid(NameIDPolicyTypeSpid_):
    """The urn:oasis:names:tc:SAML:2.0:protocol:NameIDPolicy element """
    c_tag = 'NameIDPolicy'
    c_namespace = samlp.NAMESPACE
    c_children = NameIDPolicyTypeSpid_.c_children.copy()
    c_attributes = NameIDPolicyTypeSpid_.c_attributes.copy()
    c_child_order = NameIDPolicyTypeSpid_.c_child_order[:]
    c_cardinality = NameIDPolicyTypeSpid_.c_cardinality.copy()