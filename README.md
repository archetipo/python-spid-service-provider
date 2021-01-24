# Introduction

#### WIP WIP 

This is a minimalist example for italian Spid SAML Service Provider service written using [Flask](http://flask.pocoo.org/)
and implementa a hard refactoring of [python3-saml](https://github.com/onelogin/python3-saml). Only for test purpose.

# Requirements

- [Docker](https://docs.docker.com/) 

You will also need a development environment capable of compiling Python packages and the "libffi" and "libxmlsec1"
development libraries, which are needed by python3-saml.

Instructions for installing these development libraries will differ depending on your host operating system.

### How to build and run with Docker

These instructions allow you to test this project with spid-testnv2 and create SP metadata
that pass all checks of spid saml check.

Spid Saml Check `https` check, pass only if you run this project under https url.

1. Clone repo

   ```shell
   git clone https://github.com/archetipo/python-spid-service-provider.git
   ```

1. go to folrder

   ```shell
   cd python-spid-service-provider
   ```
1. make certs
  
   go to  saml/certs and type
   
    ```shell
   $ openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -keyout sp.key -out sp.crt
    ``` 

1. make settings
  
   ``` shell
   cp settings.json.example saml/settings.json
   ```
   
   ``` shell
   cp advanced_settings.json.example saml/advanced_settings.json
   ```
   
   in settings.json type
    
   ```
    base_url_sp = IP:5000 or host of this project
    base_url_idp =  url where spid-testenv2 running
    x509_idp = read this data from spid-testenv2 metadata 
   ```

    ```shell
   $ openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -keyout sp.key -out sp.crt
    ``` 
    
   in advanced_settings.json edit the `IPACode` this field is mandatory for spid saml check
   


1. build Docker image

   ```shell
   docker build -t italia/spid-sp-test .
   ```

1. run container:

   ```shell
   docker run -p 5000:5000 italia/spid-sp-test
   ```

# Check with spid-saml-check

Follow the instructions for build and run [spid-saml-check] (https://github.com/italia/spid-saml-check)

# Testing with spid-testenv2

The fastest way to test this example SAML SP is to use the [spid-testenv2](https://github.com/italia/spid-testenv2)
service.

Here is how:

1. Configure and Start Idp spid-testenv2

   [Configure and install spid-testenv2](https://github.com/italia/spid-testenv2#installazione)


# Contact

Updates or corrections to this document are very welcome. Feel free

Additionally, comments or questions can be sent to:
&#97;&#108;&#101;&#115;&#115;&#105;&#111;&#46;&#103;&#101;&#114;&#97;&#99;&#101;&#64;&#103;&#109;&#97;&#105;&#108;&#46;&#99;&#111;&#109;

License
-------

LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl.html).

Author Information
------------------

Alessio Gerace 2018-2020