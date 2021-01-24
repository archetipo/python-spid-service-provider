# Introduction

#### WIP

This is an example for italian Spid SAML Service Provider service written using [Flask](http://flask.pocoo.org/)
and [pysaml2](https://github.com/rohe/pysaml2). Only for test purpose.

# Requirements

- [Python](https://www.python.org/) 3.7+
- [Virtualenv](https://virtualenv.pypa.io/en/latest/)
- [pip](https://pip.pypa.io/en/stable/)

You will also need a development environment capable of compiling Python packages and the "libffi" and "libxmlsec1"
development libraries, which are needed by PySAML2.

Instructions for installing these development libraries will differ depending on your host operating system.

### Docker (consigliata)

1. Clonare il repository in locale

   ```shell
   git clone https://github.com/archetipo/python-spid-service-provider.git
   ```

1. Entrare nella directory

   ```shell
   cd python-spid-service-provider
   ```

1. Fare build dell'immagine

   ```shell
   docker build -t italia/spid-sp-test .
   ```

1. Lanciare il container:

   ```shell
   docker run -p 5000:5000 italia/spid-sp-test
   ```

## Mac OS X

```shell
$ brew install libffi libxmlsec1
```

## Ubuntu

```shell
$ sudo apt install libffi-devel xmlsec1 xmlsec1-openssl
```

# Installation

```shell
$ virtualenv venv
$ . venv/bin/activate
$ pip install -r requirements.txt 
```

# Configuration

 ```shell
$ openssl req -x509 -nodes -sha256 -days 365 -newkey rsa:2048 -keyout sp.key -out sp.crt
 ``` 

 ```shell
$ cp config.yaml.example config.yaml
 ```

  ```shell
$  '0.0.0.0 spid-sp-test' >> /etc/hosts
 ```

# Running

 ```shell
$ python app.py 
 ```

# Testing

The fastest way to test this example SAML SP is to use the [spid-testenv2](https://github.com/italia/spid-testenv2)
service.

Here is how:

1. Configure and Start Idp spid-testenv2

   [Configure and install spid-testenv2](https://github.com/italia/spid-testenv2#installazione)

2. Start the example Spid Service Provider

   ```shell
   $ python app.py
   ```

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