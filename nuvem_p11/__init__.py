"""SerproID cloud-token protocol, reimplemented in Python.

Reimplementation of the SerproID PKCS#11 module (``libserproidp11.so``, version 2.1.6). Split
in three layers:

* the protocol core (:mod:`nuvem_p11.client`) -- environment/host resolution, the signing
  request, the status poll and the signature decoding;
* a PKCS#11 binding (:mod:`nuvem_p11.p11`) that exposes the same ABI the official module
  exposes to NSS/Firefox/Chromium;
* the configuration utility (:mod:`nuvem_p11.cli`), the console counterpart of the official
  JavaFX desktop: enroll the machine, install the certificates into the browsers, test.

"""

from .client import ALGORITHM_NAMES, PSS, PSS_SALT_LEN_MD, Endpoint, PssParams, SerproIDClient
from .config import AMBIENTE_PRODUCTION, Config, DeviceInfo
from .errors import CKR_OK, SerproIDError
from .setup import IssuedCertificate, install_user_certificates, parse_certificates

__all__ = [
    "ALGORITHM_NAMES",
    "AMBIENTE_PRODUCTION",
    "CKR_OK",
    "Config",
    "DeviceInfo",
    "Endpoint",
    "IssuedCertificate",
    "PSS",
    "PSS_SALT_LEN_MD",
    "PssParams",
    "SerproIDClient",
    "SerproIDError",
    "install_user_certificates",
    "parse_certificates",
]

__version__ = "2.1.6"
