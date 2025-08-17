from dataclasses import dataclass
from . import factories
# For SoftWebauthn
import json
import os
from base64 import urlsafe_b64encode
from struct import pack
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData
from fido2.utils import sha256

@dataclass(frozen=True)
class _HTTP_STATUS_CODE:
  # Informational - 1xx
  HTTP_100_CONTINUE:              int = 100
  HTTP_101_SWITCHING_PROTOCOLS:   int = 101
  HTTP_102_PROCESSING:            int = 102
  HTTP_103_EARLY_HINTS:           int = 103
  # Successful - 2xx
  HTTP_200_OK:                    int = 200
  HTTP_201_CREATED:               int = 201
  HTTP_202_ACCEPTED:              int = 202
  HTTP_204_NO_CONTENT:            int = 204
  HTTP_205_RESET_CONTENT:         int = 205
  HTTP_206_PARTIAL_CONTENT:       int = 206
  HTTP_207_MULTI_STATUS:          int = 207
  HTTP_208_ALREADY_REPORTED:      int = 208
  HTTP_226_IM_USED:               int = 226
  # Redirection - 3xx
  HTTP_300_MULTIPLE_CHOICES:      int = 300
  HTTP_301_MOVED_PERMANENTLY:     int = 301
  HTTP_302_FOUND:                 int = 302
  HTTP_303_SEE_OTHER:             int = 303
  HTTP_304_NOT_MODIFIED:          int = 304
  HTTP_305_USE_PROXY:             int = 305
  HTTP_306_RESERVED:              int = 306
  HTTP_307_TEMPORARY_REDIRECT:    int = 307
  HTTP_308_PERMANENT_REDIRECT:    int = 308
  # Client Error - 4xx
  HTTP_400_BAD_REQUEST:           int = 400
  HTTP_401_UNAUTHORIZED:          int = 401
  HTTP_402_PAYMENT_REQUIRED:      int = 402
  HTTP_403_FORBIDDEN:             int = 403
  HTTP_404_NOT_FOUND:             int = 404
  HTTP_405_METHOD_NOT_ALLOWED:    int = 405
  HTTP_406_NOT_ACCEPTABLE:        int = 406
  HTTP_408_REQUEST_TIMEOUT:       int = 408
  # Server Error - 5xx
  HTTP_500_INTERNAL_SERVER_ERROR: int = 500
  HTTP_501_NOT_IMPLEMENTED:       int = 501
  HTTP_502_BAD_GATEWAY:           int = 502
  HTTP_503_SERVICE_UNAVAILABLE:   int = 503
  HTTP_504_GATEWAY_TIMEOUT:       int = 504

  def __judge_code(self, status_code, target):
    return (status_code // 100) == target

  def is_informational(self, status_code):
    return self.__judge_code(status_code, 1) # 1xx
  def is_success(self, status_code):
    return self.__judge_code(status_code, 2) # 2xx
  def is_redirect(self, status_code):
    return self.__judge_code(status_code, 3) # 3xx
  def is_client_error(self, status_code):
    return self.__judge_code(status_code, 4) # 4xx
  def is_server_error(self, status_code):
    return self.__judge_code(status_code, 5) # 5xx

status = _HTTP_STATUS_CODE()

class SoftWebauthnDevice:
  def __init__(self):
    self.credential_id = None
    self.private_key = None
    self.aaguid = b'\x00'*16
    self.rp_id = None
    self.user_handle = None
    self.sign_count = 0

  def cred_init(self, rp_id, user_handle):
    self.credential_id = os.urandom(32)
    self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    self.rp_id = rp_id
    self.user_handle = user_handle

  def cred_as_attested(self):
    key = ES256.from_cryptography_key(self.private_key.public_key())
    data = AttestedCredentialData.create(self.aaguid, self.credential_id, key)

    return data

  def create(self, options, origin):
    if {'alg': -7, 'type': 'public-key'} not in options['publicKey']['pubKeyCredParams']:
      raise ValueError('Requested pubKeyCredParams does not contain supported type')

    if ('attestation' in options['publicKey']) and (options['publicKey']['attestation'] not in [None, 'none']):
      raise ValueError('Only none attestation supported')

    # prepare new key
    self.cred_init(options['publicKey']['rp']['id'], options['publicKey']['user']['id'])
    # generate credential response
    client_data = {
      'type': 'webauthn.create',
      'challenge': options['publicKey']['challenge'].decode('utf-8').rstrip('='),
      'origin': origin,
    }
    rp_id_hash = sha256(self.rp_id.encode('utf8'))
    flags = b'\x41'  # attested_data + user_present
    sign_count = pack('>I', self.sign_count)
    credential_id_length = pack('>H', len(self.credential_id))
    cose_key = cbor.encode(ES256.from_cryptography_key(self.private_key.public_key()))
    auth_data = rp_id_hash + flags + sign_count + self.aaguid + credential_id_length + self.credential_id + cose_key
    attestation_object = {
      'authData': auth_data,
      'fmt': 'none',
      'attStmt': {},
    }
    credentials = {
      'id': urlsafe_b64encode(self.credential_id).decode('utf-8'),
      'rawId': urlsafe_b64encode(self.credential_id).decode('utf-8'),
      'response': {
        'clientDataJSON': urlsafe_b64encode(json.dumps(client_data).encode('utf-8')).decode('ascii'),
        'attestationObject':  urlsafe_b64encode(cbor.encode(attestation_object)).decode('utf-8'),
      },
      'type': 'public-key',
    }

    return credentials

  def get(self, options, origin):
    if self.rp_id != options['publicKey']['rpId']:
        raise ValueError('Requested rpID does not match current credential')
    self.sign_count += 1
    # prepare signature
    client_data = json.dumps({
      'type': 'webauthn.get',
      'challenge': (options['publicKey']['challenge']).decode('ascii').rstrip('='),
      'origin': origin
    }).encode('utf-8')
    client_data_hash = sha256(client_data)
    rp_id_hash = sha256(self.rp_id.encode('ascii'))
    flags = b'\x01'
    sign_count = pack('>I', self.sign_count)
    authenticator_data = rp_id_hash + flags + sign_count
    signature = self.private_key.sign(authenticator_data + client_data_hash, ec.ECDSA(hashes.SHA256()))
    # generate assertion
    assertion = {
      'id': urlsafe_b64encode(self.credential_id).decode('ascii'),
      'rawId': urlsafe_b64encode(self.credential_id).decode('ascii'),
      'response': {
        'authenticatorData': urlsafe_b64encode(authenticator_data).decode('ascii'),
        'clientDataJSON': urlsafe_b64encode(client_data).decode('ascii'),
        'signature': urlsafe_b64encode(signature).decode('ascii'),
        'userHandle': self.user_handle
      },
      'type': 'public-key'
    }

    return assertion

__all__ = [
  'status',
  'factories',
  'SoftWebauthnDevice',
]