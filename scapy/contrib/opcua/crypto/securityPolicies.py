from abc import ABCMeta, abstractmethod
from scapy.contrib.opcua.binary.schemaTypes import UaMessageSecurityMode

try:
    from scapy.contrib.opcua.crypto import uacrypto
    
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

POLICY_NONE_URI = 'http://opcfoundation.org/UA/SecurityPolicy#None'


class CryptographyNone(object):
    """
    Base class for symmetric/asymmetric cryprography
    """
    
    def __init__(self):
        pass
    
    def plain_block_size(self):
        """
        Size of plain text block for block cipher.
        """
        return 1
    
    def encrypted_block_size(self):
        """
        Size of encrypted text block for block cipher.
        """
        return 1
    
    def padding(self, size):
        """
        Create padding for a block of given size.
        plain_size = size + len(padding) + signature_size()
        plain_size = N * plain_block_size()
        """
        return b''
    
    def min_padding_size(self):
        return 0
    
    def signature_size(self):
        return 0
    
    def signature(self, data):
        return b''
    
    def encrypt(self, data):
        return data
    
    def decrypt(self, data):
        return data
    
    def vsignature_size(self):
        return 0
    
    def verify(self, data, signature):
        """
        Verify signature and raise exception if signature is invalid
        """
        pass
    
    def remove_padding(self, data):
        return data


def require_cryptography(obj):
    """
    Raise exception if cryptography module is not available.
    Call this function in constructors.
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        raise RuntimeError("Can't use {0}, cryptography module is not installed".format(obj.__class__.__name__))


class Signer(object):
    """
    Abstract base class for cryptographic signature algorithm
    """
    
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def signature_size(self):
        pass
    
    @abstractmethod
    def signature(self, data):
        pass


class Verifier(object):
    """
    Abstract base class for cryptographic signature verification
    """
    
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def signature_size(self):
        pass
    
    @abstractmethod
    def verify(self, data, signature):
        pass


class Encrypter(object):
    """
    Abstract base class for encryption algorithm
    """
    
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def plain_block_size(self):
        pass
    
    @abstractmethod
    def encrypted_block_size(self):
        pass
    
    @abstractmethod
    def encrypt(self, data):
        pass


class Decrypter(object):
    """
    Abstract base class for decryption algorithm
    """
    
    __metaclass__ = ABCMeta
    
    @abstractmethod
    def plain_block_size(self):
        pass
    
    @abstractmethod
    def encrypted_block_size(self):
        pass
    
    @abstractmethod
    def decrypt(self, data):
        pass


class Cryptography(CryptographyNone):
    """
    Security policy: Sign or SignAndEncrypt
    """
    
    def __init__(self, mode=UaMessageSecurityMode.Sign):
        super(Cryptography, self).__init__()
        self.Signer = None
        self.Verifier = None
        self.Encrypter = None
        self.Decrypter = None
        self.RemoteDecrypter = None
        self.RemoteVerifier = None
        assert mode in (UaMessageSecurityMode.Sign,
                        UaMessageSecurityMode.SignAndEncrypt)
        self.is_encrypted = (mode == UaMessageSecurityMode.SignAndEncrypt)
    
    def plain_block_size(self):
        """
        Size of plain text block for block cipher.
        """
        if self.is_encrypted:
            return self.Encrypter.plain_block_size()
        return 1
    
    def encrypted_block_size(self):
        """
        Size of encrypted text block for block cipher.
        """
        if self.is_encrypted:
            return self.Encrypter.encrypted_block_size()
        return 1
    
    def padding(self, size):
        """
        Create padding for a block of given size.
        plain_size = size + len(padding) + signature_size()
        plain_size = N * plain_block_size()
        """
        if not self.is_encrypted:
            return b''
        block_size = self.Encrypter.plain_block_size()
        rem = (size + self.signature_size() + 1) % block_size
        if rem != 0:
            rem = block_size - rem
        return bytes(bytearray([rem])) * (rem + 1)
    
    def min_padding_size(self):
        if self.is_encrypted:
            return 1
        return 0
    
    def signature_size(self):
        return self.Signer.signature_size()
    
    def signature(self, data):
        return self.Signer.signature(data)
    
    def vsignature_size(self):
        return self.Verifier.signature_size()
    
    def verify(self, data, sig):
        self.Verifier.verify(data, sig)
    
    def verify_remote(self, data, sig):
        self.RemoteVerifier.verify(data, sig)
    
    def encrypt(self, data):
        if self.is_encrypted:
            assert len(data) % self.Encrypter.plain_block_size() == 0
            return self.Encrypter.encrypt(data)
        return data
    
    def decrypt(self, data):
        if self.is_encrypted:
            return self.Decrypter.decrypt(data)
        return data
    
    def decrypt_remote(self, data):
        if self.is_encrypted:
            return self.RemoteDecrypter.decrypt(data)
        return data
    
    def remove_padding(self, data):
        if self.is_encrypted:
            pad_size = bytearray(data[-1:])[0] + 1
            return data[:-pad_size]
        return data


class SignerRsa(Signer):
    
    def __init__(self, client_pk):
        require_cryptography(self)
        self.client_pk = client_pk
        self.key_size = self.client_pk.key_size // 8
    
    def signature_size(self):
        return self.key_size
    
    def signature(self, data):
        return uacrypto.sign_sha1(self.client_pk, data)


class VerifierRsa(Verifier):
    
    def __init__(self, server_cert):
        require_cryptography(self)
        self.server_cert = server_cert
        self.key_size = self.server_cert.public_key().key_size // 8
    
    def signature_size(self):
        return self.key_size
    
    def verify(self, data, signature):
        uacrypto.verify_sha1(self.server_cert, data, signature)


class EncrypterRsa(Encrypter):
    
    def __init__(self, server_cert, enc_fn, padding_size):
        require_cryptography(self)
        self.server_cert = server_cert
        self.key_size = self.server_cert.public_key().key_size // 8
        self.encryptor = enc_fn
        self.padding_size = padding_size
    
    def plain_block_size(self):
        return self.key_size - self.padding_size
    
    def encrypted_block_size(self):
        return self.key_size
    
    def encrypt(self, data):
        encrypted = b''
        block_size = self.plain_block_size()
        for i in range(0, len(data), block_size):
            encrypted += self.encryptor(self.server_cert.public_key(),
                                        data[i: i + block_size])
        return encrypted


class DecrypterRsa(Decrypter):
    
    def __init__(self, client_pk, dec_fn, padding_size):
        require_cryptography(self)
        self.client_pk = client_pk
        self.key_size = self.client_pk.key_size // 8
        self.decryptor = dec_fn
        self.padding_size = padding_size
    
    def plain_block_size(self):
        return self.key_size - self.padding_size
    
    def encrypted_block_size(self):
        return self.key_size
    
    def decrypt(self, data):
        decrypted = b''
        block_size = self.encrypted_block_size()
        for i in range(0, len(data), block_size):
            decrypted += self.decryptor(self.client_pk,
                                        data[i: i + block_size])
        return decrypted


class SignerAesCbc(Signer):
    
    def __init__(self, key):
        require_cryptography(self)
        self.key = key
    
    def signature_size(self):
        return uacrypto.sha1_size()
    
    def signature(self, data):
        return uacrypto.hmac_sha1(self.key, data)


class VerifierAesCbc(Verifier):
    
    def __init__(self, key):
        require_cryptography(self)
        self.key = key
    
    def signature_size(self):
        return uacrypto.sha1_size()
    
    def verify(self, data, signature):
        expected = uacrypto.hmac_sha1(self.key, data)
        if signature != expected:
            raise uacrypto.InvalidSignature


class EncrypterAesCbc(Encrypter):
    
    def __init__(self, key, init_vec):
        require_cryptography(self)
        self.cipher = uacrypto.cipher_aes_cbc(key, init_vec)
    
    def plain_block_size(self):
        return self.cipher.algorithm.key_size // 8
    
    def encrypted_block_size(self):
        return self.cipher.algorithm.key_size // 8
    
    def encrypt(self, data):
        return uacrypto.cipher_encrypt(self.cipher, data)


class DecrypterAesCbc(Decrypter):
    
    def __init__(self, key, init_vec):
        require_cryptography(self)
        self.cipher = uacrypto.cipher_aes_cbc(key, init_vec)
    
    def plain_block_size(self):
        return self.cipher.algorithm.key_size // 8
    
    def encrypted_block_size(self):
        return self.cipher.algorithm.key_size // 8
    
    def decrypt(self, data):
        return uacrypto.cipher_decrypt(self.cipher, data)


class SecurityPolicy(object):
    """
    Base class for security policy
    """
    URI = "http://opcfoundation.org/UA/SecurityPolicy#None"
    signature_key_size = 0
    symmetric_key_size = 0
    
    def __init__(self):
        self.asymmetric_cryptography = CryptographyNone()
        self.symmetric_cryptography = CryptographyNone()
        self.Mode = getattr(UaMessageSecurityMode, "None")
        self.server_certificate = None
        self.client_certificate = None
        self.server_pk = None
        self.client_pk = None
    
    def make_symmetric_key(self, a, b):
        pass


class SecurityPolicyBasic128Rsa15(SecurityPolicy):
    """
    Security Basic 128Rsa15
    A suite of algorithms that uses RSA15 as Key-Wrap-algorithm
    and 128-Bit (16 bytes) for encryption algorithms.
    - SymmetricSignatureAlgorithm - HmacSha1
      (http://www.w3.org/2000/09/xmldsig#hmac-sha1)
    - SymmetricEncryptionAlgorithm - Aes128
      (http://www.w3.org/2001/04/xmlenc#aes128-cbc)
    - AsymmetricSignatureAlgorithm - RsaSha1
      (http://www.w3.org/2000/09/xmldsig#rsa-sha1)
    - AsymmetricKeyWrapAlgorithm - KwRsa15
      (http://www.w3.org/2001/04/xmlenc#rsa-1_5)
    - AsymmetricEncryptionAlgorithm - Rsa15
      (http://www.w3.org/2001/04/xmlenc#rsa-1_5)
    - KeyDerivationAlgorithm - PSha1
      (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1)
    - DerivedSignatureKeyLength - 128 (16 bytes)
    - MinAsymmetricKeyLength - 1024 (128 bytes)
    - MaxAsymmetricKeyLength - 2048 (256 bytes)
    - CertificateSignatureAlgorithm - Sha1

    If a certificate or any certificate in the chain is not signed with
    a hash that is Sha1 or stronger then the certificate shall be rejected.
    """
    
    URI = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
    signature_key_size = 16
    symmetric_key_size = 16
    AsymmetricEncryptionURI = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
    
    @staticmethod
    def encrypt_asymmetric(pubkey, data):
        return uacrypto.encrypt_rsa15(pubkey, data)
    
    def __init__(self, server_cert, server_pk, client_cert, client_pk, mode):
        super(SecurityPolicyBasic128Rsa15, self).__init__()
        require_cryptography(self)
        if isinstance(server_cert, bytes):
            server_cert = uacrypto.x509_from_der(server_cert)
        # even in Sign mode we need to asymmetrically encrypt secrets
        # transmitted in OpenSecureChannel. So SignAndEncrypt here
        self.asymmetric_cryptography = Cryptography(UaMessageSecurityMode.SignAndEncrypt)
        self.asymmetric_cryptography.Signer = SignerRsa(client_pk)
        self.asymmetric_cryptography.Verifier = VerifierRsa(server_cert)
        self.asymmetric_cryptography.Encrypter = EncrypterRsa(server_cert, uacrypto.encrypt_rsa15, 11)
        self.asymmetric_cryptography.Decrypter = DecrypterRsa(client_pk, uacrypto.decrypt_rsa15, 11)
        if server_pk is not None:
            self.asymmetric_cryptography.RemoteDecrypter = DecrypterRsa(server_pk, uacrypto.decrypt_rsa15, 11)
        self.asymmetric_cryptography.RemoteVerifier = VerifierRsa(client_cert)
        self.symmetric_cryptography = Cryptography(mode)
        self.Mode = mode
        self.server_certificate = uacrypto.der_from_x509(server_cert)
        self.client_certificate = uacrypto.der_from_x509(client_cert)
        
        self.server_pk = server_pk
        self.client_pk = client_pk
    
    def make_symmetric_key(self, nonce1, nonce2):
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)
        
        (sigkey, key, init_vec) = uacrypto.p_sha1(nonce2, nonce1, key_sizes)
        self.symmetric_cryptography.Signer = SignerAesCbc(sigkey)
        self.symmetric_cryptography.Encrypter = EncrypterAesCbc(key, init_vec)
        self.symmetric_cryptography.RemoteDecrypter = DecrypterAesCbc(key, init_vec)
        self.symmetric_cryptography.RemoteVerifier = VerifierAesCbc(sigkey)
        
        (sigkey, key, init_vec) = uacrypto.p_sha1(nonce1, nonce2, key_sizes)
        self.symmetric_cryptography.Verifier = VerifierAesCbc(sigkey)
        self.symmetric_cryptography.Decrypter = DecrypterAesCbc(key, init_vec)


class SecurityPolicyBasic256(SecurityPolicy):
    """
    Security Basic 256
    A suite of algorithms that are for 256-Bit (32 bytes) encryption,
    algorithms include:
    - SymmetricSignatureAlgorithm - HmacSha1
      (http://www.w3.org/2000/09/xmldsig#hmac-sha1)
    - SymmetricEncryptionAlgorithm - Aes256
      (http://www.w3.org/2001/04/xmlenc#aes256-cbc)
    - AsymmetricSignatureAlgorithm - RsaSha1
      (http://www.w3.org/2000/09/xmldsig#rsa-sha1)
    - AsymmetricKeyWrapAlgorithm - KwRsaOaep
      (http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p)
    - AsymmetricEncryptionAlgorithm - RsaOaep
      (http://www.w3.org/2001/04/xmlenc#rsa-oaep)
    - KeyDerivationAlgorithm - PSha1
      (http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_sha1)
    - DerivedSignatureKeyLength - 192 (24 bytes)
    - MinAsymmetricKeyLength - 1024 (128 bytes)
    - MaxAsymmetricKeyLength - 2048 (256 bytes)
    - CertificateSignatureAlgorithm - Sha1

    If a certificate or any certificate in the chain is not signed with
    a hash that is Sha1 or stronger then the certificate shall be rejected.
    """
    
    URI = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"
    signature_key_size = 24
    symmetric_key_size = 32
    AsymmetricEncryptionURI = "http://www.w3.org/2001/04/xmlenc#rsa-oaep"
    
    @staticmethod
    def encrypt_asymmetric(pubkey, data):
        return uacrypto.encrypt_rsa_oaep(pubkey, data)
    
    def __init__(self, server_cert, server_pk, client_cert, client_pk, mode):
        super(SecurityPolicyBasic256, self).__init__()
        require_cryptography(self)
        if isinstance(server_cert, bytes):
            server_cert = uacrypto.x509_from_der(server_cert)
        # even in Sign mode we need to asymmetrically encrypt secrets
        # transmitted in OpenSecureChannel. So SignAndEncrypt here
        self.asymmetric_cryptography = Cryptography(UaMessageSecurityMode.SignAndEncrypt)
        self.asymmetric_cryptography.Signer = SignerRsa(client_pk)
        self.asymmetric_cryptography.Verifier = VerifierRsa(server_cert)
        self.asymmetric_cryptography.Encrypter = EncrypterRsa(
            server_cert, uacrypto.encrypt_rsa_oaep, 42)
        self.asymmetric_cryptography.Decrypter = DecrypterRsa(
            client_pk, uacrypto.decrypt_rsa_oaep, 42)
        if server_pk is not None:
            self.asymmetric_cryptography.RemoteDecrypter = DecrypterRsa(server_pk, uacrypto.decrypt_rsa_oaep, 42)
        self.asymmetric_cryptography.RemoteVerifier = VerifierRsa(client_cert)
        self.symmetric_cryptography = Cryptography(mode)
        self.Mode = mode
        self.server_certificate = uacrypto.der_from_x509(server_cert)
        self.client_certificate = uacrypto.der_from_x509(client_cert)
        
        self.server_pk = server_pk
        self.client_pk = client_pk
    
    def make_symmetric_key(self, nonce1, nonce2):
        # specs part 6, 6.7.5
        key_sizes = (self.signature_key_size, self.symmetric_key_size, 16)
        
        (sigkey, key, init_vec) = uacrypto.p_sha1(nonce2, nonce1, key_sizes)
        self.symmetric_cryptography.Signer = SignerAesCbc(sigkey)
        self.symmetric_cryptography.Encrypter = EncrypterAesCbc(key, init_vec)
        self.symmetric_cryptography.RemoteDecrypter = DecrypterAesCbc(key, init_vec)
        self.symmetric_cryptography.RemoteVerifier = VerifierAesCbc(sigkey)
        
        (sigkey, key, init_vec) = uacrypto.p_sha1(nonce1, nonce2, key_sizes)
        self.symmetric_cryptography.Verifier = VerifierAesCbc(sigkey)
        self.symmetric_cryptography.Decrypter = DecrypterAesCbc(key, init_vec)


def encrypt_asymmetric(pubkey, data, policy_uri):
    """
    Encrypt data with pubkey using an asymmetric algorithm.
    The algorithm is selected by policy_uri.
    Returns a tuple (encrypted_data, algorithm_uri)
    """
    for cls in [SecurityPolicyBasic256, SecurityPolicyBasic128Rsa15]:
        if policy_uri == cls.URI:
            return (cls.encrypt_asymmetric(pubkey, data),
                    cls.AsymmetricEncryptionURI)
    if not policy_uri or policy_uri == POLICY_NONE_URI:
        return (data, '')
    raise RuntimeError("Unsupported security policy `{0}`".format(policy_uri))
