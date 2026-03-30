import secrets
import hashlib
import hmac
import base64
import struct
import time
import json
import os
from typing import Tuple, List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from enum import IntEnum


class EncryptionLevel(IntEnum):
    PREVIEW = 1
    VERBOSE = 2
    REVERSIBLE = 3
    MLKEM_FULL = 4


@dataclass
class StepLog:
    step_num: int
    title: str
    description: str
    variables: Dict[str, Any] = field(default_factory=dict)
    hex_data: Optional[str] = None
    explanation: str = ""


@dataclass
class EncryptionResult:
    success: bool
    level: int
    plaintext: bytes
    plaintext_hex: str
    ciphertext: bytes
    ciphertext_hex: str
    ciphertext_b64: str
    seed: bytes
    seed_hex: str
    otp_key: bytes
    otp_key_hex: str
    mlkem_public_key: bytes
    mlkem_secret_key: bytes
    mlkem_encapsulated: bytes
    shared_secret: bytes
    steps: List[StepLog]
    preview_100: str
    timestamp: float
    file_name: Optional[str] = None
    encoding: Optional[str] = None
    error: Optional[str] = None
    per_byte_log: List[Dict] = field(default_factory=list)
    mac: Optional[str] = None
    nonce: Optional[str] = None


@dataclass
class ReversiblePair:
    correct_file: bytes
    tampered_file: bytes
    correct_key: bytes
    tampered_key: bytes
    n_tampered: int
    tampered_positions: List[int]


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = bytes(hashlib.sha256().digest_size)
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, length: int, info: bytes = b"") -> bytes:
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + i.to_bytes(1, "big"), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def hkdf(salt: bytes, ikm: bytes, length: int, info: bytes = b"") -> bytes:
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, length, info)


class MLKEMSimulator:
    """
    Симулятор ML-KEM (Kyber-768).
    В реальной системе используется liboqs/pq-crystals.
    Здесь воспроизведена структура: keygen → encaps → decaps.
    """

    KYBER_K = 3
    KYBER_N = 256
    KYBER_Q = 3329
    KYBER_ETA1 = 2
    KYBER_ETA2 = 2
    PUBLIC_KEY_BYTES = 1184
    SECRET_KEY_BYTES = 2400
    CIPHERTEXT_BYTES = 1088
    SHARED_SECRET_BYTES = 32

    def __init__(self, seed: Optional[bytes] = None):
        self._seed = seed or secrets.token_bytes(64)
        self._rng_state = self._seed

    def _deterministic_bytes(self, n: int, domain: bytes = b"") -> bytes:
        return hkdf(self._seed, domain, n, info=b"mlkem-sim-" + domain[:8])

    def keygen(self) -> Tuple[bytes, bytes]:
        pk_seed = self._deterministic_bytes(32, b"pk-seed")
        sk_seed = self._deterministic_bytes(32, b"sk-seed")

        rho = hkdf(pk_seed, b"rho", 32, b"rho")
        sigma = hkdf(sk_seed, b"sigma", 32, b"sigma")

        pk_core = hkdf(rho + sigma, b"pk-core", self.PUBLIC_KEY_BYTES - 32, b"pk")
        public_key = rho + pk_core

        sk_s = hkdf(sigma, b"sk-s", 768, b"s")
        pk_hash = hashlib.sha3_256(public_key).digest()
        z = secrets.token_bytes(32)
        secret_key = sk_s + public_key + pk_hash + z

        return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        m = secrets.token_bytes(32)
        pk_hash = hashlib.sha3_256(public_key).digest()

        g_input = m + pk_hash
        g_output = hashlib.sha3_512(g_input).digest()
        K_bar = g_output[:32]
        r = g_output[32:]

        ct_core = hkdf(r + public_key[:32], b"ct", self.CIPHERTEXT_BYTES - 32, b"ct")
        ciphertext = hashlib.sha3_256(m).digest() + ct_core

        h_c = hashlib.sha3_256(ciphertext).digest()
        shared_secret = hkdf(
            K_bar + h_c, b"ss", self.SHARED_SECRET_BYTES, b"shared-secret"
        )

        return ciphertext, shared_secret

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        pk_bytes = self.PUBLIC_KEY_BYTES
        pk = secret_key[768 : 768 + pk_bytes]
        pk_hash_stored = secret_key[768 + pk_bytes : 768 + pk_bytes + 32]
        z = secret_key[768 + pk_bytes + 32 : 768 + pk_bytes + 64]

        m_prime_hash = ciphertext[:32]
        K_bar_prime = hkdf(m_prime_hash + pk_hash_stored, b"Kbar", 32, b"decaps-Kbar")
        r_prime = hkdf(m_prime_hash + pk_hash_stored, b"r", 32, b"decaps-r")

        ct_check = hkdf(r_prime + pk[:32], b"ct", self.CIPHERTEXT_BYTES - 32, b"ct")
        ct_reconstructed = m_prime_hash + ct_check

        ct_valid = hmac.compare_digest(ciphertext, ct_reconstructed)
        h_c = hashlib.sha3_256(ciphertext).digest()

        if ct_valid:
            shared_secret = hkdf(
                K_bar_prime + h_c, b"ss", self.SHARED_SECRET_BYTES, b"shared-secret"
            )
        else:
            K_implicit = hkdf(
                z + h_c, b"implicit", self.SHARED_SECRET_BYTES, b"implicit-reject"
            )
            shared_secret = K_implicit

        return shared_secret


def compute_mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def detect_encoding(data: bytes) -> Optional[str]:
    encodings = ["utf-8", "utf-16", "latin-1", "cp1251", "ascii"]
    for enc in encodings:
        try:
            data.decode(enc)
            return enc
        except Exception:
            continue
    return None


def encrypt(
    data: bytes,
    level: EncryptionLevel,
    file_name: Optional[str] = None,
    custom_seed: Optional[bytes] = None,
    custom_info: bytes = b"hybrid-otp-derivation-2026",
) -> EncryptionResult:
    steps: List[StepLog] = []
    per_byte_log: List[Dict] = []
    timestamp = time.time()

    encoding = detect_encoding(data)
    preview_100 = ""
    if encoding and level >= EncryptionLevel.PREVIEW:
        try:
            text = data.decode(encoding)
            preview_100 = text[:100]
        except Exception:
            pass

    steps.append(
        StepLog(
            step_num=1,
            title="Входные данные",
            description="Получены данные для шифрования",
            variables={
                "длина_байт": len(data),
                "кодировка": encoding or "бинарный файл",
                "имя_файла": file_name or "текст",
            },
            hex_data=data[:64].hex() + ("..." if len(data) > 64 else ""),
            explanation="На первом шаге мы получаем исходные данные в виде байт. "
            "UTF-8 — стандартная кодировка для текста. Бинарные файлы не имеют текстовой кодировки.",
        )
    )

    mlkem = MLKEMSimulator(seed=custom_seed)
    public_key, secret_key = mlkem.keygen()

    steps.append(
        StepLog(
            step_num=2,
            title="ML-KEM: Генерация ключевой пары",
            description="Алиса генерирует пару ключей ML-KEM (Kyber-768)",
            variables={
                "pk_длина": len(public_key),
                "sk_длина": len(secret_key),
                "rho": public_key[:32].hex(),
                "pk_hash": hashlib.sha3_256(public_key).hexdigest(),
            },
            hex_data=public_key[:32].hex(),
            explanation=(
                "ML-KEM (Module Learning with Errors Key Encapsulation Mechanism) — постквантовый алгоритм.\n"
                "keygen() создаёт: открытый ключ pk (1184 байта) и закрытый ключ sk (2400 байт).\n"
                "Безопасность основана на задаче Module-LWE — вычислительно неразрешимой даже для квантовых компьютеров.\n"
                "rho — публичное зерно для матрицы A. sigma — секретное зерно. pk = (A, b = A·s + e)."
            ),
        )
    )

    ciphertext_mlkem, shared_secret = mlkem.encapsulate(public_key)

    steps.append(
        StepLog(
            step_num=3,
            title="ML-KEM: Инкапсуляция",
            description="Отправитель инкапсулирует случайный ключ",
            variables={
                "ct_длина": len(ciphertext_mlkem),
                "shared_secret_hex": shared_secret.hex(),
                "ct_первые_32": ciphertext_mlkem[:32].hex(),
            },
            hex_data=shared_secret.hex(),
            explanation=(
                "encapsulate(pk) генерирует случайное m (32 байта).\n"
                "G(m || H(pk)) → K̄ || r — хеш-функция SHA3-512 создаёт пару значений.\n"
                "Шифртекст ct = (u, v) передаётся получателю по открытому каналу.\n"
                "Общий секрет K = KDF(K̄ || H(ct)) — оба участника вычисляют одинаковое значение.\n"
                "Перехватчик не может восстановить K без закрытого ключа sk."
            ),
        )
    )

    seed = shared_secret
    salt = secrets.token_bytes(32)
    nonce = secrets.token_bytes(16)

    prk = hkdf_extract(salt, seed)
    otp_key = hkdf_expand(prk, len(data), info=custom_info)

    steps.append(
        StepLog(
            step_num=4,
            title="HKDF: Растягивание ключа",
            description="Из shared_secret получаем OTP-ключ нужной длины",
            variables={
                "salt_hex": salt.hex(),
                "nonce_hex": nonce.hex(),
                "prk_hex": prk.hex(),
                "otp_длина": len(otp_key),
                "info": custom_info.decode(errors="replace"),
                "otp_первые_32": otp_key[:32].hex(),
            },
            hex_data=otp_key[:64].hex(),
            explanation=(
                "HKDF (HMAC-based Key Derivation Function, RFC 5869) — стандарт для получения ключей.\n"
                "Шаг Extract: PRK = HMAC-SHA256(salt, IKM) — нормализует энтропию входа.\n"
                "Шаг Expand: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i) — растягивает до нужной длины.\n"
                "Результат: псевдослучайный OTP-ключ той же длины, что и сообщение.\n"
                "Это теоретически стойкий OTP при условии, что shared_secret не повторяется."
            ),
        )
    )

    ciphertext_bytes = bytearray(len(data))
    for i, (p_byte, k_byte) in enumerate(zip(data, otp_key)):
        c_byte = p_byte ^ k_byte
        ciphertext_bytes[i] = c_byte
        if level >= EncryptionLevel.VERBOSE:
            p_char = chr(p_byte) if 32 <= p_byte <= 126 else "·"
            c_char = chr(c_byte) if 32 <= c_byte <= 126 else "·"
            per_byte_log.append(
                {
                    "idx": i,
                    "p_dec": p_byte,
                    "p_char": p_char,
                    "k_dec": k_byte,
                    "c_dec": c_byte,
                    "c_char": c_char,
                    "p_bin": format(p_byte, "08b"),
                    "k_bin": format(k_byte, "08b"),
                    "c_bin": format(c_byte, "08b"),
                }
            )

    ciphertext = bytes(ciphertext_bytes)
    mac_key = hkdf_expand(prk, 32, info=b"mac-key")
    mac = compute_mac(mac_key, ciphertext)

    steps.append(
        StepLog(
            step_num=5,
            title="XOR: Шифрование One-Time Pad",
            description="Каждый байт открытого текста XOR-ится с байтом ключа",
            variables={
                "операция": "ciphertext[i] = plaintext[i] XOR otp_key[i]",
                "зашифровано_байт": len(ciphertext),
                "MAC": mac.hex(),
                "mac_алгоритм": "HMAC-SHA256",
            },
            hex_data=ciphertext[:64].hex(),
            explanation=(
                "Шифр Вернама (One-Time Pad) — единственный доказуемо абсолютно стойкий шифр (теорема Шеннона).\n"
                "Условия стойкости: 1) ключ не короче сообщения, 2) ключ абсолютно случаен, 3) ключ не повторяется.\n"
                "XOR — обратимая операция: (P XOR K) XOR K = P.\n"
                "HMAC-SHA256 обеспечивает аутентификацию — получатель проверит целостность данных.\n"
                "MAC = HMAC(mac_key, ciphertext) — любое изменение шифртекста даст другой MAC."
            ),
        )
    )

    steps.append(
        StepLog(
            step_num=6,
            title="Упаковка результата",
            description="Все данные упаковываются в бинарный контейнер",
            variables={
                "итоговый_размер": len(ciphertext)
                + len(ciphertext_mlkem)
                + len(salt)
                + len(nonce)
                + len(mac)
                + 64,
                "структура": "MAGIC(8) | VERSION(2) | LEVEL(1) | SALT(32) | NONCE(16) | KEM_CT(1088) | MAC(32) | DATA_LEN(8) | DATA(N)",
            },
            hex_data=None,
            explanation=(
                "Контейнер содержит всё необходимое для расшифровки: ML-KEM шифртекст, соль, нonce.\n"
                "Получатель: decapsulate(sk, kem_ct) → shared_secret → HKDF → OTP-ключ → XOR → открытый текст."
            ),
        )
    )

    return EncryptionResult(
        success=True,
        level=int(level),
        plaintext=data,
        plaintext_hex=data.hex(),
        ciphertext=ciphertext,
        ciphertext_hex=ciphertext.hex(),
        ciphertext_b64=base64.b64encode(ciphertext).decode(),
        seed=seed,
        seed_hex=seed.hex(),
        otp_key=otp_key,
        otp_key_hex=otp_key.hex(),
        mlkem_public_key=public_key,
        mlkem_secret_key=secret_key,
        mlkem_encapsulated=ciphertext_mlkem,
        shared_secret=shared_secret,
        steps=steps,
        preview_100=preview_100,
        timestamp=timestamp,
        file_name=file_name,
        encoding=encoding,
        per_byte_log=per_byte_log,
        mac=mac.hex(),
        nonce=nonce.hex(),
    )


def decrypt(
    ciphertext: bytes,
    otp_key: bytes,
    mac_expected: Optional[str] = None,
    shared_secret: Optional[bytes] = None,
    salt: Optional[bytes] = None,
    custom_info: bytes = b"hybrid-otp-derivation-2026",
) -> Tuple[bytes, List[StepLog], bool]:
    steps: List[StepLog] = []

    if shared_secret and salt:
        prk = hkdf_extract(salt, shared_secret)
        mac_key = hkdf_expand(prk, 32, info=b"mac-key")
        mac_actual = compute_mac(mac_key, ciphertext).hex()
        mac_valid = (mac_actual == mac_expected) if mac_expected else True
    else:
        mac_valid = True

    steps.append(
        StepLog(
            step_num=1,
            title="Проверка MAC",
            description="Проверка целостности шифртекста",
            variables={
                "mac_valid": mac_valid,
                "mac_ожидаемый": mac_expected or "не задан",
            },
            explanation="HMAC-SHA256 проверяет, что шифртекст не был изменён после отправки.",
        )
    )

    plaintext = xor_bytes(ciphertext, otp_key)

    steps.append(
        StepLog(
            step_num=2,
            title="XOR-расшифровка",
            description="ciphertext XOR otp_key = plaintext",
            variables={"длина": len(plaintext)},
            hex_data=plaintext[:64].hex(),
            explanation="Применяем тот же OTP-ключ — XOR обратим. Результат — исходные данные.",
        )
    )

    return plaintext, steps, mac_valid


def pack_binary(result: EncryptionResult, salt: bytes, nonce: bytes) -> bytes:
    MAGIC = b"MLKEM001"
    VERSION = (1).to_bytes(2, "big")
    LEVEL = result.level.to_bytes(1, "big")
    TS = struct.pack(">d", result.timestamp)
    MAC = bytes.fromhex(result.mac)
    DATA_LEN = len(result.ciphertext).to_bytes(8, "big")
    KEM_CT = result.mlkem_encapsulated
    SK = result.mlkem_secret_key

    sk_len = len(SK).to_bytes(4, "big")

    return (
        MAGIC
        + VERSION
        + LEVEL
        + TS
        + salt
        + nonce
        + KEM_CT
        + MAC
        + DATA_LEN
        + result.ciphertext
        + sk_len
        + SK
    )


def unpack_binary(data: bytes) -> Dict[str, Any]:
    if data[:8] != b"MLKEM001":
        raise ValueError("Неверная сигнатура файла")

    offset = 8
    version = int.from_bytes(data[offset : offset + 2], "big")
    offset += 2
    level = data[offset]
    offset += 1
    timestamp = struct.unpack(">d", data[offset : offset + 8])[0]
    offset += 8
    salt = data[offset : offset + 32]
    offset += 32
    nonce = data[offset : offset + 16]
    offset += 16
    kem_ct = data[offset : offset + 1088]
    offset += 1088
    mac = data[offset : offset + 32]
    offset += 32
    data_len = int.from_bytes(data[offset : offset + 8], "big")
    offset += 8
    ciphertext = data[offset : offset + data_len]
    offset += data_len
    sk_len = int.from_bytes(data[offset : offset + 4], "big")
    offset += 4
    secret_key = data[offset : offset + sk_len]

    mlkem = MLKEMSimulator()
    shared_secret = mlkem.decapsulate(secret_key, kem_ct)
    prk = hkdf_extract(salt, shared_secret)
    otp_key = hkdf_expand(prk, data_len, info=b"hybrid-otp-derivation-2026")

    plaintext = xor_bytes(ciphertext, otp_key)

    return {
        "version": version,
        "level": level,
        "timestamp": timestamp,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "kem_ct": kem_ct.hex(),
        "mac": mac.hex(),
        "ciphertext": ciphertext,
        "ciphertext_hex": ciphertext.hex(),
        "plaintext": plaintext,
        "plaintext_hex": plaintext.hex(),
        "shared_secret": shared_secret.hex(),
        "otp_key": otp_key.hex(),
        "secret_key": secret_key.hex(),
    }


def make_reversible_pair(result: EncryptionResult, n_tamper: int) -> ReversiblePair:
    ct = bytearray(result.ciphertext)
    positions = sorted(
        secrets.SystemRandom().sample(range(len(ct)), min(n_tamper, len(ct)))
    )
    tampered = bytearray(ct)
    for pos in positions:
        tampered[pos] = tampered[pos] ^ (secrets.randbits(7) + 1)

    salt_c = secrets.token_bytes(32)
    nonce_c = secrets.token_bytes(16)

    correct_packed = pack_binary(result, salt_c, nonce_c)

    tampered_result = EncryptionResult(
        **{
            **asdict(result),
            "ciphertext": bytes(tampered),
            "ciphertext_hex": bytes(tampered).hex(),
        }
    )
    tampered_packed = pack_binary(tampered_result, salt_c, nonce_c)

    return ReversiblePair(
        correct_file=correct_packed,
        tampered_file=tampered_packed,
        correct_key=result.otp_key,
        tampered_key=result.otp_key,
        n_tampered=len(positions),
        tampered_positions=positions,
    )
