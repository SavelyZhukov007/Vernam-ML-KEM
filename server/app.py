import os
import sys
import json
import time
import base64
import hashlib
import secrets
import struct
import threading
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify, send_from_directory, render_template_string

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.crypto_engine import (
    encrypt,
    decrypt,
    pack_binary,
    unpack_binary,
    make_reversible_pair,
    EncryptionLevel,
    MLKEMSimulator,
    hkdf_extract,
    hkdf_expand,
    xor_bytes,
    compute_mac,
    StepLog,
)

app = Flask(__name__, static_folder="static", template_folder="templates")

CHANNEL_TTL = 20

channel_lock = threading.Lock()
channel_messages: List[Dict] = []

sessions: Dict[str, Dict] = {}

alice_state: Dict = {
    "messages_sent": 0,
    "current_encryption": None,
    "custom_info": "hybrid-otp-derivation-2026",
    "level": 4,
}

bob_state: Dict = {
    "messages_received": 0,
    "decrypted_messages": [],
}

eva_state: Dict = {
    "intercepted": [],
    "cracked": [],
    "listening": True,
}


def cleanup_channel():
    while True:
        time.sleep(2)
        with channel_lock:
            now = time.time()
            expired = [
                m for m in channel_messages if now - m["timestamp"] > CHANNEL_TTL
            ]
            for m in expired:
                channel_messages.remove(m)


threading.Thread(target=cleanup_channel, daemon=True).start()


@app.route("/")
def index():
    return send_from_directory("templates", "index.html")


@app.route("/alice")
def alice_page():
    return send_from_directory("templates", "Alice.html")


@app.route("/bob")
def bob_page():
    return send_from_directory("templates", "Bob.html")


@app.route("/eva")
def eva_page():
    return send_from_directory("templates", "Eva.html")


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    try:
        data_b64 = request.json.get("data_b64")
        level = int(request.json.get("level", 4))
        file_name = request.json.get("file_name")
        custom_info = request.json.get(
            "custom_info", "hybrid-otp-derivation-2026"
        ).encode()

        raw_data = base64.b64decode(data_b64)

        result = encrypt(
            raw_data,
            EncryptionLevel(level),
            file_name=file_name,
            custom_info=custom_info,
        )

        salt_bytes = bytes.fromhex(
            result.steps[3].variables.get("salt_hex", secrets.token_bytes(32).hex())
        )
        nonce_bytes = bytes.fromhex(result.nonce)
        try:
            salt_bytes = bytes.fromhex(result.steps[3].variables.get("salt_hex", ""))
            if len(salt_bytes) != 32:
                raise ValueError
        except Exception:
            salt_bytes = secrets.token_bytes(32)

        import secrets as sec

        salt_bytes = sec.token_bytes(32)

        packed = pack_binary(result, salt_bytes, nonce_bytes)

        steps_out = []
        for s in result.steps:
            steps_out.append(
                {
                    "step_num": s.step_num,
                    "title": s.title,
                    "description": s.description,
                    "variables": s.variables,
                    "hex_data": s.hex_data,
                    "explanation": s.explanation,
                }
            )

        return jsonify(
            {
                "success": True,
                "level": level,
                "preview_100": result.preview_100,
                "ciphertext_b64": result.ciphertext_b64,
                "ciphertext_hex": result.ciphertext_hex[:128],
                "packed_b64": base64.b64encode(packed).decode(),
                "seed_hex": result.seed_hex,
                "otp_key_hex": result.otp_key_hex[:64],
                "shared_secret_hex": result.shared_secret.hex(),
                "mlkem_pk_hex": result.mlkem_public_key.hex()[:64],
                "mac": result.mac,
                "nonce": result.nonce,
                "steps": steps_out,
                "per_byte_log": result.per_byte_log[:500],
                "encoding": result.encoding,
                "plaintext_len": len(result.plaintext),
                "timestamp": result.timestamp,
            }
        )
    except Exception as e:
        import traceback

        return (
            jsonify(
                {"success": False, "error": str(e), "trace": traceback.format_exc()}
            ),
            500,
        )


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    try:
        packed_b64 = request.json.get("packed_b64")
        packed = base64.b64decode(packed_b64)
        result = unpack_binary(packed)

        plaintext = result["plaintext"]
        encoding_detected = None
        text_out = None
        encodings = ["utf-8", "utf-16", "latin-1", "cp1251", "ascii"]
        for enc in encodings:
            try:
                text_out = plaintext.decode(enc)
                encoding_detected = enc
                break
            except Exception:
                pass

        return jsonify(
            {
                "success": True,
                "plaintext_b64": base64.b64encode(plaintext).decode(),
                "plaintext_hex": plaintext.hex()[:256],
                "text": text_out,
                "encoding": encoding_detected,
                "level": result["level"],
                "timestamp": result["timestamp"],
                "salt": result["salt"][:32],
                "nonce": result["nonce"],
                "shared_secret": result["shared_secret"][:64],
                "otp_key": result["otp_key"][:64],
                "mac": result["mac"],
            }
        )
    except Exception as e:
        import traceback

        return (
            jsonify(
                {"success": False, "error": str(e), "trace": traceback.format_exc()}
            ),
            500,
        )


@app.route("/api/channel/send", methods=["POST"])
def channel_send():
    try:
        packed_b64 = request.json.get("packed_b64")
        sender = request.json.get("sender", "alice")
        recipient = request.json.get("recipient", "bob")
        label = request.json.get("label", "Зашифрованное сообщение")
        preview = request.json.get("preview", "")
        level = request.json.get("level", 4)
        is_ideal = request.json.get("is_ideal", False)

        msg_id = secrets.token_hex(8)
        ts = time.time()

        packed = base64.b64decode(packed_b64)
        size_bytes = len(packed)

        msg = {
            "id": msg_id,
            "sender": sender,
            "recipient": recipient,
            "label": label,
            "preview": preview[:100],
            "level": level,
            "is_ideal": is_ideal,
            "timestamp": ts,
            "expires_at": ts + CHANNEL_TTL,
            "packed_b64": packed_b64,
            "size_bytes": size_bytes,
        }

        with channel_lock:
            channel_messages.append(msg)
            if eva_state["listening"]:
                eva_state["intercepted"].append(
                    {
                        "msg_id": msg_id,
                        "timestamp": ts,
                        "sender": sender,
                        "recipient": recipient,
                        "level": level,
                        "is_ideal": is_ideal,
                        "size_bytes": size_bytes,
                        "preview": preview[:50],
                    }
                )

        alice_state["messages_sent"] += 1

        return jsonify(
            {
                "success": True,
                "msg_id": msg_id,
                "expires_in": CHANNEL_TTL,
                "timestamp": ts,
            }
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/channel/list", methods=["GET"])
def channel_list():
    now = time.time()
    with channel_lock:
        msgs = []
        for m in channel_messages:
            remaining = m["expires_at"] - now
            if remaining > 0:
                msgs.append(
                    {
                        "id": m["id"],
                        "sender": m["sender"],
                        "recipient": m["recipient"],
                        "label": m["label"],
                        "preview": m["preview"],
                        "level": m["level"],
                        "is_ideal": m["is_ideal"],
                        "timestamp": m["timestamp"],
                        "expires_in": remaining,
                        "size_bytes": m["size_bytes"],
                    }
                )
    return jsonify({"messages": msgs, "count": len(msgs)})


@app.route("/api/channel/download/<msg_id>", methods=["GET"])
def channel_download(msg_id):
    now = time.time()
    with channel_lock:
        for m in channel_messages:
            if m["id"] == msg_id and m["expires_at"] > now:
                return jsonify(
                    {
                        "success": True,
                        "msg_id": msg_id,
                        "packed_b64": m["packed_b64"],
                        "sender": m["sender"],
                        "level": m["level"],
                        "timestamp": m["timestamp"],
                    }
                )
    return (
        jsonify({"success": False, "error": "Сообщение не найдено или истёк срок"}),
        404,
    )


@app.route("/api/channel/delete/<msg_id>", methods=["DELETE"])
def channel_delete(msg_id):
    with channel_lock:
        for m in channel_messages:
            if m["id"] == msg_id:
                channel_messages.remove(m)
                return jsonify({"success": True})
    return jsonify({"success": False, "error": "Не найдено"}), 404


@app.route("/api/eva/intercept", methods=["GET"])
def eva_intercept():
    with channel_lock:
        intercepted = list(eva_state["intercepted"])
    return jsonify({"intercepted": intercepted})


@app.route("/api/eva/crack", methods=["POST"])
def eva_crack():
    try:
        msg_id = request.json.get("msg_id")
        method = request.json.get("method", "bruteforce")

        with channel_lock:
            target = None
            for m in channel_messages:
                if m["id"] == msg_id:
                    target = m
                    break

        if not target:
            return jsonify(
                {"success": False, "error": "Сообщение не найдено или истекло"}
            )

        level = target.get("level", 4)
        is_ideal = target.get("is_ideal", True)

        if is_ideal or level >= 4:
            return jsonify(
                {
                    "success": False,
                    "cracked": False,
                    "reason": "ML-KEM обеспечивает постквантовую стойкость. Взлом невозможен без закрытого ключа.",
                    "method": method,
                    "level": level,
                }
            )
        else:
            packed_b64 = target["packed_b64"]
            try:
                parsed = unpack_binary(base64.b64decode(packed_b64))
                plaintext = parsed["plaintext"]
                encoding = None
                text = None
                for enc in ["utf-8", "cp1251", "latin-1"]:
                    try:
                        text = plaintext.decode(enc)
                        encoding = enc
                        break
                    except Exception:
                        pass

                crack_result = {
                    "success": True,
                    "cracked": True,
                    "reason": f"Уровень шифрования {level} — ключ доступен в открытом виде",
                    "text": text,
                    "encoding": encoding,
                    "plaintext_hex": plaintext.hex()[:128],
                }
                with channel_lock:
                    eva_state["cracked"].append(
                        {
                            "msg_id": msg_id,
                            "text": text[:200] if text else None,
                            "timestamp": time.time(),
                        }
                    )
                return jsonify(crack_result)
            except Exception as ex:
                return jsonify(
                    {
                        "success": False,
                        "cracked": False,
                        "reason": f"Ошибка при попытке взлома: {str(ex)}",
                    }
                )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/reversible", methods=["POST"])
def make_reversible():
    try:
        packed_b64 = request.json.get("packed_b64")
        n_tamper = int(request.json.get("n_tamper", 5))

        packed = base64.b64decode(packed_b64)
        parsed = unpack_binary(packed)

        from core.crypto_engine import EncryptionResult, asdict
        import dataclasses

        fake_result = EncryptionResult(
            success=True,
            level=parsed["level"],
            plaintext=parsed["plaintext"],
            plaintext_hex=parsed["plaintext_hex"],
            ciphertext=parsed["ciphertext"],
            ciphertext_hex=parsed["ciphertext_hex"],
            ciphertext_b64=base64.b64encode(parsed["ciphertext"]).decode(),
            seed=bytes.fromhex(parsed["shared_secret"]),
            seed_hex=parsed["shared_secret"],
            otp_key=bytes.fromhex(parsed["otp_key"]),
            otp_key_hex=parsed["otp_key"],
            mlkem_public_key=b"\x00" * 1184,
            mlkem_secret_key=bytes.fromhex(parsed["secret_key"]),
            mlkem_encapsulated=bytes.fromhex(parsed["kem_ct"]),
            shared_secret=bytes.fromhex(parsed["shared_secret"]),
            steps=[],
            preview_100="",
            timestamp=time.time(),
            mac=parsed["mac"],
            nonce=parsed["nonce"],
        )

        pair = make_reversible_pair(fake_result, n_tamper)

        return jsonify(
            {
                "success": True,
                "correct_b64": base64.b64encode(pair.correct_file).decode(),
                "tampered_b64": base64.b64encode(pair.tampered_file).decode(),
                "n_tampered": pair.n_tampered,
                "tampered_positions": pair.tampered_positions[:50],
            }
        )
    except Exception as e:
        import traceback

        return (
            jsonify(
                {"success": False, "error": str(e), "trace": traceback.format_exc()}
            ),
            500,
        )


@app.route("/api/status", methods=["GET"])
def status():
    with channel_lock:
        ch_count = len(channel_messages)
    return jsonify(
        {
            "status": "ok",
            "channel_messages": ch_count,
            "alice_sent": alice_state["messages_sent"],
            "bob_received": bob_state["messages_received"],
            "eva_intercepted": len(eva_state["intercepted"]),
            "eva_cracked": len(eva_state["cracked"]),
            "timestamp": time.time(),
        }
    )


if __name__ == "__main__":
    print("🔐 Crypto System Server запущен")
    print("  Alice: http://localhost:5000/alice")
    print("  Bob:   http://localhost:5000/bob")
    print("  Eva:   http://localhost:5000/eva")
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)