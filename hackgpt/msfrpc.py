"""Minimal MessagePack codec + MSFRPCD client for remote Metasploit control.

Implements just enough of the Metasploit JSON-RPC v1.0 protocol (MessagePack over
HTTP) to authenticate, drive consoles, execute modules and manage sessions with no
third-party dependencies. Point it at a host running `msfrpcd` — preferably reached
over an SSH tunnel; see references/msfrpcd-setup.md in the hackgpt skill.
"""
from __future__ import annotations

import struct
import urllib.request

MSFRPCD_DEFAULTS = {
    "host": "",
    "port": 55553,
    "user": "msf",
    "password": "",
    "ssl": False,
    "timeout": 60,
}


class RpcError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# msgpack encode
# --------------------------------------------------------------------------

def pack(obj) -> bytes:
    if obj is None:
        return b"\xc0"
    if obj is True:
        return b"\xc3"
    if obj is False:
        return b"\xc2"
    if isinstance(obj, int):
        if 0 <= obj < 128:
            return bytes([obj])
        if -32 <= obj < 0:
            return bytes([obj & 0xFF])
        if 0 <= obj < 1 << 8:
            return b"\xcc" + bytes([obj])
        if 0 <= obj < 1 << 16:
            return b"\xcd" + obj.to_bytes(2, "big")
        if 0 <= obj < 1 << 32:
            return b"\xce" + obj.to_bytes(4, "big")
        if 0 <= obj < 1 << 64:
            return b"\xcf" + obj.to_bytes(8, "big")
        if -(1 << 7) <= obj < 0:
            return b"\xd0" + (obj & 0xFF).to_bytes(1, "big")
        if -(1 << 15) <= obj < 0:
            return b"\xd1" + (obj & 0xFFFF).to_bytes(2, "big")
        if -(1 << 31) <= obj < 0:
            return b"\xd2" + (obj & 0xFFFFFFFF).to_bytes(4, "big")
        return b"\xd3" + (obj & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
    if isinstance(obj, float):
        return b"\xcb" + struct.pack(">d", obj)
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        n = len(raw)
        if n < 32:
            return bytes([0xA0 | n]) + raw
        if n < 1 << 8:
            return b"\xd9" + bytes([n]) + raw
        if n < 1 << 16:
            return b"\xda" + n.to_bytes(2, "big") + raw
        return b"\xdb" + n.to_bytes(4, "big") + raw
    if isinstance(obj, (bytes, bytearray)):
        n = len(obj)
        if n < 1 << 8:
            return b"\xc4" + bytes([n]) + bytes(obj)
        if n < 1 << 16:
            return b"\xc5" + n.to_bytes(2, "big") + bytes(obj)
        return b"\xc6" + n.to_bytes(4, "big") + bytes(obj)
    if isinstance(obj, (list, tuple)):
        n = len(obj)
        if n < 16:
            head = bytes([0x90 | n])
        elif n < 1 << 16:
            head = b"\xdc" + n.to_bytes(2, "big")
        else:
            head = b"\xdd" + n.to_bytes(4, "big")
        return head + b"".join(pack(x) for x in obj)
    if isinstance(obj, dict):
        n = len(obj)
        if n < 16:
            head = bytes([0x80 | n])
        elif n < 1 << 16:
            head = b"\xde" + n.to_bytes(2, "big")
        else:
            head = b"\xdf" + n.to_bytes(4, "big")
        return head + b"".join(pack(k) + pack(v) for k, v in obj.items())
    raise RpcError(f"msgpack: cannot encode {type(obj).__name__}")


# --------------------------------------------------------------------------
# msgpack decode
# --------------------------------------------------------------------------

class _Unpacker:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def u8(self) -> int:
        b = self.d[self.i]
        self.i += 1
        return b

    def take(self, n: int) -> bytes:
        s = self.d[self.i:self.i + n]
        self.i += n
        return s

    def array(self, n: int) -> list:
        return [self.decode() for _ in range(n)]

    def mapping(self, n: int) -> dict:
        out: dict = {}
        for _ in range(n):
            k = self.decode()
            v = self.decode()
            if isinstance(k, bytes):
                k = k.decode("utf-8", "replace")
            if not isinstance(k, (str, int)):
                k = str(k)
            out[k] = v
        return out

    def text(self, n: int) -> str:
        return self.take(n).decode("utf-8", "replace")

    def decode(self):
        b = self.u8()
        if b < 0x80:
            return b
        if b >= 0xE0:
            return b - 256
        if 0x80 <= b <= 0x8F:
            return self.mapping(b & 0x0F)
        if 0x90 <= b <= 0x9F:
            return self.array(b & 0x0F)
        if 0xA0 <= b <= 0xBF:
            return self.text(b & 0x1F)
        if b == 0xC0:
            return None
        if b == 0xC2:
            return False
        if b == 0xC3:
            return True
        if b == 0xC4:
            return self.take(self.u8())
        if b == 0xC5:
            return self.take(int.from_bytes(self.take(2), "big"))
        if b == 0xC6:
            return self.take(int.from_bytes(self.take(4), "big"))
        if b == 0xCA:
            return struct.unpack(">f", self.take(4))[0]
        if b == 0xCB:
            return struct.unpack(">d", self.take(8))[0]
        if b == 0xCC:
            return self.u8()
        if b == 0xCD:
            return int.from_bytes(self.take(2), "big")
        if b == 0xCE:
            return int.from_bytes(self.take(4), "big")
        if b == 0xCF:
            return int.from_bytes(self.take(8), "big")
        if b == 0xD0:
            return int.from_bytes(self.take(1), "big", signed=True)
        if b == 0xD1:
            return int.from_bytes(self.take(2), "big", signed=True)
        if b == 0xD2:
            return int.from_bytes(self.take(4), "big", signed=True)
        if b == 0xD3:
            return int.from_bytes(self.take(8), "big", signed=True)
        if b == 0xD9:
            return self.text(self.u8())
        if b == 0xDA:
            return self.text(int.from_bytes(self.take(2), "big"))
        if b == 0xDB:
            return self.text(int.from_bytes(self.take(4), "big"))
        if b == 0xDC:
            return self.array(int.from_bytes(self.take(2), "big"))
        if b == 0xDD:
            return self.array(int.from_bytes(self.take(4), "big"))
        if b == 0xDE:
            return self.mapping(int.from_bytes(self.take(2), "big"))
        if b == 0xDF:
            return self.mapping(int.from_bytes(self.take(4), "big"))
        raise RpcError(f"msgpack: unsupported prefix 0x{b:02x}")


def unpack(data: bytes):
    return _Unpacker(data).decode()


# --------------------------------------------------------------------------
# MSFRPCD client
# --------------------------------------------------------------------------

class MsfRpcClient:
    """Thin driver for Metasploit's RPC v1.0 endpoint (/api/1.0, MessagePack)."""

    def __init__(self, cfg: dict, timeout: int | None = None):
        host = str(cfg.get("msfrpcd_host") or "").strip()
        if not host:
            raise RpcError("msfrpcd_host is not configured")
        port = int(cfg.get("msfrpcd_port") or 55553)
        ssl = bool(cfg.get("msfrpcd_ssl"))
        scheme = "https" if ssl else "http"
        self.url = f"{scheme}://{host}:{port}/api/1.0"
        self.timeout = int(timeout or cfg.get("msfrpcd_timeout") or 60)
        self.user = str(cfg.get("msfrpcd_user") or "msf")
        self.password = str(cfg.get("msfrpcd_pass") or "")
        self.token = ""
        self.last_auth_header = ""

    # -- transport --------------------------------------------------------

    def _post(self, payload: dict):
        body = pack({"version": "1.0", "method": payload["method"], "params": payload.get("params") or []})
        req = urllib.request.Request(self.url, data=body, method="POST")
        req.add_header("Content-Type", "application/msgpack")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except Exception as exc:  # noqa: BLE001
            raise RpcError(f"transport failed ({self.url}): {exc}") from exc
        if not raw:
            raise RpcError("empty response from msfrpcd")
        try:
            out = unpack(raw)
        except RpcError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise RpcError(f"undecodable response: {exc}") from exc
        if not isinstance(out, dict):
            raise RpcError(f"unexpected response type: {type(out).__name__}")
        if out.get("error"):
            err = out["error"]
            if isinstance(err, dict):
                err = err.get("message") or err
            raise RpcError(str(err)[:400])
        return out.get("result")

    # -- auth -------------------------------------------------------------

    def login(self) -> str:
        res = self._post({"method": "auth.login", "params": [self.user, self.password]})
        token = None
        if isinstance(res, dict):
            token = res.get("token")
        if not token and isinstance(res, (list, tuple)) and res:
            token = res[0]
        if not token and isinstance(res, str):
            token = res
        if not token:
            raise RpcError(f"auth.login returned no token: {str(res)[:200]}")
        self.token = str(token)
        return self.token

    def logout(self) -> None:
        if self.token:
            try:
                self.call("auth.logout", [self.token])
            except Exception:  # noqa: BLE001
                pass
            self.token = ""

    # -- generic call -----------------------------------------------------

    def call(self, method: str, params: list | None = None):
        # Lazily authenticate so console/module/session helpers work without the
        # caller invoking login() first (login itself must not recurse here).
        if not self.token and method != "auth.login":
            self.login()
        return self._post({"method": method, "params": params or []})

    # -- console / module / session helpers --------------------------------

    def version(self):
        return self.call("core.version")

    def console_create(self):
        return self.call("console.create")

    def console_list(self):
        return self.call("console.list")

    def console_write(self, cid, data: str):
        return self.call("console.write", [cid, data])

    def console_read(self, cid):
        return self.call("console.read", [cid])

    def console_destroy(self, cid):
        return self.call("console.destroy", [cid])

    def module_execute(self, mtype: str, name: str, options: dict):
        return self.call("module.execute", [mtype, name, options or {}])

    def module_info(self, mtype: str, name: str):
        return self.call("module.info", [mtype, name])

    def sessions(self):
        return self.call("session.list")

    def session_stop(self, sid):
        return self.call("session.stop", [sid])
