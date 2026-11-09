"""Testes do sidecar HTTP: contrato, fail-closed e loopback."""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

from sentinela.serve import build_server


class TestSidecar(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = build_server(port=0, load_model=False)
        cls.host, cls.port = cls.server.server_address[:2]
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def post(self, payload: bytes) -> tuple[int, dict]:
        req = urllib.request.Request(
            f"http://{self.host}:{self.port}/check",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def check(self, tool_call: dict, mode: str = "shadow") -> dict:
        code, body = self.post(json.dumps({"tool_call": tool_call, "mode": mode}).encode())
        self.assertEqual(code, 200, body)
        return body

    def test_health(self) -> None:
        with urllib.request.urlopen(f"http://{self.host}:{self.port}/health", timeout=5) as resp:
            body = json.loads(resp.read())
        self.assertTrue(body["ok"])
        self.assertFalse(body["l1"])

    def test_deny_no_modo_enforce(self) -> None:
        body = self.check({"name": "bash", "args": {"command": "rm -rf /etc"}}, mode="enforce")
        self.assertEqual(body["verdict"], "DENY")
        self.assertEqual(body["mode"], "enforce")

    def test_allow(self) -> None:
        body = self.check({"name": "bash", "args": {"command": "ls -la"}})
        self.assertEqual(body["verdict"], "ALLOW")

    def test_shadow_nao_promove_nem_rebaixa(self) -> None:
        body = self.check({"name": "bash", "args": {"command": "npm publish"}}, mode="shadow")
        self.assertEqual(body["verdict"], "UNCERTAIN")

    def test_json_invalido_nega(self) -> None:
        code, body = self.post(b"{nao e json")
        self.assertEqual(code, 500)
        self.assertEqual(body["verdict"], "DENY")

    def test_payload_sem_tool_call_nega(self) -> None:
        code, body = self.post(b'{"mode":"enforce"}')
        self.assertEqual(code, 400)
        self.assertEqual(body["verdict"], "DENY")

    def test_modo_desconhecido_nega(self) -> None:
        code, body = self.post(b'{"tool_call":{"name":"bash","args":{}},"mode":"yolo"}')
        self.assertEqual(code, 400)
        self.assertEqual(body["verdict"], "DENY")

    def test_corpo_gigante_nega(self) -> None:
        code, body = self.post(b'{"tool_call":' + b"x" * (1 << 20))
        self.assertEqual(code, 413)
        self.assertEqual(body["verdict"], "DENY")

    def test_rota_desconhecida(self) -> None:
        req = urllib.request.Request(f"http://{self.host}:{self.port}/nada", method="POST", data=b"{}")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
