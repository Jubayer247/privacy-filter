"""
End-to-end check of the privacy filter, with no NVIDIA key needed.

A fake "NVIDIA" server records exactly what it receives. The filter runs in front of it.
We check (1) nothing personal reaches the fake server and (2) the answers come back
with the real values, for normal replies, streamed replies and tool calls.

Run:  .venv\\Scripts\\python.exe test_filter.py
"""
import json
import socket
import sys
import threading
import time

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

import privacy_filter as pfm

SECRETS = {
    "names": ["Rahim Uddin Chowdhury", "Ayesha Rahman", "Imran", "Shakil", "Fatema Begum", "Md Kamal Hossain",
              "Tanvir Hasan", "John Smith"],
    "phones": ["+880 1712 345678", "01711234567", "+1 (603) 555-0100", "০১৭১১২৩৪৫৬৭"],
    "emails": ["rahim.c@example.com", "imran@example.org"],
    "ids": ["1234567890123", "19901234567890123", "AB1234567"],
    "secrets": ["nvapi-FAKE0000000000000000000000000000", "S3cretPass!99", "ghp_FAKE0000000000000000000000000000000000",
                "hunter2pass"],
    "other": ["100000000000001@lid", "House 12, Road 5", "192.168.1.44", "4111 1111 1111 1111"],
}

TEXT = (
    "Client Rahim Uddin Chowdhury (phone +880 1712-345678, email rahim.c@example.com) lives at House 12, Road 5, "
    "Dhanmondi. His NID: 1234567890123 and smart card 19901234567890123. Passport no AB1234567. "
    "Ayesha Rahman called from 01711234567; Imran asked Shakil to follow up. Fatema Begum's US number is "
    "+1 (603) 555-0100. Md Kamal Hossain reviewed it. Tanvir Hasan, John Smith. WhatsApp 100000000000001@lid. "
    "Server 192.168.1.44, password: S3cretPass!99, key nvapi-FAKE0000000000000000000000000000, "
    "token ghp_FAKE0000000000000000000000000000000000, db postgres://admin:hunter2pass@db.local/app. "
    "Card 4111 1111 1111 1111. DOB: 12/03/1990. Bangla digits: ০১৭১১২৩৪৫৬৭. "
    "Keep: Progression, Dhaka, invoice INV-2026-0042, amount BDT 160,000, date 21 Oct 2026."
)
MUST_KEEP = ["Progression", "Dhaka", "INV-2026-0042", "BDT 160,000", "21 Oct 2026", "Passport no", "US number"]
SAME = lambda s: s.translate(pfm.BN_DIGITS)  # Bangla digits come back as the first-seen form of the same number

received: list[dict] = []
fake = FastAPI()


def _echo_text(body: dict) -> str:
    # The fake model repeats back the last user message, so placeholders come back to be restored.
    c = [m for m in body["messages"] if m["role"] == "user"][-1]["content"]
    return c if isinstance(c, str) else "".join(p.get("text", "") for p in c if p.get("type") == "text")


@fake.post("/v1/chat/completions")
async def fake_chat(req: Request):
    body = await req.json()
    received.append(body)
    echo = _echo_text(body)
    args = json.dumps({"to": "[PERSON_1]", "note": "call [PHONE_1] then mail [EMAIL_1]"})
    if body.get("stream"):
        async def gen():
            # split the text into tiny pieces so placeholders get cut in half
            for i in range(0, len(echo), 7):
                d = {"choices": [{"index": 0, "delta": {"content": echo[i:i + 7]}, "finish_reason": None}]}
                yield "data: " + json.dumps(d) + "\n\n"
            for i in range(0, len(args), 5):
                d = {"choices": [{"index": 0, "delta": {"tool_calls": [
                    {"index": 0, "id": "c1" if i == 0 else None, "type": "function",
                     "function": {"name": "send" if i == 0 else None, "arguments": args[i:i + 5]}}]},
                    "finish_reason": None}]}
                yield "data: " + json.dumps(d) + "\n\n"
            yield "data: " + json.dumps({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}) + "\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(gen(), media_type="text/event-stream")
    return JSONResponse({"choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
        "role": "assistant", "content": echo,
        "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "send", "arguments": args}}]}}]})


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def serve(app, port):
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    srv = uvicorn.Server(cfg)
    threading.Thread(target=srv.run, daemon=True).start()
    for _ in range(100):
        try:
            httpx.get(f"http://127.0.0.1:{port}/health", timeout=0.5)
            return srv
        except Exception:
            time.sleep(0.1)
    return srv


def main() -> int:
    fails = 0

    def check(ok, label, detail=""):
        nonlocal fails
        print(("  PASS  " if ok else "  FAIL  ") + label + (f"  ({detail})" if detail and not ok else ""))
        fails += 0 if ok else 1

    fport, pport = free_port(), free_port()
    serve(fake, fport)
    cfg = pfm.load_config()
    cfg["upstream"] = f"http://127.0.0.1:{fport}/v1"
    t = time.time()
    pf = pfm.PrivacyFilter(cfg)
    print(f"model loaded in {time.time() - t:.1f}s")
    serve(pfm.build_app(cfg, pf), pport)
    base = f"http://127.0.0.1:{pport}/v1"

    def leaked(body: dict) -> list[str]:
        blob = json.dumps(body, ensure_ascii=False)
        bad = []
        for group in SECRETS.values():
            for s in group:
                if s in blob:
                    bad.append(s)
        # also check digits-only forms of phone numbers
        for s in ["1712345678", "1711234567"]:
            if s in blob.replace("-", "").replace(" ", ""):
                bad.append(s)
        return bad

    msgs = [{"role": "system", "content": "You help Imran at Progression."},
            {"role": "user", "content": TEXT},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "t0", "type": "function", "function": {
                "name": "terminal", "arguments": json.dumps({"command": "grep 'Rahim Uddin Chowdhury' clients.csv"})}}]},
            {"role": "tool", "tool_call_id": "t0", "content": "Rahim Uddin Chowdhury,01711234567,rahim.c@example.com"},
            {"role": "user", "content": [{"type": "text", "text": TEXT},
                                         {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]}]

    # 1) non-streaming
    t = time.time()
    r = httpx.post(base + "/chat/completions", json={"model": "x", "messages": msgs[:2]},
                   headers={"Authorization": "Bearer test"}, timeout=120)
    print(f"non-stream round trip {time.time() - t:.1f}s")
    sent = received[-1]
    check(not leaked(sent), "non-stream: nothing personal reached the API", ", ".join(leaked(sent)))
    sent_user = sent["messages"][1]["content"]
    for k in MUST_KEEP:
        check(k in sent_user, f"kept ordinary text: {k}")
    print("\n  what the API saw:\n  " + sent_user + "\n")
    out = r.json()["choices"][0]["message"]
    check(SAME(out["content"]) == SAME(TEXT), "non-stream: reply restored exactly",
          next((f"{a!r} vs {b!r}" for a, b in zip(out["content"], TEXT) if a != b), "length differs"))
    args = json.loads(out["tool_calls"][0]["function"]["arguments"])
    check("[" not in json.dumps(args) and pf.vault.rev["[PERSON_1]"] == args["to"], "non-stream: tool-call arguments restored",
          json.dumps(args))

    # 2) full history, streaming
    r = httpx.post(base + "/chat/completions", json={"model": "x", "messages": msgs, "stream": True},
                   headers={"Authorization": "Bearer test"}, timeout=120)
    sent = received[-1]
    check(not leaked(sent), "stream + tool history: nothing personal reached the API", ", ".join(leaked(sent)))
    check("attachment removed" in json.dumps(sent), "image removed before sending")
    content, argbuf = "", ""
    for line in r.text.splitlines():
        if line.startswith("data:") and "[DONE]" not in line:
            d = json.loads(line[5:])
            for ch in d.get("choices", []):
                content += ch.get("delta", {}).get("content") or ""
                for tc in ch.get("delta", {}).get("tool_calls") or []:
                    argbuf += (tc.get("function") or {}).get("arguments") or ""
    content = content.replace("[attachment removed by the privacy filter]", "")  # the image became this note
    check(SAME(content) == SAME(TEXT), "stream: reply restored exactly (placeholders split across chunks)",
          next((f"at {i}: got {content[max(0,i-30):i+30]!r} want {TEXT[max(0,i-30):i+30]!r}" for i,(a,b) in enumerate(zip(SAME(content),SAME(TEXT))) if a!=b), f"len {len(content)} vs {len(TEXT)}"))
    try:
        a2 = json.loads(argbuf)
        check("[" not in argbuf and a2["to"] == pf.vault.rev["[PERSON_1]"], "stream: tool-call arguments restored", argbuf)
    except Exception as e:
        check(False, "stream: tool-call arguments are valid JSON", f"{e}: {argbuf}")

    # 3) consistency: same person -> same placeholder across requests
    ph1 = pf.anonymize("Rahim Uddin Chowdhury")
    ph2 = pf.anonymize("I met rahim uddin chowdhury today")
    check(ph1 in ph2, "same person gets the same placeholder (sticky, any case)", f"{ph1} / {ph2}")

    # 4) unknown endpoints are not forwarded
    r = httpx.post(base + "/responses", json={"input": TEXT}, timeout=30)
    check(r.status_code == 404, "unknown endpoint refused (404), not passed through")

    # 5) audit log has counts, not values
    log = (pfm.LOGS / "audit.log").read_text(encoding="utf-8").strip().splitlines()[-1]
    check(not any(s in log for g in SECRETS.values() for s in g), "audit log holds no personal values")
    print("\n  last audit line: " + log)

    print(f"\n{'ALL PASSED' if not fails else str(fails) + ' FAILED'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
