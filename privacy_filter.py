"""
Privacy filter: a local OpenAI-compatible proxy that sits in front of NVIDIA Build.

    Hermes helper agents --> http://127.0.0.1:8790/v1 --> https://integrate.api.nvidia.com/v1

Before a request leaves this PC, names, phone numbers, emails, ID and account
numbers, addresses, dates of birth, WhatsApp IDs, IP addresses and secrets are
swapped for placeholders such as [PERSON_1] or [PHONE_2]. When the answer comes
back, the placeholders are swapped back to the real values (also inside tool-call
arguments, so the agent's tools act on the real data).

Rules that matter:
- Fail closed. If the filter itself errors, the request is NOT sent.
- Only known endpoints are forwarded; anything else gets 404, never a raw pass-through.
- Images are removed from requests (text in a picture can't be checked).
- The audit log records counts per type, never the values.
- The mapping (real value <-> placeholder) lives in memory only and is gone on restart.
- Anything detected once stays hidden everywhere after that ("sticky" pass).

Lists you can edit (re-read automatically):
  data/always_hide.txt   one name/number/word per line, always hidden (use it for Bangla-script names)
  data/never_hide.txt    words that must never be hidden (product names, the assistant's names)
"""

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
LOGS = ROOT / "logs"
CONFIG_PATH = ROOT / "config.json"

DEFAULT_CONFIG = {
    "listen_host": "127.0.0.1",
    "listen_port": 8790,
    "upstream": "https://integrate.api.nvidia.com/v1",
    "min_score": 0.35,
    "block_images": True,
    "phone_regions": ["BD", "US", "GB", "IN", "CA", "AU", "AE", "SA", "MY", "SG"],
    "upstream_timeout_s": 900,
}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
    return cfg


# --------------------------------------------------------------------------- types

# Presidio / custom entity name -> placeholder label
LABELS = {
    "PERSON": "PERSON",
    "BD_NAME": "PERSON",
    "LISTED": "PRIVATE",
    "LISTED_NAME": "PERSON",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "BD_PHONE": "PHONE",
    "CREDIT_CARD": "CARD",
    "IBAN_CODE": "BANK_ACCOUNT",
    "IP_ADDRESS": "IP",
    "CRYPTO": "CRYPTO_WALLET",
    "US_SSN": "ID_NUMBER",
    "US_PASSPORT": "ID_NUMBER",
    "UK_NHS": "ID_NUMBER",
    "ID_NUMBER": "ID_NUMBER",
    "ACCOUNT_NUMBER": "BANK_ACCOUNT",
    "SECRET": "SECRET",
    "WHATSAPP_ID": "WHATSAPP_ID",
    "ADDRESS": "ADDRESS",
    "DATE_OF_BIRTH": "DOB",
}
PLACEHOLDER_TYPES = sorted(set(LABELS.values()), key=len, reverse=True)
# Bracketed form always; the bare form (model dropped the brackets) only for long, unambiguous labels.
_BARE_OK = [t for t in PLACEHOLDER_TYPES if len(t) >= 5]
PLACEHOLDER_RE = re.compile(r"\[(" + "|".join(PLACEHOLDER_TYPES) + r")_(\d{1,6})\]"
                            r"|\b(" + "|".join(_BARE_OK) + r")_(\d{1,6})\b")
# A trailing fragment that might be the start of a placeholder split across stream chunks.
PARTIAL_TAIL_RE = re.compile(r"(\[[A-Z_0-9]{0,24}|\b[A-Z][A-Z_]{1,15}_?\d{0,6})$")

BN_DIGITS = str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789")

BD_SURNAMES = (
    "Chowdhury|Chowdhuri|Choudhury|Rahman|Rahaman|Hossain|Hossen|Hussain|Hosen|Islam|Ahmed|Ahmad|Akter|Akhter|"
    "Aktar|Begum|Khan|Uddin|Udin|Hasan|Hassan|Haque|Hoque|Huq|Sarkar|Sarker|Talukder|Talukdar|Mia|Miah|Sultana|"
    "Jahan|Khatun|Alam|Ali|Karim|Kabir|Mahmud|Mahmood|Siddique|Siddiqui|Siddiky|Bhuiyan|Bhuiya|Bhuyan|Mollah|"
    "Molla|Sheikh|Shaikh|Shikder|Sikder|Paul|Das|Roy|Saha|Dey|Biswas|Ghosh|Barua|Chakraborty|Majumder|Mazumder|"
    "Mondal|Mridha|Howlader|Hawlader|Patwary|Munshi|Bepari|Matubbar|Haider|Reza|Rashid|Kader|Aziz|Sobhan|Mannan|"
    "Nahar|Parvin|Parveen|Ferdous|Ferdousi|Yasmin|Yeasmin|Nasrin|Afroz|Tasnim|Zaman|Anwar|Babu|Shah|Bhattacharjee|"
    "Sen|Nandi|Sultan|Kazi|Quazi|Mozumder|Pramanik|Prodhan|Pradhan|Rahim|Karmakar|Akand|Akanda|Fakir|Fakeer"
)

SECRET_PATTERNS = [
    # (regex, group to hide (0 = whole match))
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----", 0),
    (r"\bsk-(?:ant-|proj-|or-)?[A-Za-z0-9_\-]{20,}", 0),
    (r"\bnvapi-[A-Za-z0-9_\-]{20,}", 0),
    (r"\bgh[pousr]_[A-Za-z0-9]{30,}", 0),
    (r"\bgithub_pat_[A-Za-z0-9_]{40,}", 0),
    (r"\bAKIA[0-9A-Z]{16}\b", 0),
    (r"\bAIza[0-9A-Za-z_\-]{35}\b", 0),
    (r"\bxox[abposr]-[A-Za-z0-9-]{10,}", 0),
    (r"\bhf_[A-Za-z0-9]{30,}", 0),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 0),
    # password: x / api_key = "x" / token=x
    (r"(?i)\b(?:password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|pin)\b"
     r"\s*[:=]\s*[\"']?([^\s\"',;]{4,})", 1),
    # scheme://user:password@host
    (r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s@/]+)@", 1),
    # ?token=... &key=... in URLs
    (r"(?i)[?&](?:token|key|secret|sig|signature|password|auth|code|access_token)=([^&\s#\"']{6,})", 1),
]

ADDRESS_PART = (r"(?:House|Holding|Flat|Apartment|Apt|Road|Rd|Lane|Block|Sector|Plot|Village|Vill|Ward|"
                r"Section|Avenue|Ave|Street|St)\.?\s*(?:No\.?|#)?\s*[:\-]?\s*\d+[A-Za-z]?(?:/\d+[A-Za-z]?)?")
ADDRESS_PATTERNS = [
    (r"(?i)\b" + ADDRESS_PART + r"(?:\s*,\s*" + ADDRESS_PART + r")*", 0),
    (r"\b\d{1,6}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|"
     r"Court|Ct|Way|Place|Pl)\b\.?", 0),
]

OTHER_PATTERNS = [
    ("WHATSAPP_ID", r"\b\d{8,20}@(?:lid|s\.whatsapp\.net|g\.us|c\.us)\b", 0, 0.95),
    ("BD_PHONE", r"(?<![\w+])(?:\+?880[\s\-]?|0)1[3-9]\d(?:[\s\-]?\d){7}(?!\d)", 0, 0.9),
    ("ID_NUMBER", r"(?i)\b(?:nid|national\s*id|smart\s*card|birth\s*reg(?:istration)?|brn|passport|tin|"
                  r"driving\s*licen[cs]e)\b[^\n\d]{0,25}?([A-Z]{0,2}\d[\d\- ]{5,22}\d)", 1, 0.9),
    ("ID_NUMBER", r"(?<![\d.])\d{17}(?![\d.])", 0, 0.6),
    ("ACCOUNT_NUMBER", r"(?i)\b(?:account|acct|a/c|acc(?:ount)?\s*no|bank\s*ac|bkash|nagad|rocket|routing|swift)"
                       r"\b[^\n\d]{0,25}(\d[\d\- ]{5,24}\d)", 1, 0.9),
    ("DATE_OF_BIRTH", r"(?i)\b(?:dob|d\.o\.b|date\s+of\s+birth|born\s+on|birthday|birth\s*date)\b[^\n\d]{0,15}"
                      r"(\d{1,4}[\-/. ]\d{1,2}[\-/. ]\d{1,4}|\d{1,2}\s+[A-Za-z]{3,9},?\s+\d{4}|"
                      r"[A-Za-z]{3,9}\s+\d{1,2},?\s+\d{4})", 1, 0.95),
]


# --------------------------------------------------------------------------- detector

class Detector:
    """Finds personal and sensitive spans. Presidio + spaCy for names, regexes for the rest."""

    def __init__(self, cfg: dict):
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, EntityRecognizer, RecognizerResult
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_analyzer.predefined_recognizers import (
            EmailRecognizer, PhoneRecognizer, CreditCardRecognizer, IbanRecognizer, IpRecognizer,
            CryptoRecognizer, UsSsnRecognizer, SpacyRecognizer,
        )

        self.cfg = cfg
        self.min_score = float(cfg.get("min_score", 0.35))
        nlp_engine = NlpEngineProvider(nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
        }).create_engine()

        class GroupRegex(EntityRecognizer):
            """Regex recognizer that can hide just one capture group (e.g. the value after 'password:')."""

            def __init__(self, entity: str, patterns: list[tuple[str, int]], score: float):
                self._patterns = [(re.compile(p), g) for p, g in patterns]
                self._score = score
                super().__init__(supported_entities=[entity], name=f"group_regex_{entity}_{id(self)}")

            def load(self):
                pass

            def analyze(self, text, entities, nlp_artifacts=None):
                out = []
                for rx, g in self._patterns:
                    for m in rx.finditer(text):
                        s, e = m.span(g)
                        if e > s:
                            out.append(RecognizerResult(self.supported_entities[0], s, e, self._score))
                return out

        registry = RecognizerRegistry()
        registry.add_recognizer(SpacyRecognizer(supported_entities=["PERSON"]))
        registry.add_recognizer(EmailRecognizer())
        registry.add_recognizer(PhoneRecognizer(supported_regions=tuple(cfg.get("phone_regions", ["BD", "US"]))))
        registry.add_recognizer(CreditCardRecognizer())
        registry.add_recognizer(IbanRecognizer())
        registry.add_recognizer(IpRecognizer())
        registry.add_recognizer(CryptoRecognizer())
        registry.add_recognizer(UsSsnRecognizer())
        registry.add_recognizer(GroupRegex("SECRET", SECRET_PATTERNS, 0.95))
        registry.add_recognizer(GroupRegex("ADDRESS", ADDRESS_PATTERNS, 0.85))
        registry.add_recognizer(GroupRegex(
            "BD_NAME", [(r"\b(?!(?:The|In|Of|And|For|To|On|At|By|With|From|About|This|That|My|Our|Your|His|Her|"
                         r"Their|A|An|Is|Was|Dear|Hi|Hello)\s)(?:[A-Z][a-z]{1,20}\s+){1,3}(?:" + BD_SURNAMES + r")\b", 0),
                        (r"\b(?:Md|Mohammad|Mohammed|Muhammad|Mst|Mosammat|Sheikh|Syed|Kazi|Dr|Mr|Mrs|Ms|Miss)\.?"
                         r"\s+(?:[A-Z][a-z]{1,20}\s*){1,3}", 0)], 0.8))
        for entity, rx, group, score in OTHER_PATTERNS:
            registry.add_recognizer(GroupRegex(entity, [(rx, group)], score))

        self.entities = sorted({e for r in registry.recognizers for e in r.supported_entities})
        self.engine = AnalyzerEngine(registry=registry, nlp_engine=nlp_engine, supported_languages=["en"])
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, list[tuple[int, int, str]]] = OrderedDict()
        self._cache_max = 5000

    def _analyze_chunk(self, text: str) -> list[tuple[int, int, str, float]]:
        res = self.engine.analyze(text=text, language="en", entities=self.entities,
                                  score_threshold=self.min_score)
        return [(r.start, r.end, r.entity_type, r.score) for r in res]

    def find(self, text: str) -> list[tuple[int, int, str]]:
        """Non-overlapping (start, end, entity) spans, cached by text hash."""
        if not text or not text.strip():
            return []
        key = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        with self._lock:
            hit = self._cache.get(key)
            if hit is not None:
                self._cache.move_to_end(key)
                return hit
        norm = text.translate(BN_DIGITS)  # same length, so spans line up
        found: list[tuple[int, int, str, float]] = []
        with self._lock:
            for off, chunk in _chunks(norm, 20000):
                found += [(s + off, e + off, t, sc) for s, e, t, sc in self._analyze_chunk(chunk)]
        found = [f for f in found if f[2] != "PERSON" or _plausible_person(text[f[0]:f[1]])]
        spans = _resolve_overlaps(found)
        # Trim trailing punctuation/whitespace the regexes may have caught.
        cleaned = []
        for s, e, t in spans:
            if text[s:e].endswith(("'s", "\u2019s")):
                e -= 2
            while e > s and text[e - 1] in " \t\r\n,.;:":
                e -= 1
            while s < e and text[s] in " \t\r\n,.;:":
                s += 1
            if e > s:
                cleaned.append((s, e, t))
        with self._lock:
            self._cache[key] = cleaned
            if len(self._cache) > self._cache_max:
                self._cache.popitem(last=False)
        return cleaned


_NAME_TOKEN = re.compile(r"^(?:[A-Z][a-z'\-]+\.?|[A-Z]\.|[A-Z]{2,4}\.?|bin|binte|bint|al|el|de|van|von|da|ud|uz)$")


def _plausible_person(value: str) -> bool:
    """spaCy tags bits of code and ordinary capitalised words as names; keep only name-shaped spans."""
    v = value.strip()
    if not v or any(c in v for c in "()[]{}<>=;:/\\|@#$%^&*+\"`_0123456789"):
        return False
    if not re.search(r"[A-Za-z]", v):
        return True  # non-Latin script (e.g. Bangla): trust the detector
    toks = v.split()
    if not 1 <= len(toks) <= 5 or not all(_NAME_TOKEN.match(t) for t in toks):
        return False
    if len(toks) == 1:
        try:
            from wordfreq import zipf_frequency
            if zipf_frequency(v.lower().rstrip("."), "en") >= 4.5:
                return False  # a common English word (Profile, Total, Dear), not worth hiding alone
        except Exception:
            pass
    return True


def _chunks(text: str, size: int) -> Iterable[tuple[int, str]]:
    i = 0
    n = len(text)
    while i < n:
        j = min(n, i + size)
        if j < n:
            k = text.rfind("\n", i + size // 2, j)
            if k > i:
                j = k + 1
        yield i, text[i:j]
        i = j


def _resolve_overlaps(found: list[tuple[int, int, str, float]]) -> list[tuple[int, int, str]]:
    # Higher score first, then longer span; keep spans that don't overlap an accepted one.
    order = sorted(found, key=lambda x: (-x[3], -(x[1] - x[0])))
    taken: list[tuple[int, int, str]] = []
    for s, e, t, _ in order:
        if all(e <= ts or s >= te for ts, te, _ in taken):
            taken.append((s, e, t))
    return sorted(taken)


# --------------------------------------------------------------------------- vault

def _normalize(label: str, value: str) -> str:
    v = value.translate(BN_DIGITS)
    if label == "PHONE":
        d = re.sub(r"\D", "", v)
        return d[-10:] if len(d) >= 10 else d
    if label in ("ID_NUMBER", "BANK_ACCOUNT", "CARD"):
        return re.sub(r"[\s\-]", "", v)
    return re.sub(r"\s+", " ", v).strip().casefold()


class Vault:
    """Real value <-> placeholder, in memory only."""

    def __init__(self):
        self._lock = threading.Lock()
        self.fwd: dict[tuple[str, str], str] = {}
        self.rev: dict[str, str] = {}
        self.counters: dict[str, int] = {}
        self._sticky_rx: re.Pattern | None = None
        self._sticky_map: dict[str, str] = {}
        self._dirty = True

    def placeholder(self, label: str, value: str) -> str:
        key = (label, _normalize(label, value))
        with self._lock:
            ph = self.fwd.get(key)
            if ph:
                return ph
            n = self.counters.get(label, 0) + 1
            self.counters[label] = n
            ph = f"[{label}_{n}]"
            self.fwd[key] = ph
            self.rev[ph] = value
            if len(value.strip()) >= 3:
                self._sticky_map[value.strip().casefold()] = ph
                self._dirty = True
            return ph

    def sticky_regex(self) -> tuple[re.Pattern | None, dict[str, str]]:
        with self._lock:
            if self._dirty:
                vals = sorted(self._sticky_map, key=len, reverse=True)
                self._sticky_rx = (re.compile(r"(?<!\w)(?:" + "|".join(re.escape(v) for v in vals) + r")(?!\w)",
                                              re.IGNORECASE) if vals else None)
                self._dirty = False
            return self._sticky_rx, self._sticky_map

    def restore(self, text: str, json_escape: bool = False) -> str:
        if not text or "_" not in text:
            return text

        def sub(m: re.Match) -> str:
            ph = f"[{m.group(1) or m.group(3)}_{m.group(2) or m.group(4)}]"
            real = self.rev.get(ph)
            if real is None:
                return m.group(0)
            if json_escape:
                real = json.dumps(real, ensure_ascii=False)[1:-1]
            return real

        return PLACEHOLDER_RE.sub(sub, text)


# --------------------------------------------------------------------------- lists

class Lists:
    def __init__(self):
        self.always: list[str] = []
        self.never: set[str] = set()
        self._mt = (None, None)
        self._rx: re.Pattern | None = None

    def refresh(self):
        a, n = DATA / "always_hide.txt", DATA / "never_hide.txt"
        mt = (a.stat().st_mtime if a.exists() else 0, n.stat().st_mtime if n.exists() else 0)
        if mt == self._mt:
            return
        self._mt = mt

        def read(p: Path) -> list[str]:
            if not p.exists():
                return []
            out = []
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
            return out

        self.always = sorted(read(a), key=len, reverse=True)
        self.never = {w.casefold() for w in read(n)}
        self._rx = (re.compile(r"(?<!\w)(?:" + "|".join(re.escape(w) for w in self.always) + r")(?!\w)",
                               re.IGNORECASE) if self.always else None)

    def always_spans(self, text: str) -> list[tuple[int, int, str]]:
        if not self._rx:
            return []
        return [(m.start(), m.end(), "LISTED_NAME" if re.fullmatch(r"[^\W\d_]+(?:[\s.\-'][^\W\d_]+)*", m.group(0))
                 else "LISTED") for m in self._rx.finditer(text)]


# --------------------------------------------------------------------------- filter

class PrivacyFilter:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.detector = Detector(cfg)
        self.vault = Vault()
        self.lists = Lists()

    def anonymize(self, text: str, counts: dict[str, int] | None = None) -> str:
        if not isinstance(text, str) or not text:
            return text
        self.lists.refresh()
        spans = list(self.detector.find(text))
        listed = self.lists.always_spans(text)
        # Values hidden before keep their placeholder, even where the detector misses them this time.
        rx, mp = self.vault.sticky_regex()
        sticky = [(m.start(), m.end(), "STICKY:" + mp[m.group(0).casefold()])
                  for m in rx.finditer(text)] if rx is not None else []
        merged = _resolve_overlaps([(s, e, t, 1.0) for s, e, t in listed] +
                                   [(s, e, t, 0.9) for s, e, t in sticky] +
                                   [(s, e, t, 0.5) for s, e, t in spans])
        out = []
        last = 0
        for s, e, t in merged:
            value = text[s:e]
            if value.strip().casefold() in self.lists.never:
                continue
            if PLACEHOLDER_RE.fullmatch(value.strip()):
                continue  # already a placeholder
            if t.startswith("STICKY:"):
                ph = t[7:]
                label = ph[1:].rsplit("_", 1)[0]
            else:
                label = LABELS.get(t, "PRIVATE")
                ph = self.vault.placeholder(label, value)
            out.append(text[last:s])
            out.append(ph)
            last = e
            if counts is not None:
                counts[label] = counts.get(label, 0) + 1
        out.append(text[last:])
        result = "".join(out)
        # Second sticky pass: catches values first found further down in this same text.
        rx, mp = self.vault.sticky_regex()
        if rx is not None:
            def sub(m: re.Match) -> str:
                v = m.group(0)
                if v.casefold() in self.lists.never:
                    return v
                ph = mp.get(v.casefold())
                if ph and counts is not None:
                    lab = ph[1:].rsplit("_", 1)[0]
                    counts[lab] = counts.get(lab, 0) + 1
                return ph or v
            result = _sub_outside_placeholders(rx, sub, result)
        return result

    # ---- request bodies

    def anonymize_messages(self, messages: list, counts: dict[str, int]) -> list:
        out = []
        for msg in messages:
            if not isinstance(msg, dict):
                out.append(msg)
                continue
            m = dict(msg)
            c = m.get("content")
            if isinstance(c, str):
                m["content"] = self.anonymize(c, counts)
            elif isinstance(c, list):
                parts = []
                for p in c:
                    if not isinstance(p, dict):
                        parts.append(p)
                        continue
                    p = dict(p)
                    if p.get("type") == "text" and isinstance(p.get("text"), str):
                        p["text"] = self.anonymize(p["text"], counts)
                    elif p.get("type") in ("image_url", "input_image", "image", "input_audio", "file") and \
                            self.cfg.get("block_images", True):
                        counts["IMAGE_REMOVED"] = counts.get("IMAGE_REMOVED", 0) + 1
                        p = {"type": "text", "text": "[attachment removed by the privacy filter]"}
                    parts.append(p)
                m["content"] = parts
            for key in ("reasoning_content", "reasoning"):
                if isinstance(m.get(key), str):
                    m[key] = self.anonymize(m[key], counts)
            if isinstance(m.get("tool_calls"), list):
                tcs = []
                for tc in m["tool_calls"]:
                    tc = json.loads(json.dumps(tc))
                    fn = tc.get("function") or {}
                    if isinstance(fn.get("arguments"), str):
                        fn["arguments"] = self.anonymize(fn["arguments"], counts)
                    tcs.append(tc)
                m["tool_calls"] = tcs
            out.append(m)
        return out

    def anonymize_body(self, body: dict, counts: dict[str, int]) -> dict:
        b = dict(body)
        if isinstance(b.get("messages"), list):
            b["messages"] = self.anonymize_messages(b["messages"], counts)
        if isinstance(b.get("prompt"), str):
            b["prompt"] = self.anonymize(b["prompt"], counts)
        if isinstance(b.get("input"), str):
            b["input"] = self.anonymize(b["input"], counts)
        elif isinstance(b.get("input"), list):
            b["input"] = [self.anonymize(x, counts) if isinstance(x, str) else x for x in b["input"]]
        return b

    # ---- responses

    def restore_response(self, data: dict) -> dict:
        for ch in data.get("choices") or []:
            msg = ch.get("message")
            if isinstance(msg, dict):
                for key in ("content", "reasoning_content", "reasoning"):
                    if isinstance(msg.get(key), str):
                        msg[key] = self.vault.restore(msg[key])
                for tc in msg.get("tool_calls") or []:
                    fn = tc.get("function") or {}
                    if isinstance(fn.get("arguments"), str):
                        fn["arguments"] = self.vault.restore(fn["arguments"], json_escape=True)
            if isinstance(ch.get("text"), str):
                ch["text"] = self.vault.restore(ch["text"])
        return data


def _sub_outside_placeholders(rx: re.Pattern, fn, text: str) -> str:
    """Apply rx.sub only to the text between existing placeholders."""
    pieces = []
    last = 0
    for m in PLACEHOLDER_RE.finditer(text):
        pieces.append(rx.sub(fn, text[last:m.start()]))
        pieces.append(m.group(0))
        last = m.end()
    pieces.append(rx.sub(fn, text[last:]))
    return "".join(pieces)


class StreamRestorer:
    """Restores placeholders in streamed text, holding back a fragment that might be half a placeholder."""

    def __init__(self, vault: Vault, json_escape: bool = False):
        self.vault = vault
        self.json_escape = json_escape
        self.buf = ""

    def feed(self, text: str) -> str:
        self.buf += text
        m = PARTIAL_TAIL_RE.search(self.buf)
        cut = m.start() if m else len(self.buf)
        ready, self.buf = self.buf[:cut], self.buf[cut:]
        return self.vault.restore(ready, self.json_escape)

    def flush(self) -> str:
        ready, self.buf = self.buf, ""
        return self.vault.restore(ready, self.json_escape)


# --------------------------------------------------------------------------- server

_CONSOLE_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>privacy filter console</title>
<style>body{background:#0d1117;color:#c9d1d9;font-family:Consolas,monospace;margin:16px}
h1{font-size:15px;color:#e6edf3} .row{border:1px solid #21262d;border-radius:6px;padding:10px;margin:10px 0}
.meta{color:#8b949e;font-size:12px;margin-bottom:6px} .hid{color:#3fb950}
pre{white-space:pre-wrap;word-break:break-word;font-size:12px;margin:6px 0}
.out{color:#79c0ff} .recv{color:#ffd29d} button{float:right}
</style></head><body>
<h1>privacy filter console &mdash; anonymized out, restored in
<button onclick="fetch('/console.json').then(r=>r.json()).then(d=>render(d))">refresh</button></h1>
<div id="rows">(waiting for the first request)</div>
<script>
function esc(s){return (s||'').replace(/&/g,'&').replace(/</g,'<')}
function render(rows){document.getElementById('rows').innerHTML = rows.slice().reverse().map(r=>
  '<div class="row"><div class="meta">' + new Date(r.ts*1000).toLocaleTimeString() +
  ' &nbsp; ' + esc(r.provider) + ' &nbsp; ' + esc(r.model||'') +
  ' &nbsp; <span class="hid">' + Object.entries(r.hidden||{}).map(([k,v])=>k+' '+v).join(', ') + '</span></div>' +
  '<pre class="out">' + esc(r.out) + '</pre>' +
  (r.recv ? '<pre class="recv">' + esc(r.recv) + '</pre>' : '') + '</div>').join('')}
async function tick(){try{const r=await fetch('/console.json');render(await r.json())}catch(e){}}
tick(); setInterval(tick, 1500);
</script></body></html>"""


def build_app(cfg: dict, pf: PrivacyFilter):
    import httpx
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, StreamingResponse, Response
    from starlette.concurrency import run_in_threadpool

    app = FastAPI(title="Privacy filter", docs_url=None, redoc_url=None, openapi_url=None)
    upstream = cfg["upstream"].rstrip("/")
    upstreams = {k: v.rstrip("/") for k, v in (cfg.get("upstreams") or {}).items()}
    client = httpx.AsyncClient(timeout=httpx.Timeout(cfg.get("upstream_timeout_s", 900), connect=30))
    LOGS.mkdir(exist_ok=True)
    audit_path = LOGS / "audit.log"
    stats = {"requests": 0, "blocked": 0, "started": time.strftime("%Y-%m-%d %H:%M:%S")}

    def audit(entry: dict):
        """Counts only. The prompt and reply text live in the console ring (memory),
        never in this file, so the audit log still carries no personal values."""
        entry["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
        clean_entry = {k: v for k, v in entry.items() if k not in ("out", "recv")}
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(clean_entry, ensure_ascii=False) + "\n")

    def write_preview(provider: str, body: dict, counts: dict) -> None:
        """Save what the ANONYMIZED request looks like, for the overlay box.
        Only already-anonymized text and counts are written; never real values."""
        try:
            lines = []
            for m in body.get("messages") or []:
                role = (m.get("role") or "?")[:9]
                c = m.get("content")
                if isinstance(c, list):
                    c = " ".join(str(p.get("text", "")) for p in c if isinstance(p, dict))
                if not isinstance(c, str):
                    continue
                lines.append(f"[{role}] {c}")
            text = "\n".join(lines)
            if len(text) > 6000:
                text = text[:6000] + "\n… (truncated)"
            with open(LOGS / "last_sent.json", "w", encoding="utf-8") as f:
                json.dump({"ts": time.time(), "provider": provider, "model": body.get("model"),
                           "hidden": counts, "stream": bool(body.get("stream")), "text": text},
                          f, ensure_ascii=False)
        except Exception:
            pass

    console_rows: list = []          # in memory only: the restored replies are real data

    def console_read() -> list:
        return console_rows

    def console_write(entries: list):
        del console_rows[:]
        console_rows.extend(entries[-20:])

    def console_add(entry: dict) -> None:
        """One exchange in the live console: anonymized outgoing, restored incoming."""
        import time as _t
        rows = console_read()
        row = {"ts": _t.time(), "provider": entry.get("provider") or "default",
               "model": entry.get("model"), "hidden": entry.get("hidden") or {},
               "stream": entry.get("stream") or False,
               "out": entry.get("out") or "", "recv": entry.get("recv") or ""}
        if rows and rows[-1].get("out") == row["out"] and not rows[-1].get("recv") and row["recv"]:
            rows[-1] = row           # the reply half of the exchange just sent
        else:
            rows.append(row)
        console_write(rows)

    def fwd_headers(req: Request) -> dict:
        h = {"Content-Type": "application/json", "Accept": req.headers.get("accept", "application/json")}
        if req.headers.get("authorization"):
            h["Authorization"] = req.headers["authorization"]
        return h

    @app.get("/health")
    async def health():
        return {"ok": True, "upstream": upstream, "providers": sorted(upstreams), **stats,
                "placeholders": len(pf.vault.rev)}

    @app.post("/preview")
    async def preview(req: Request):
        if req.client and req.client.host not in ("127.0.0.1", "::1"):
            return JSONResponse({"error": "local only"}, status_code=403)
        body = await req.json()
        counts: dict[str, int] = {}
        out = await run_in_threadpool(pf.anonymize, body.get("text", ""), counts)
        write_preview("preview", {"messages": [{"role": "user", "content": out}]}, counts)
        console_add({"provider": "preview", "model": None, "hidden": counts, "stream": False,
                     "out": "[user] " + (out if len(out) <= 4000 else out[:4000] + "… (truncated)")})
        return {"text": out, "counts": counts}

    @app.get("/v1/models")
    async def models(req: Request):
        r = await client.get(upstream + "/models", headers=fwd_headers(req))
        return Response(r.content, status_code=r.status_code, media_type="application/json")

    @app.get("/v1/models/{model_id:path}")
    async def model_one(model_id: str, req: Request):
        r = await client.get(upstream + "/models/" + model_id, headers=fwd_headers(req))
        return Response(r.content, status_code=r.status_code, media_type="application/json")

    def _preview_text(body: dict, limit: int = 4000) -> str:
        lines = []
        for m in body.get("messages") or []:
            role = (m.get("role") or "?")[:9]
            c = m.get("content")
            if isinstance(c, list):
                c = " ".join(str(p.get("text", "")) for p in c if isinstance(p, dict))
            if not isinstance(c, str):
                continue
            lines.append(f"[{role}] {c}")
        text = "\n".join(lines)
        return text if len(text) <= limit else text[:limit] + "\n… (truncated)"

    async def handle(req: Request, path: str, up: str | None = None, provider: str = ""):
        stats["requests"] += 1
        t0 = time.time()
        try:
            body = await req.json()
            counts: dict[str, int] = {}
            clean = await run_in_threadpool(pf.anonymize_body, body, counts)
        except Exception as e:  # fail closed
            stats["blocked"] += 1
            audit({"path": path, "blocked": True, "error": type(e).__name__})
            console_add({"provider": provider or "default", "model": None, "stream": False,
                         "hidden": {}, "out": "(blocked by the privacy filter: "
                         + type(e).__name__ + ", nothing was sent)"})
            return JSONResponse({"error": {"message": "privacy filter failed, so the request was not sent "
                                                      f"({type(e).__name__})", "type": "privacy_filter"}},
                                status_code=502)
        write_preview(provider or "default", clean, counts)
        entry = {"path": path, "provider": provider or "default", "model": body.get("model"),
                 "stream": bool(body.get("stream")), "hidden": counts,
                 "out": _preview_text(clean),
                 "messages": len(body.get("messages") or []), "filter_ms": int((time.time() - t0) * 1000),
                 "hidden": counts}
        url = (up or upstream) + path
        if body.get("stream"):
            up = await client.send(client.build_request("POST", url, json=clean, headers=fwd_headers(req)),
                                   stream=True)
            if up.status_code != 200:
                raw = await up.aread()
                await up.aclose()
                entry["status"] = up.status_code
                audit(entry)
                return Response(raw, status_code=up.status_code,
                                media_type=up.headers.get("content-type", "application/json"))
            return StreamingResponse(_stream(up, entry), media_type="text/event-stream")
        r = await client.post(url, json=clean, headers=fwd_headers(req))
        entry["status"] = r.status_code
        audit(entry)
        try:
            data = r.json()
        except Exception:
            return Response(r.content, status_code=r.status_code, media_type=r.headers.get("content-type"))
        if r.status_code == 200:
            data = pf.restore_response(data)
            recv = ""
            for ch in data.get("choices") or []:
                msg = ch.get("message") or {}
                if isinstance(msg.get("content"), str):
                    recv += msg["content"]
            entry["recv"] = recv if len(recv) <= 4000 else recv[:4000] + "… (truncated)"
        console_add(entry)
        return JSONResponse(data, status_code=r.status_code)

    async def _stream(r, entry: dict):
        restorers: dict[tuple, StreamRestorer] = {}

        def rest(key: tuple, json_escape=False) -> StreamRestorer:
            if key not in restorers:
                restorers[key] = StreamRestorer(pf.vault, json_escape)
            return restorers[key]

        def flush_choice(idx: int, delta: dict):
            for key, r in list(restorers.items()):
                if key[0] != idx:
                    continue
                tail = r.flush()
                if not tail:
                    continue
                if key[1] == "tool":
                    tcs = delta.setdefault("tool_calls", [])
                    tc = next((t for t in tcs if t.get("index") == key[2]), None)
                    if tc is None:
                        tc = {"index": key[2], "function": {"arguments": ""}}
                        tcs.append(tc)
                    fn = tc.setdefault("function", {})
                    fn["arguments"] = (fn.get("arguments") or "") + tail
                else:
                    delta[key[1]] = (delta.get(key[1]) or "") + tail

        status = r.status_code
        try:
            if True:
                async for line in r.aiter_lines():
                    if not line.startswith("data:"):
                        if line:
                            yield (line + "\n").encode()
                        continue
                    payload = line[5:].strip()
                    if payload == "[DONE]":
                        leftovers = {}
                        for key in list(restorers):
                            leftovers.setdefault(key[0], {})
                        if any(r_.buf for r_ in restorers.values()):
                            chunk = {"object": "chat.completion.chunk", "choices": []}
                            for idx in leftovers:
                                d: dict = {}
                                flush_choice(idx, d)
                                if d:
                                    chunk["choices"].append({"index": idx, "delta": d})
                            if chunk["choices"]:
                                yield b"data: " + json.dumps(chunk, ensure_ascii=False).encode() + b"\n\n"
                        yield b"data: [DONE]\n\n"
                        continue
                    try:
                        data = json.loads(payload)
                    except Exception:
                        yield (line + "\n\n").encode()
                        continue
                    for ch in data.get("choices") or []:
                        idx = ch.get("index", 0)
                        delta = ch.get("delta") or {}
                        for key in ("content", "reasoning_content", "reasoning"):
                            if isinstance(delta.get(key), str):
                                delta[key] = rest((idx, key)).feed(delta[key])
                                if key == "content":
                                    entry["recv"] = (entry.get("recv") or "") + delta[key]
                        for tc in delta.get("tool_calls") or []:
                            fn = tc.get("function") or {}
                            if isinstance(fn.get("arguments"), str):
                                fn["arguments"] = rest((idx, "tool", tc.get("index", 0)), True).feed(fn["arguments"])
                        if ch.get("finish_reason"):
                            flush_choice(idx, delta)
                            ch["delta"] = delta
                    yield b"data: " + json.dumps(data, ensure_ascii=False).encode() + b"\n\n"
        finally:
            await r.aclose()
            entry["status"] = status
            recv = entry.get("recv") or ""
            if len(recv) > 4000:
                entry["recv"] = recv[:4000] + "… (truncated)"
            audit(entry)
            console_add(entry)

    @app.post("/v1/chat/completions")
    async def chat(req: Request):
        return await handle(req, "/chat/completions")

    @app.post("/v1/completions")
    async def completions(req: Request):
        return await handle(req, "/completions")

    @app.post("/v1/embeddings")
    async def embeddings(req: Request):
        return await handle(req, "/embeddings")

    def upstream_for(name: str):
        if name not in upstreams:
            return JSONResponse({"error": {"message": "unknown provider " + name + ". "
                                              f"Known: {sorted(upstreams)}"}}, status_code=404)
        return upstreams[name]

    @app.post("/p/{name}/v1/chat/completions")
    async def chat_p(name: str, req: Request):
        return await handle(req, "/chat/completions", upstream_for(name), name)

    @app.post("/p/{name}/v1/completions")
    async def completions_p(name: str, req: Request):
        return await handle(req, "/completions", upstream_for(name), name)

    @app.post("/p/{name}/v1/embeddings")
    async def embeddings_p(name: str, req: Request):
        return await handle(req, "/embeddings", upstream_for(name), name)

    @app.get("/p/{name}/v1/models")
    async def models_p(name: str, req: Request):
        return Response((await client.get(upstream_for(name) + "/models",
                                           headers=fwd_headers(req))).content,
                         media_type="application/json")

    @app.get("/console")
    async def console_page():
        from fastapi.responses import HTMLResponse
        return HTMLResponse(_CONSOLE_HTML)

    @app.get("/console.json")
    async def console_data():
        return console_read()

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def other(path: str):
        return JSONResponse({"error": {"message": f"/{path} is not forwarded by the privacy filter"}},
                            status_code=404)

    return app


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--test", metavar="TEXT", help="print the anonymized version of TEXT and exit")
    args = ap.parse_args()
    cfg = load_config()
    pf = PrivacyFilter(cfg)
    if args.test is not None:
        counts: dict[str, int] = {}
        print(pf.anonymize(args.test, counts))
        print(json.dumps(counts))
        return
    import uvicorn
    pf.anonymize("warm up John Smith 01711000000")  # load the model before the first real request
    app = build_app(cfg, pf)
    uvicorn.run(app, host=cfg["listen_host"], port=int(cfg["listen_port"]), log_level="warning")


if __name__ == "__main__":
    main()
