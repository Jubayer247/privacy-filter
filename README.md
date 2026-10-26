# privacy-filter

I use a lot of free and cheap AI APIs. NVIDIA's, OpenRouter's, a couple of local
models. One day I looked at what I was actually sending them and it was client
names, phone numbers, e-mail addresses. Nobody signed up for that.

So I put a small proxy between my tools and the internet. Every request that
goes through it gets scanned for personal data first. Names, phone numbers,
e-mail addresses, secrets, ID numbers, addresses. Whatever it finds is swapped
for a placeholder like `[PERSON_12]` or `[PHONE_1]` before anything leaves my
machine. The model gets the context it needs, but not the person.

Then the reply comes back through the same proxy, and the placeholders are
turned back into the real values. This works mid-sentence, across streamed
tokens, and inside tool call arguments. So the model can still say "call
[PERSON_12] at [PHONE_1]" and my tool gets the real number.

It runs on my PC, on 127.0.0.1. It holds the name-to-placeholder map in
memory only. Nothing is written to disk except a log of counts (how many
things were hidden, never the values).

## What it catches

Presidio with the large spaCy English model, plus my own regexes and lists:

- names (English and names in Bangla script), with a word-frequency check so
  it stops tagging `String caseRef` in Java code as a person
- phone numbers for Bangladesh, US, UK, India, Canada, Australia, the Gulf,
  Malaysia, Singapore (Bangla digits are translated first)
- e-mail addresses, ID numbers, addresses, credit cards, URLs with embedded
  credentials, things that look like `password:` or `api_key=` or `nvapi-...`
- anything you add to `data/always_hide.txt`
- anything you want kept visible, put it in `data/never_hide.txt`

If the filter itself fails, the request is not sent. It returns a 502 and
you'll know.

Images are dropped and replaced with a note. Text inside a picture can't be
checked, so pictures don't go through.

## Honest limits

- It hides what it recognizes. It is a filter, not a promise. Run your own
  tests on your own data before trusting it.
- Placeholder restore is exact-match on the recognized text. Typos in the
  original stay typos.
- It speaks the OpenAI chat/completions shape. That covers NVIDIA NIM,
  OpenRouter, DeepSeek, GLM, llama.cpp, Ollama and friends. Anything that
  talks Anthropic's format is not wired up yet.

## Install

Python 3.12. I use `uv` because the venv has no pip:

    uv venv --python 3.12
    uv pip install fastapi uvicorn httpx presidio-analyzer phonenumbers wordfreq
    uv pip install "en_core_web_lg @ <spaCy release wheel url for your platform>"

Copy the example lists and put your own entries in:

    copy data\always_hide.example.txt data\always_hide.txt
    copy data\never_hide.example.txt data\never_hide.txt

Point the tool you already use at the proxy instead of the internet. Pick your
provider by path:

    http://127.0.0.1:8790/p/nvidia/v1      -> NVIDIA NIM
    http://127.0.0.1:8790/p/openrouter/v1  -> OpenRouter
    http://127.0.0.1:8790/p/zai/v1         -> Z.ai (GLM)
    http://127.0.0.1:8790/p/local/v1       -> llama.cpp on 18434
    http://127.0.0.1:8790/p/local-ollama/v1 -> Ollama on 11434

Your API key travels with your request and is forwarded as-is. The proxy
never stores keys. Add more providers in `config.json` under `upstreams`.
The plain `/v1/...` paths use the default `upstream` from `config.json`.

Try it without calling anything:

    .venv\Scripts\python.exe privacy_filter.py --test "Rahim called from 01711000000"

That prints the anonymized version and exits.

## Tests

The test file runs a fake upstream that records everything it receives, then
checks that nothing personal reached it and that replies came back whole:

    .venv\Scripts\python.exe test_filter.py

Expect `ALL PASSED` at the end.

## Files

- `privacy_filter.py` - the proxy, one file, no framework beyond FastAPI
- `test_filter.py` - end-to-end tests against a fake upstream
- `config.json` - listen port, provider list, detection settings
- `data/always_hide.txt` - always hidden, one entry per line (yours, not committed)
- `data/never_hide.txt` - never hidden, one entry per line
- `logs/audit.log` - counts only, never values

## License

MIT. Use it, change it, no warranty. If it hides something it shouldn't have,
or shows something it should have hidden, that's on you to catch with your own
tests.
