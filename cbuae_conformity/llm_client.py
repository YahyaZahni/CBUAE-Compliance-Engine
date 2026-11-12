"""Provider-agnostic LLM client with a call log for reproducibility.

Configure with environment variables:
  LLM_PROVIDER   anthropic | claude_cli | openai | replay
  LLM_MODEL      model name (required for anthropic/openai), e.g. the Claude model you have access to, or a local
                 Ollama model such as "qwen2.5:14b-instruct"
  ANTHROPIC_API_KEY                         for provider=anthropic
  OPENAI_BASE_URL, OPENAI_API_KEY           for provider=openai (any OpenAI-compatible server; Ollama:
                                            OPENAI_BASE_URL=http://localhost:11434/v1, OPENAI_API_KEY=ollama)
  CLAUDE_BIN                                for provider=claude_cli, only if the `claude` program is not found

provider=claude_cli calls the Claude Code command-line program in print mode (`claude -p`), which is billed to the
Claude subscription (Pro/Max) you are signed in with instead of an API key. Sign in once with `claude auth login`.
It differs from the API in three ways, all recorded in the call log: the temperature cannot be set (the model's
default is used), max_tokens is not applied, and Claude Code adds about a thousand tokens of its own context to
each request. Tools, project instructions, settings and session history are switched off, and the call runs in an
empty directory. Set LLM_MODEL to a full model id rather than an alias such as "sonnet", so the log names one
model; the id the service actually answered with is saved as `resolved_models`.
Every call (prompt, response, model, time) is saved under data/llm_runs/<sha256>.json. provider=replay answers from
that log only, so an experiment can be re-scored exactly without calling a model again.
Calls use temperature 0 unless LLM_TEMPERATURE is set (some hosted models reject the parameter: set
LLM_TEMPERATURE=default to leave it out). A non-zero setting is part of the log key, so runs never mix.
"""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from .config import ROOT

LOG_DIR = ROOT / "data" / "llm_runs"


class LLMError(RuntimeError):
    pass


def _post(url, headers, body, timeout=300):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"content-type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def claude_bin() -> str:
    """The Claude Code program: $CLAUDE_BIN, else `claude` on the PATH, else the copy inside the newest VS Code
    extension (the extension does not put it on the PATH)."""
    if os.environ.get("CLAUDE_BIN"):
        return os.environ["CLAUDE_BIN"]
    found = shutil.which("claude")
    if found:
        return found
    ext = sorted((Path.home() / ".vscode" / "extensions").glob("anthropic.claude-code-*/resources/native-binary/claude*"),
                 key=lambda q: q.stat().st_mtime)
    if ext:
        return str(ext[-1])
    raise LLMError("Claude Code not found: install it (https://claude.com/claude-code) or set CLAUDE_BIN to the program")


def _claude_cli(model, system, user, timeout=900):
    """One prompt through `claude -p` on the signed-in subscription. Returns (text, extra fields for the log)."""
    env = {k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")}  # subscription, not a key
    with tempfile.TemporaryDirectory() as td:  # empty working directory: no project instructions or memory are picked up
        sp = Path(td) / "system.txt"           # prompts go by file and stdin: no command-line length or quoting limits
        sp.write_text(system, encoding="utf-8")
        cmd = [claude_bin(), "-p", "--model", model, "--system-prompt-file", str(sp), "--tools", "",
               "--output-format", "json", "--no-session-persistence", "--setting-sources", "",
               "--strict-mcp-config", "--disable-slash-commands"]
        try:
            r = subprocess.run(cmd, input=user.encode("utf-8"), capture_output=True, cwd=td, env=env, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise LLMError(f"claude did not answer within {timeout}s") from e
    out = r.stdout.decode("utf-8", errors="replace").strip()
    try:
        res = json.loads(out[out.index("{"):])
    except ValueError as e:
        raise LLMError(f"claude exited with code {r.returncode}: "
                       f"{(out or r.stderr.decode('utf-8', errors='replace'))[:500]}") from e
    if r.returncode != 0 or res.get("is_error") or not isinstance(res.get("result"), str):
        raise LLMError(f"claude returned an error (a usage limit ends a run this way; calls already answered are "
                       f"kept, so run the same command again later): {str(res.get('result'))[:500]}")
    return res["result"], {"resolved_models": sorted(res.get("modelUsage") or {}), "usage": res.get("usage")}


class LLM:
    def __init__(self, provider=None, model=None):
        self.provider = provider or os.environ.get("LLM_PROVIDER", "replay")
        self.model = model or os.environ.get("LLM_MODEL", "")
        t = os.environ.get("LLM_TEMPERATURE", "0")
        self.temperature = None if t == "default" or self.provider == "claude_cli" else float(t)
        if self.provider in ("anthropic", "openai", "claude_cli") and not self.model:
            raise LLMError("set LLM_MODEL")
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    def key(self, system, user):
        tag = "" if self.temperature == 0 else f"\ntemperature={self.temperature}"
        if self.provider == "claude_cli":
            tag += "\nvia=claude_cli"   # answers obtained through Claude Code are never mixed with API answers
        return hashlib.sha256(f"{self.model}\n{system}\n{user}{tag}".encode()).hexdigest()

    def complete(self, system: str, user: str, max_tokens=4000) -> str:
        k = self.key(system, user)
        path = LOG_DIR / f"{k}.json"
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))["response"]
        if self.provider == "replay":
            raise LLMError(f"no logged response for prompt {k[:12]} (model={self.model!r}); run with a live provider first")
        t0 = time.time()
        temp = {} if self.temperature is None else {"temperature": self.temperature}
        extra = {}
        if self.provider == "claude_cli":
            text, extra = _claude_cli(self.model, system, user)
        elif self.provider == "anthropic":
            out = _post("https://api.anthropic.com/v1/messages",
                        {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"},
                        {"model": self.model, "max_tokens": max_tokens, "system": system, **temp,
                         "messages": [{"role": "user", "content": user}]})
            text = "".join(b.get("text", "") for b in out["content"])
        elif self.provider == "openai":
            base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
            out = _post(f"{base}/chat/completions", {"authorization": f"Bearer {os.environ.get('OPENAI_API_KEY', '')}"},
                        {"model": self.model, **temp, "max_tokens": max_tokens,
                         "response_format": {"type": "json_object"},
                         "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
            text = out["choices"][0]["message"]["content"]
        else:
            raise LLMError(f"unknown provider {self.provider}")
        path.write_text(json.dumps({"provider": self.provider, "model": self.model, "temperature": self.temperature,
                                    "system": system, "user": user, **extra,
                                    "response": text, "seconds": round(time.time() - t0, 2),
                                    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, indent=2), encoding="utf-8")
        return text


def parse_json(text: str):
    """Extract the first JSON object from a model response (models sometimes wrap it in prose or fences)."""
    s = text.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1].rsplit("```", 1)[0]
    start = s.find("{")
    if start < 0:
        raise ValueError("no JSON object in response")
    depth, in_str, esc = 0, False, False
    for i, ch in enumerate(s[start:], start):
        if in_str:
            esc = (ch == "\\") and not esc
            if ch == '"' and not esc:
                in_str = False
            elif ch != "\\":
                esc = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(s[start:i + 1])
    raise ValueError("unterminated JSON object")
