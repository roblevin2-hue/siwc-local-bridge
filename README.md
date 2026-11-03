# Local SIWC Bridge

A generic, local-only pairing bridge for the documented **Sign in with
ChatGPT** self-hosted workflow. It contains no downstream product integration,
model configuration, prompts, media, server addresses, or credentials.

## What it does

1. Creates and persists a stable per-host identifier.
2. Starts OpenAI's dynamic open-source-client registration with PKCE.
3. Receives the authorization callback only on `127.0.0.1`.
4. Exchanges the code, validates the ID token against OpenAI's JWKS, and writes
   credentials atomically with owner-only permissions.
5. Exposes a redacted local status endpoint. It never returns credentials.

## What it intentionally does not do

- Send a request to an AI model.
- Expose a public callback route.
- Copy credentials to another host.
- Log, export, or place credentials in browser storage.

For a self-hosted VM, complete the browser flow on the computer running this
bridge. Transfer the protected credential file to the VM over a separately
approved secure channel, preserving the VM's own host identifier. See OpenAI's
[self-hosted VM guidance](https://developers.openai.com/siwc/token-sharing-open-source/self-hosted-vms).

## Development

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
uvicorn siwc_local_bridge.app:create_app --factory --host 127.0.0.1 --port 1455
```

The browser-facing connection is local-only by design. Publishing this code
does not publish any credentials or downstream system.
