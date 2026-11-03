from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from siwc_local_bridge.app import CredentialStore, create_app


def test_new_authorization_is_loopback_pkce_and_has_no_private_app_details(tmp_path):
    app = create_app(directory=tmp_path, agent_name="Generic Local Bridge")
    with TestClient(app) as client:
        assert client.get('/v1/status').json() == {'connected': False, 'plan_usage_authorized': False}
        url = client.post('/v1/authorize').json()['authorization_url']
    query = parse_qs(urlparse(url).query)
    assert url.startswith('https://auth.openai.com/api/accounts/authorize?')
    assert query['client_id'] == ['dynamic_agent_client']
    assert query['redirect_uri'] == ['http://127.0.0.1:1455/auth/callback']
    assert query['resource'] == ['https://api.openai.com/v1']
    assert query['code_challenge_method'] == ['S256']
    assert 'chatgpt.tokens.use.direct' in query['scope'][0]
    assert 'Generic Local Bridge' in query['agent_name_hint'][0]
    assert 'sxwf' not in url.lower()


def test_host_id_is_stable_and_private(tmp_path):
    store = CredentialStore(Path(tmp_path))
    first = store.host_id()
    assert first == store.host_id()
    assert first.startswith('urn:uuid:')
    assert (Path(tmp_path) / 'host.json').stat().st_mode & 0o777 == 0o600


def test_callback_requires_an_active_matching_state(tmp_path):
    app = create_app(directory=tmp_path)
    with TestClient(app) as client:
        response = client.get('/auth/callback?code=ignored&state=wrong')
    assert response.status_code == 400
    assert 'ignored' not in response.text
