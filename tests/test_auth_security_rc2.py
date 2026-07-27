import uuid
from backend.app.core.config import settings
from backend.app.models.refresh_session import RefreshSession


def _login(client, test_user):
    return client.post('/api/v1/login', data={'username': test_user.username, 'password': 'TestPassword123!'})


def test_login_sets_httponly_refresh_cookie_and_hides_token(client, test_user):
    response = _login(client, test_user)
    assert response.status_code == 200
    assert 'refresh_token' not in response.json()
    cookie = response.headers.get('set-cookie', '').lower()
    assert settings.REFRESH_COOKIE_NAME.lower() in cookie
    assert 'httponly' in cookie


def test_refresh_rotates_session_cookie(client, test_user, db_session):
    login = _login(client, test_user)
    old_cookie = client.cookies.get(settings.REFRESH_COOKIE_NAME)
    refreshed = client.post('/api/v1/refresh')
    assert refreshed.status_code == 200
    new_cookie = client.cookies.get(settings.REFRESH_COOKIE_NAME)
    assert old_cookie and new_cookie and old_cookie != new_cookie
    assert db_session.query(RefreshSession).filter(RefreshSession.user_id == test_user.id, RefreshSession.revoked.is_(True)).count() >= 1


def test_refresh_requires_cookie(client):
    client.cookies.clear()
    response = client.post('/api/v1/refresh')
    assert response.status_code == 401


def test_logout_revokes_cookie_session(client, test_user):
    login = _login(client, test_user)
    access = login.json()['access_token']
    response = client.post('/api/v1/logout', headers={'Authorization': f'Bearer {access}'})
    assert response.status_code == 200
    assert not client.cookies.get(settings.REFRESH_COOKIE_NAME)
    assert client.post('/api/v1/refresh').status_code == 401
