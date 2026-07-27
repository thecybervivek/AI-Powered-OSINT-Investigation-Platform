import os
from backend.app.core.paths import PROJECT_ROOT, resolve_project_path
from backend.app.utils.privacy import redact_for_external_ai


def test_external_ai_redaction_removes_common_sensitive_values():
    data = {'email':'alice@example.com','api_key':'secret','nested':{'ip':'192.0.2.10','password':'p'}}
    redacted = redact_for_external_ai(data)
    assert redacted['email'] == '[REDACTED_EMAIL]'
    assert redacted['api_key'] == '[REDACTED]'
    assert redacted['nested']['password'] == '[REDACTED]'
    assert redacted['nested']['ip'] == '[REDACTED_IP]'


def test_project_paths_do_not_depend_on_cwd(tmp_path):
    before = os.getcwd()
    try:
        os.chdir(tmp_path)
        assert resolve_project_path('storage/uploads') == PROJECT_ROOT / 'storage/uploads'
    finally:
        os.chdir(before)
