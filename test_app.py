import os
import re
import json
import tempfile
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

os.environ.update(SECRET_KEY='test-only-secret-' * 4, DB_PATH=tempfile.mktemp(suffix='.sqlite3'), SESSION_HTTPS_ONLY='false', BASE_URL='http://testserver')
import app as module
from fastapi.testclient import TestClient


def token(client, path='/new'):
    response = client.get(path)
    return re.search('name="csrf" value="([^"]+)"', response.text)[1]


def account(email):
    client = TestClient(module.app)
    response = client.post('/register', data={'email': email, 'password': 'TestingPassword#91', 'csrf': token(client, '/register')}, follow_redirects=False)
    assert response.status_code == 303
    return client


def reset_limits():
    with module.connect() as c:
        c.execute('DELETE FROM rate_limits')


def test_complete_flow_and_security():
    a = account('first@example.com')
    reset_limits()
    assert a.post('/new', data={'category': 'Outro', 'description': 'Texto suficientemente longo', 'csrf': 'forged'}).status_code == 403
    created = a.post('/new', data={'category': 'Pedido de Pix', 'description': 'Urgente, preciso pagar um Pix agora. Pediram meu código e senha.', 'csrf': token(a)}, follow_redirects=False)
    assert created.status_code == 303
    location = created.headers['location']
    result = a.get(location)
    assert 'O que fazer agora' in result.text and 'pressão de tempo' in result.text
    assert 'sem IA' in result.text
    with module.connect() as c:
        assert c.execute('SELECT status FROM cases WHERE id=?', (int(location.rsplit('/', 1)[1]),)).fetchone()[0] == 'checklist'
    assert result.headers['x-content-type-options'] == 'nosniff'
    assert "script-src 'none'" in result.headers['content-security-policy']
    with module.connect() as c:
        user = c.execute('SELECT password FROM users WHERE email=?', ('first@example.com',)).fetchone()
        assert 'TestingPassword' not in user[0]
    reset_limits()
    b = account('second@example.com')
    assert b.get(location).status_code == 404
    assert b.post(location + '/analyze', data={'category': 'Outro', 'description': 'Este texto não é meu', 'csrf': token(b)}).status_code == 404
    assert b.post(location + '/delete', data={'csrf': token(b), 'confirm': 'yes'}).status_code == 404
    assert a.get(location).status_code == 200
    # Injection is always displayed as text, never executable markup.
    payload = '<script>alert(1)</script> Oferta de teste'
    x = a.post('/new', data={'category': 'Outro', 'description': payload, 'csrf': token(a)}, follow_redirects=False)
    assert '<script>' not in a.get(x.headers['location']).text
    assert '&lt;script&gt;' in a.get(x.headers['location']).text
    assert a.post(location + '/delete', data={'csrf': token(a)}).status_code == 403
    assert a.post(location + '/delete', data={'csrf': token(a), 'confirm': 'yes'}, follow_redirects=False).status_code == 303
    assert a.get(location).status_code == 404
    assert a.post('/logout', data={'csrf': token(a)}, follow_redirects=False).status_code == 303
    assert a.get('/dashboard', follow_redirects=False).headers['location'] == '/login'
    assert a.post('/login', data={'email': 'first@example.com', 'password': 'wrong', 'csrf': token(a, '/login')}).status_code == 401
    assert a.post('/login', data={'email': 'first@example.com', 'password': 'TestingPassword#91', 'csrf': token(a, '/login')}, follow_redirects=False).status_code == 303


def test_old_cases_and_failure_do_not_destroy_results():
    reset_limits()
    client = account('legacy@example.com')
    with module.connect() as c:
        uid = c.execute('SELECT id FROM users WHERE email=?', ('legacy@example.com',)).fetchone()[0]
        cur = c.execute("INSERT INTO cases(user_id,category,description,status,assessment,created) VALUES(?,? ,?,'pendente','',1)", (uid, 'Oferta suspeita', 'Televisão nas Casas Bahia'))
        cid = cur.lastrowid
    assert 'versão anterior' in client.get(f'/cases/{cid}').text
    expected = module.fallback('Outro', 'Teste de análise completa')
    expected['mode'] = 'ia'
    with patch.object(module, 'ai_analysis', return_value=expected):
        assert client.post(f'/cases/{cid}/analyze', data={'category': 'Outro', 'description': 'Teste de análise completa', 'csrf': token(client), 'use_ai': 'yes'}, follow_redirects=False).status_code == 303
    with patch.object(module, 'ai_analysis', side_effect=module.AnalysisUnavailable('indisponível')):
        assert client.post(f'/cases/{cid}/analyze', data={'category': 'Outro', 'description': 'Novo relato de teste', 'csrf': token(client), 'use_ai': 'yes'}).status_code == 503
    with module.connect() as c:
        row = c.execute('SELECT description,assessment FROM cases WHERE id=?', (cid,)).fetchone()
        assert row[0] == 'Teste de análise completa'
        assert json.loads(row[1])['mode'] == 'ia'


def test_urls_and_provider_failure():
    for bad in ('http://127.0.0.1/a','http://169.254.169.254/','http://[::1]/','http://localhost/','http://app.internal/','https://user:password@store.com/','javascript:alert(1)','https://store.com:8080/'):
        assert module.public_url(bad) is None
    assert module.public_url('https://www.magazineluiza.com.br/product/?token=secret#frag') == 'https://www.magazineluiza.com.br/product/'
    with patch.object(module, 'API_KEY', ''):
        result = module.produce('Outro', 'Teste sem provedor disponível', 9991, True)
        assert result['mode'] == 'checklist'
        assert any('indisponível' in line for line in result['limitations'])


def test_atomic_global_budget():
    with module.connect() as c:
        c.execute('DELETE FROM analysis_attempts')
    with patch.object(module, 'DAILY_LIMIT', 2):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(module.reserve_analysis, range(8000, 8008)))
        assert results.count('') == 2
    with module.connect() as c:
        assert c.execute('SELECT count(*) FROM analysis_attempts').fetchone()[0] == 2


def test_cookie_and_login_rate_limit():
    reset_limits()
    client = TestClient(module.app)
    for _ in range(10):
        r = client.post('/login', data={'email': 'nobody@example.com', 'password': 'wrong', 'csrf': token(client, '/login')})
        assert r.status_code == 401
    r = client.post('/login', data={'email': 'nobody@example.com', 'password': 'wrong', 'csrf': token(client, '/login')})
    assert r.status_code == 429
    cookie = client.get('/login').headers['set-cookie'].lower()
    assert 'httponly' in cookie and 'samesite=lax' in cookie


def test_provider_schema_citations_and_secret_query_removed():
    result = module.fallback('Outro','Uma oferta suficientemente detalhada')
    for key in ('mode','sources','checked_at'):
        result.pop(key)
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size):
            return json.dumps({'status':'completed','output':[{'type':'web_search_call'},{'type':'message','content':[{'type':'output_text','text':json.dumps(result),'annotations':[{'type':'url_citation','url':'https://example.org/source','title':'Fonte real'}]}]}]}).encode()
    def request_check(request, timeout):
        data = json.loads(request.data)
        assert data['store'] is False
        assert 'secret=123' not in data['input']
        assert 'email' not in data['input']
        return Response()
    with patch.object(module,'API_KEY','not-a-real-key'), patch.object(module,'urlopen',side_effect=request_check):
        answer = module.ai_analysis('Outro','Veja https://example.org/p?secret=123')
        assert answer['mode'] == 'ia' and len(answer['sources']) == 1


def test_checklist_gives_specific_actions_without_claiming_verification():
    urgent = module.fallback('Pedido de Pix', 'Um número novo pediu Pix urgente e solicitou meu código de autenticação.')
    assert urgent['risk'] == 'alto'
    assert any('Não envie senha' in a for a in urgent['actions'])
    paid = module.fallback('Pedido de Pix', 'Já paguei e agora acho que perdi dinheiro.')
    assert 'banco agora' in paid['summary']
    bill = module.fallback('Cobrança inesperada', 'Recebi um boleto de uma empresa que não reconheço.')
    assert any('credor' in a for a in bill['actions'])
    assert all('sem risco' not in r['summary'] for r in (urgent, paid, bill))
