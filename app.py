import os, sqlite3, secrets, hashlib, hmac, time, html
from contextlib import contextmanager
from urllib.parse import quote
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

BASE=os.getenv("BASE_URL","http://localhost:8000").rstrip("/")
DB=os.getenv("DB_PATH","/data/confere.sqlite3")
SECRET=os.getenv("SECRET_KEY","")
if len(SECRET)<32: raise RuntimeError("Configure SECRET_KEY com no minimo 32 caracteres")
app=FastAPI(title="CONFERE",docs_url=None,redoc_url=None)
app.add_middleware(SessionMiddleware,secret_key=SECRET,https_only=os.getenv("SESSION_HTTPS_ONLY","true").lower()=="true",same_site="lax")
os.makedirs(os.path.dirname(DB) or ".",exist_ok=True)
def connect():
 c=sqlite3.connect(DB,timeout=20);c.row_factory=sqlite3.Row;c.execute("PRAGMA journal_mode=WAL");return c
def init():
 with connect() as c:
  c.executescript("""CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,created INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,category TEXT NOT NULL,description TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pendente',assessment TEXT NOT NULL DEFAULT '',created INTEGER NOT NULL,FOREIGN KEY(user_id) REFERENCES users(id));
  CREATE INDEX IF NOT EXISTS idx_cases_user ON cases(user_id);""")
init()
def esc(s):return html.escape(str(s),quote=True)
def digest(p):
 salt=secrets.token_bytes(16);return salt.hex()+":"+hashlib.pbkdf2_hmac("sha256",p.encode(),salt,250000).hex()
def verify(p,stored):
 try:
  salt,key=stored.split(":");return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(salt),250000),bytes.fromhex(key))
 except (ValueError,TypeError):return False
def current(req):
 uid=req.session.get("uid")
 if not uid:return None
 with connect() as c:return c.execute("SELECT id,email FROM users WHERE id=?",(uid,)).fetchone()
def csrf(req):
 if "csrf" not in req.session:req.session["csrf"]=secrets.token_urlsafe(24)
 return req.session["csrf"]
def check(req,token):return bool(token and hmac.compare_digest(str(token),str(req.session.get("csrf",""))))
def page(req,title,body):
 user=current(req);nav='<a href="/">Início</a> '+('<a href="/dashboard">Minhas consultas</a> <form method="post" action="/logout" class="inline"><input type="hidden" name="csrf" value="'+esc(csrf(req))+'"><button>Sair</button></form>' if user else '<a href="/login">Entrar</a> <a href="/register">Criar conta</a>')
 return HTMLResponse("""<!doctype html><html lang="pt-br"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>"""+esc(title)+""" | CONFERE</title><style>:root{font-family:Inter,system-ui,sans-serif;color:#112c37;background:#f5f8fa}*{box-sizing:border-box}body{margin:0}header{background:#fff;border-bottom:1px solid #e0e9ee;padding:19px max(5vw,16px);display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap}header strong{color:#087b78;font-size:22px}nav{display:flex;gap:16px;align-items:center;flex-wrap:wrap}a{color:#087b78;text-decoration:none}main{max-width:920px;margin:44px auto;padding:0 20px}h1{font-size:clamp(32px,5vw,53px);line-height:1.13}h2{margin-top:0}.hero{padding:36px 0 24px}.hero p{font-size:20px;color:#4a6874;max-width:650px}.card{background:white;padding:28px;border:1px solid #e2ebef;border-radius:18px;box-shadow:0 10px 36px #1233 4;margin:18px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}.btn,button{background:#087b78;color:white;border:0;border-radius:10px;padding:12px 18px;cursor:pointer;font-weight:650;font-size:15px}.btn{display:inline-block}input,select,textarea{display:block;width:100%;padding:13px;border:1px solid #b9cbd3;border-radius:9px;margin:7px 0 17px;font:inherit}textarea{min-height:170px}label{font-weight:650}.muted{color:#526c77}.small{font-size:13px}.inline{display:inline}.inline button{padding:7px 12px}.alert{padding:14px;background:#fff3e3;border-radius:9px}.tag{background:#e5f3f1;padding:5px 9px;border-radius:6px;font-size:13px}.listitem{padding:17px 0;border-top:1px solid #e5ebef}footer{margin:65px auto 20px;max-width:900px;color:#678;font-size:13px;padding:0 20px}</style></head><body><header><strong>✓ CONFERE</strong><nav>"""+nav+"""</nav></header><main>"""+body+"""</main><footer>CONFERE — Uma segunda opinião preventiva. Não garantimos a legitimidade de compras ou transferências. Nunca informe senhas, códigos bancários ou documentos completos.</footer></body></html>""")
def redirect(where):return RedirectResponse(where,status_code=303)
def formtoken(req):return '<input type="hidden" name="csrf" value="'+esc(csrf(req))+'">'
@app.get("/",response_class=HTMLResponse)
def home(req:Request):
 return page(req,"Confira antes de pagar",'<section class="hero"><span class="tag">Segurança para decisões do dia a dia</span><h1>Antes de pagar,<br> confira.</h1><p>Recebeu uma oferta estranha, um pedido urgente de Pix ou uma cobrança inesperada? Registre a situação e solicite uma segunda opinião preventiva.</p><a class="btn" href="/register">Começar gratuitamente</a></section><section class="grid"><div class="card"><h2>1. Conte o que aconteceu</h2><p>Descreva a situação sem divulgar dados sensíveis.</p></div><div class="card"><h2>2. Consulte o histórico</h2><p>Acompanhe suas consultas em um só lugar.</p></div><div class="card"><h2>3. Decida com cautela</h2><p>Receba orientações, sem falsas garantias de segurança.</p></div></section><div class="card alert">Acesso de demonstração sem cobrança. Assinaturas e análise profissional dependem de ativação posterior.</div>')
@app.get("/health")
def health():return {"status":"ok"}
@app.get("/register")
def register(req:Request):return page(req,"Criar conta",'<div class="card"><h2>Crie sua conta</h2><form method="post">'+formtoken(req)+'<label>E-mail<input type="email" name="email" required maxlength="254"></label><label>Senha (mínimo 10 caracteres)<input type="password" name="password" minlength="10" required></label><button>Criar conta</button></form></div>')
@app.post("/register")
def register_post(req:Request,email:str=Form(...),password:str=Form(...),csrf:str=Form(...)):
 if not check(req,csrf):return HTMLResponse("Solicitação inválida",status_code=403)
 email=email.strip().lower()
 if len(password)<10 or len(email)>254:return HTMLResponse("Dados inválidos",status_code=422)
 try:
  with connect() as c:
   cur=c.execute("INSERT INTO users(email,password,created) VALUES(?,?,?)",(email,digest(password),int(time.time())))
   req.session.clear();req.session["uid"]=cur.lastrowid
 except sqlite3.IntegrityError:return HTMLResponse("Este e-mail já está cadastrado.",status_code=409)
 return redirect("/dashboard")
@app.get("/login")
def login(req:Request):return page(req,"Entrar",'<div class="card"><h2>Entrar</h2><form method="post">'+formtoken(req)+'<label>E-mail<input type="email" name="email" required></label><label>Senha<input type="password" name="password" required></label><button>Entrar</button></form></div>')
@app.post("/login")
def login_post(req:Request,email:str=Form(...),password:str=Form(...),csrf:str=Form(...)):
 if not check(req,csrf):return HTMLResponse("Solicitação inválida",status_code=403)
 with connect() as c:user=c.execute("SELECT * FROM users WHERE email=?",(email.strip().lower(),)).fetchone()
 if not user or not verify(password,user["password"]):return HTMLResponse("Credenciais inválidas",status_code=401)
 req.session.clear();req.session["uid"]=user["id"];return redirect("/dashboard")
@app.post("/logout")
def logout(req:Request,csrf:str=Form(...)):
 if not check(req,csrf):return HTMLResponse("Solicitação inválida",status_code=403)
 req.session.clear();return redirect("/")
@app.get("/dashboard")
def dashboard(req:Request):
 user=current(req)
 if not user:return redirect("/login")
 with connect() as c:rows=c.execute("SELECT * FROM cases WHERE user_id=? ORDER BY created DESC",(user["id"],)).fetchall()
 items="".join('<div class="listitem"><strong>#'+str(r["id"])+' — '+esc(r["category"])+'</strong> <span class="tag">'+esc(r["status"])+'</span><p>'+esc(r["description"])+'</p>'+(('<p><b>Orientação:</b> '+esc(r["assessment"])+'</p>') if r["assessment"] else "")+'</div>' for r in rows) or '<p class="muted">Nenhuma consulta ainda.</p>'
 return page(req,"Painel",'<h1>Minhas consultas</h1><p class="muted">Olá, '+esc(user["email"])+'</p><a class="btn" href="/new">Nova consulta</a><div class="card">'+items+'</div>')
@app.get("/new")
def new(req:Request):
 if not current(req):return redirect("/login")
 return page(req,"Nova consulta",'<div class="card"><h2>Nova consulta</h2><p class="alert">Não envie senhas, documentos, números de cartões, códigos de autenticação ou informações bancárias completas.</p><form method="post">'+formtoken(req)+'<label>Tipo de situação<select name="category"><option>Oferta suspeita</option><option>Pedido de Pix</option><option>Cobrança inesperada</option><option>Outro</option></select></label><label>Descreva a situação<textarea name="description" minlength="20" maxlength="3000" required></textarea></label><button>Enviar para avaliação</button></form></div>')
@app.post("/new")
def new_post(req:Request,category:str=Form(...),description:str=Form(...),csrf:str=Form(...)):
 user=current(req)
 if not user:return redirect("/login")
 if not check(req,csrf):return HTMLResponse("Solicitação inválida",status_code=403)
 if category not in ("Oferta suspeita","Pedido de Pix","Cobrança inesperada","Outro") or not 20<=len(description)<=3000:return HTMLResponse("Dados inválidos",status_code=422)
 with connect() as c:
  n=c.execute("SELECT count(*) FROM cases WHERE user_id=? AND created>=?",(user["id"],int(time.time())-30*86400)).fetchone()[0]
  if n>=5:return HTMLResponse("Limite de 5 consultas a cada 30 dias atingido.",status_code=429)
  c.execute("INSERT INTO cases(user_id,category,description,created) VALUES(?,?,?,?)",(user["id"],category,description,int(time.time())))
 return redirect("/dashboard")
