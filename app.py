"""Tailor Pro — standalone local development server, Python 3.12+."""
import os, json, sqlite3, hashlib, secrets, hmac, time, csv, io, re
from datetime import date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from http.cookies import SimpleCookie

ROOT = Path(__file__).parent
DB = Path(os.environ.get('TAILOR_DB', ROOT / 'data/tailor.sqlite3'))
STATUSES = ['طلب جديد','بانتظار التنفيذ','قيد التفصيل والخياطة','بانتظار التجربة أو التعديل','جاهز للتسليم','تم التسليم','ملغي']
PERMISSIONS = {'admin':['read','customers','orders','measurements','employees','payments','reports','settings','users','backup'], 'reception':['read','customers','orders','measurements','payments','reports'], 'tailor':['read','status']}
SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY,name TEXT NOT NULL,phone TEXT NOT NULL,email TEXT DEFAULT '',address TEXT DEFAULT '',notes TEXT DEFAULT '',created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS employees(id INTEGER PRIMARY KEY,name TEXT NOT NULL,phone TEXT DEFAULT '',specialty TEXT DEFAULT '',active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS roles_permissions(role TEXT PRIMARY KEY,permissions TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL REFERENCES roles_permissions(role),employee_id INTEGER REFERENCES employees(id));
CREATE TABLE IF NOT EXISTS measurements(id INTEGER PRIMARY KEY,customer_id INTEGER NOT NULL REFERENCES customers(id),values_json TEXT NOT NULL,notes TEXT DEFAULT '',created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,customer_id INTEGER NOT NULL REFERENCES customers(id),employee_id INTEGER REFERENCES employees(id),measurement_id INTEGER REFERENCES measurements(id),status TEXT NOT NULL,received TEXT NOT NULL,due TEXT NOT NULL,total INTEGER NOT NULL CHECK(total>=0),discount INTEGER NOT NULL DEFAULT 0 CHECK(discount>=0),tax_bps INTEGER NOT NULL DEFAULT 0,notes TEXT DEFAULT '',CHECK(discount<=total));
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL REFERENCES orders(id),kind TEXT NOT NULL,quantity INTEGER NOT NULL CHECK(quantity>0),fabric TEXT DEFAULT '',color TEXT DEFAULT '',design TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL REFERENCES orders(id),amount INTEGER NOT NULL CHECK(amount>0),method TEXT NOT NULL,created TEXT NOT NULL,request_key TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS invoices(id INTEGER PRIMARY KEY,order_id INTEGER UNIQUE NOT NULL REFERENCES orders(id),created TEXT NOT NULL,snapshot TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY,order_id INTEGER REFERENCES orders(id),message TEXT NOT NULL,created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS order_status_history(id INTEGER PRIMARY KEY,order_id INTEGER NOT NULL REFERENCES orders(id),status TEXT NOT NULL,user_id INTEGER NOT NULL REFERENCES users(id),created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),action TEXT NOT NULL,entity TEXT NOT NULL,entity_id INTEGER,created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),csrf TEXT NOT NULL,expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS login_attempts(address TEXT PRIMARY KEY,failures INTEGER NOT NULL,blocked_until REAL NOT NULL);
'''

def now(): return datetime.now(ZoneInfo('Asia/Riyadh')).isoformat(timespec='seconds')
def business_today(): return datetime.now(ZoneInfo('Asia/Riyadh')).date()
def connect():
    c=sqlite3.connect(DB, timeout=20); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def password_hash(value):
    salt=secrets.token_hex(16)
    return salt+':'+hashlib.pbkdf2_hmac('sha256', value.encode(),salt.encode(),310000).hex()

def verify(value, stored):
    salt, expected=stored.split(':')
    return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',value.encode(),salt.encode(),310000).hex(),expected)

def money(v):
    from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
    try:
        d=Decimal(str(v))
        if not d.is_finite() or d<0 or d>Decimal('10000000'): raise ValueError()
        return int((d*100).quantize(Decimal('1'),rounding=ROUND_HALF_UP))
    except (InvalidOperation,ValueError,TypeError): raise ValueError('أدخل مبلغاً صحيحاً غير سالب')

def integer(v, minimum=1, maximum=1000000):
    try:
        n=int(str(v))
        if not minimum<=n<=maximum: raise ValueError()
        return n
    except (ValueError,TypeError): raise ValueError('قيمة رقمية غير صالحة')

def text(v, required=False, limit=2000):
    if not isinstance(v,str) or len(v)>limit or (required and not v.strip()): raise ValueError('تحقق من الحقول المطلوبة وطول النص')
    return v.strip()

def phone(v):
    v=text(v,True,24)
    if not re.fullmatch(r'\+?[0-9٠-٩ ()-]{7,24}',v): raise ValueError('رقم الجوال غير صالح')
    return v

def audit(c,u,action,entity,eid=None): c.execute('INSERT INTO audit_logs(user_id,action,entity,entity_id,created) VALUES(?,?,?,?,?)',(u['id'],action,entity,eid,now()))
def net(o):
    base=o['total']-o['discount']; return base+(base*o['tax_bps']+5000)//10000

def init_db():
    DB.parent.mkdir(parents=True,exist_ok=True)
    with connect() as c:
        c.executescript(SCHEMA)
        for role,perms in PERMISSIONS.items(): c.execute('INSERT OR IGNORE INTO roles_permissions VALUES(?,?)',(role,json.dumps(perms)))
        for k,v in {'shop':'دار الإتقان للخياطة','address':'الرياض، المملكة العربية السعودية','phone':'','tax_bps':'0','tax_number':''}.items(): c.execute('INSERT OR IGNORE INTO settings VALUES(?,?)',(k,v))
        if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            pwd=os.environ.get('TAILOR_ADMIN_PASSWORD') or secrets.token_urlsafe(15)
            c.execute('INSERT INTO users(username,name,password,role) VALUES(?,?,?,?)',('admin','مدير النظام',password_hash(pwd),'admin'))
            if not os.environ.get('TAILOR_ADMIN_PASSWORD'):
                p=DB.parent/'initial-password.txt'; p.write_text(pwd+'\n'); p.chmod(0o600)
                print(f'Initial admin password saved locally in {p}. It is not included in the project archive.',flush=True)
        if os.environ.get('TAILOR_SEED')=='1' and not c.execute('SELECT 1 FROM customers').fetchone():
            for name,p in [('أحمد العتيبي','0501112233'),('خالد القحطاني','0552223344'),('محمد الدوسري','0533334455'),('عبدالله السبيعي','0544445566')]: c.execute('INSERT INTO customers(name,phone,created) VALUES(?,?,?)',(name,p,now()))
            for name in ['عمر عبدالله','يوسف أحمد']: c.execute('INSERT INTO employees(name,specialty) VALUES(?,?)',(name,'تفصيل الثياب الرجالية'))
            for i in range(1,5):
                m=c.execute('INSERT INTO measurements(customer_id,values_json,created) VALUES(?,?,?)',(i,json.dumps({'طول الثوب':150,'عرض الكتف':45,'طول الكم':60,'محيط الصدر':100,'محيط الخصر':94,'محيط الرقبة':40}),now())).lastrowid
                oid=c.execute('INSERT INTO orders(customer_id,employee_id,measurement_id,status,received,due,total) VALUES(?,?,?,?,?,?,?)',(i,1+(i%2),m,STATUSES[[0,2,4,5][i-1]],(business_today()-timedelta(days=4)).isoformat(),(business_today()+timedelta(days=i-2)).isoformat(),i*35000)).lastrowid
                c.execute('INSERT INTO order_items(order_id,kind,quantity,fabric,color) VALUES(?,?,?,?,?)',(oid,'ثوب رجالي',i,'قطن ياباني','أبيض'))
                c.execute('INSERT INTO payments(order_id,amount,method,created,request_key) VALUES(?,?,?,?,?)',(oid,i*(35000 if i==4 else 15000),'نقدي',now(),secrets.token_hex(16)))
                c.execute('INSERT INTO order_status_history(order_id,status,user_id,created) VALUES(?,?,1,?)',(oid,STATUSES[[0,2,4,5][i-1]],now()))
    DB.chmod(0o600)

class Handler(BaseHTTPRequestHandler):
    def log_message(self,format,*args): pass
    def send(self,status,data,ctype='application/json; charset=utf-8',headers=None):
        body=json.dumps(data,ensure_ascii=False).encode() if ctype.startswith('application/json') else data
        self.send_response(status)
        for k,v in {'Content-Type':ctype,'Content-Length':str(len(body)),'X-Content-Type-Options':'nosniff','Cache-Control':'no-store','Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",**(headers or {})}.items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(body)
    def body(self):
        n=int(self.headers.get('Content-Length','0'))
        if not 0<n<=100000: raise ValueError('حجم الطلب غير صالح')
        d=json.loads(self.rfile.read(n))
        if not isinstance(d,dict): raise ValueError('صيغة البيانات غير صالحة')
        return d
    def user(self,c):
        cookie=SimpleCookie(); cookie.load(self.headers.get('Cookie',''))
        token=cookie.get('tailor_session')
        if not token: return None
        return c.execute('SELECT u.id,u.username,u.name,u.role,u.employee_id,s.csrf,r.permissions FROM sessions s JOIN users u ON u.id=s.user_id JOIN roles_permissions r ON r.role=u.role WHERE s.token=? AND s.expires>?',(hashlib.sha256(token.value.encode()).hexdigest(),time.time())).fetchone()
    def allowed(self,u,p):
        if p not in json.loads(u['permissions']): raise PermissionError('لا تملك صلاحية تنفيذ هذه العملية')
    def visible_order(self,c,u,oid):
        o=c.execute('SELECT * FROM orders WHERE id=?',(oid,)).fetchone()
        if not o: raise ValueError('الطلب غير موجود')
        if u['role']=='tailor' and (not u['employee_id'] or o['employee_id']!=u['employee_id']): raise PermissionError('هذا الطلب غير مسند إليك')
        return o
    def do_GET(self): self.handle_request('GET')
    def do_POST(self): self.handle_request('POST')
    def do_PUT(self): self.handle_request('PUT')
    def handle_request(self,method):
        path=urlparse(self.path).path
        try:
            if not path.startswith('/api/'):
                if method!='GET': return self.send(405,{'error':'طريقة غير مدعومة'})
                files={'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
                if path not in files: return self.send(404,{'error':'غير موجود'})
                f,ct=files[path]; return self.send(200,(ROOT/'static'/f).read_bytes(),ct)
            with connect() as c:
                if path=='/api/login' and method=='POST':
                    d=self.body(); address=self.client_address[0]; a=c.execute('SELECT * FROM login_attempts WHERE address=?',(address,)).fetchone()
                    if a and a['blocked_until']>time.time(): return self.send(429,{'error':'محاولات كثيرة، حاول بعد ٥ دقائق'})
                    u=c.execute('SELECT * FROM users WHERE username=?',(text(d.get('username',''),True,100),)).fetchone()
                    if not u or not verify(text(d.get('password',''),True,256),u['password']):
                        failures=(a['failures'] if a else 0)+1
                        c.execute('INSERT OR REPLACE INTO login_attempts VALUES(?,?,?)',(address,failures,time.time()+300 if failures>=8 else 0)); c.commit()
                        return self.send(401,{'error':'اسم المستخدم أو كلمة المرور غير صحيحة'})
                    c.execute('DELETE FROM login_attempts WHERE address=?',(address,))
                    token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
                    c.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
                    c.execute('INSERT INTO sessions VALUES(?,?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],csrf,time.time()+28800)); audit(c,u,'تسجيل دخول','users',u['id']); c.commit()
                    return self.send(200,{'ok':True},headers={'Set-Cookie':f'tailor_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'+ ('; Secure' if os.environ.get('TAILOR_SECURE_COOKIE')=='1' else '')})
                u=self.user(c)
                if not u: return self.send(401,{'error':'يرجى تسجيل الدخول'})
                if method!='GET' and not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),u['csrf']): return self.send(403,{'error':'رمز حماية الجلسة غير صالح'})
                if path=='/api/me' and method=='GET': return self.send(200,dict(u))
                if path=='/api/logout' and method=='POST':
                    c.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],)); c.commit(); return self.send(200,{'ok':True},headers={'Set-Cookie':'tailor_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})
                if path=='/api/data' and method=='GET': return self.send(200,self.data(c,u))
                if path=='/api/backup' and method=='GET':
                    self.allowed(u,'backup'); audit(c,u,'تنزيل نسخة احتياطية','backup'); c.commit()
                    dest=sqlite3.connect(':memory:'); c.backup(dest)
                    dest.execute('DELETE FROM sessions'); dest.execute('DELETE FROM login_attempts'); dest.commit()
                    raw=dest.serialize(); dest.close()
                    return self.send(200,raw,'application/vnd.sqlite3',{'Content-Disposition':'attachment; filename=tailor-backup.sqlite3'})
                if path=='/api/export' and method=='GET':
                    self.allowed(u,'reports'); data=self.data(c,u); out=io.StringIO(); w=csv.writer(out); w.writerow(['رقم الطلب','العميل','الحالة','التسليم','الصافي','المدفوع','المتبقي'])
                    def safe(v):
                        s=str(v); return "'"+s if s.startswith(('=','+','-','@','\t','\r')) else s
                    for o in data['orders']: w.writerow([o['id'],safe(o['customer']),o['status'],o['due'],o['net']/100,o['paid']/100,o['remaining']/100])
                    return self.send(200,('\ufeff'+out.getvalue()).encode(),'text/csv; charset=utf-8',{'Content-Disposition':'attachment; filename=tailor-report.csv'})
                if method not in ('POST','PUT'): return self.send(404,{'error':'غير موجود'})
                d=self.body(); parts=path.strip('/').split('/'); entity=parts[1] if len(parts)>1 else ''; eid=integer(parts[2]) if len(parts)>2 else None
                if entity=='customers':
                    self.allowed(u,'customers'); vals=(text(d.get('name',''),True,150),phone(d.get('phone','')),text(d.get('email',''),False,200),text(d.get('address','')),text(d.get('notes','')))
                    if method=='PUT':
                        if not c.execute('UPDATE customers SET name=?,phone=?,email=?,address=?,notes=? WHERE id=?',(*vals,eid)).rowcount: raise ValueError('العميل غير موجود')
                    else: eid=c.execute('INSERT INTO customers(name,phone,email,address,notes,created) VALUES(?,?,?,?,?,?)',(*vals,now())).lastrowid
                elif entity=='employees':
                    self.allowed(u,'employees'); vals=(text(d.get('name',''),True,150),text(d.get('phone',''),False,24),text(d.get('specialty',''),False,200),integer(d.get('active',1),0,1))
                    if method=='PUT':
                        if not c.execute('UPDATE employees SET name=?,phone=?,specialty=?,active=? WHERE id=?',(*vals,eid)).rowcount: raise ValueError('الموظف غير موجود')
                    else: eid=c.execute('INSERT INTO employees(name,phone,specialty,active) VALUES(?,?,?,?)',vals).lastrowid
                elif entity=='measurements':
                    self.allowed(u,'measurements'); customer=integer(d.get('customer_id')); values=d.get('values',{})
                    if not isinstance(values,dict) or not values or len(values)>30: raise ValueError('أدخل المقاسات')
                    for k,v in values.items():
                        text(k,True,100)
                        if not isinstance(v,(int,float)) or not 0<float(v)<=400: raise ValueError('المقاسات يجب أن تكون بين ٠ و٤٠٠ سم')
                    eid=c.execute('INSERT INTO measurements(customer_id,values_json,notes,created) VALUES(?,?,?,?)',(customer,json.dumps(values,ensure_ascii=False),text(d.get('notes','')),now())).lastrowid
                elif entity=='orders' and len(parts)>3 and parts[3]=='status':
                    if 'orders' not in json.loads(u['permissions']): self.allowed(u,'status')
                    o=self.visible_order(c,u,eid); status=text(d.get('status',''),True)
                    if status not in STATUSES: raise ValueError('حالة غير صالحة')
                    if u['role']=='tailor' and status not in STATUSES[2:5]: raise PermissionError('الخياط يستطيع تحديث مراحل التنفيذ فقط')
                    if status=='تم التسليم' and net(o)>c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE order_id=?',(eid,)).fetchone()[0]: raise ValueError('يجب تحصيل الرصيد المستحق قبل التسليم')
                    if status=='ملغي' and c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE order_id=?',(eid,)).fetchone()[0]>0: raise ValueError('لا يمكن إلغاء طلب له دفعات؛ يلزم مسار استرداد محاسبي منفصل')
                    c.execute('UPDATE orders SET status=? WHERE id=?',(status,eid)); c.execute('INSERT INTO order_status_history(order_id,status,user_id,created) VALUES(?,?,?,?)',(eid,status,u['id'],now()))
                elif entity=='orders' and method=='POST':
                    self.allowed(u,'orders'); customer=integer(d.get('customer_id')); employee=integer(d['employee_id']) if d.get('employee_id') else None
                    if employee and not c.execute('SELECT 1 FROM employees WHERE id=? AND active=1',(employee,)).fetchone(): raise ValueError('الخياط غير متاح')
                    mid=integer(d['measurement_id']) if d.get('measurement_id') else None
                    if mid and not c.execute('SELECT 1 FROM measurements WHERE id=? AND customer_id=?',(mid,customer)).fetchone(): raise ValueError('المقاسات لا تخص العميل')
                    total=money(d.get('total',0)); discount=money(d.get('discount',0)); received=business_today().isoformat(); due=date.fromisoformat(d.get('due','')).isoformat()
                    if due<received: raise ValueError('تاريخ التسليم يجب ألا يسبق تاريخ الطلب')
                    if discount>total: raise ValueError('الخصم أكبر من قيمة الطلب')
                    tax=int(c.execute("SELECT value FROM settings WHERE key='tax_bps'").fetchone()[0])
                    eid=c.execute('INSERT INTO orders(customer_id,employee_id,measurement_id,status,received,due,total,discount,tax_bps,notes) VALUES(?,?,?,?,?,?,?,?,?,?)',(customer,employee,mid,STATUSES[0],received,due,total,discount,tax,text(d.get('notes','')))).lastrowid
                    items=d.get('items',[])
                    if not isinstance(items,list) or not 1<=len(items)<=50: raise ValueError('أضف قطعة واحدة على الأقل')
                    for it in items: c.execute('INSERT INTO order_items(order_id,kind,quantity,fabric,color,design) VALUES(?,?,?,?,?,?)',(eid,text(it.get('kind',''),True,100),integer(it.get('quantity',1),1,1000),text(it.get('fabric','')),text(it.get('color','')),text(it.get('design',''))))
                    c.execute('INSERT INTO order_status_history(order_id,status,user_id,created) VALUES(?,?,?,?)',(eid,STATUSES[0],u['id'],now()))
                elif entity=='orders' and method=='PUT':
                    self.allowed(u,'orders'); self.visible_order(c,u,eid); employee=integer(d['employee_id']) if d.get('employee_id') else None
                    if employee and not c.execute('SELECT 1 FROM employees WHERE id=? AND active=1',(employee,)).fetchone(): raise ValueError('الخياط غير متاح')
                    due=date.fromisoformat(d.get('due','')).isoformat()
                    c.execute('UPDATE orders SET employee_id=?,due=?,notes=? WHERE id=?',(employee,due,text(d.get('notes','')),eid))
                elif entity=='payments':
                    self.allowed(u,'payments'); c.execute('BEGIN IMMEDIATE'); oid=integer(d.get('order_id')); o=self.visible_order(c,u,oid)
                    key=text(d.get('request_key',''),True,120); previous=c.execute('SELECT * FROM payments WHERE request_key=?',(key,)).fetchone(); amount=money(d.get('amount',0)); method_pay=text(d.get('method',''),True)
                    if previous:
                        if previous['order_id']!=oid or previous['amount']!=amount or previous['method']!=method_pay: raise ValueError('معرف العملية مستخدم لدفعة مختلفة')
                        return self.send(200,{'id':previous['id'],'ok':True})
                    paid=c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE order_id=?',(oid,)).fetchone()[0]
                    if o['status']=='ملغي': raise ValueError('لا يمكن تحصيل دفعة لطلب ملغي')
                    if amount<=0 or amount>net(o)-paid: raise ValueError('الدفعة يجب أن تكون موجبة ولا تتجاوز المتبقي')
                    if method_pay not in ['نقدي','بطاقة','تحويل بنكي']: raise ValueError('طريقة دفع غير صالحة')
                    eid=c.execute('INSERT INTO payments(order_id,amount,method,created,request_key) VALUES(?,?,?,?,?)',(oid,amount,method_pay,now(),key)).lastrowid
                elif entity=='invoices':
                    self.allowed(u,'payments'); oid=integer(d.get('order_id')); self.visible_order(c,u,oid)
                    old=c.execute('SELECT id FROM invoices WHERE order_id=?',(oid,)).fetchone()
                    if old: return self.send(200,{'ok':True,'id':old['id']})
                    full=self.data(c,u); order=next(o for o in full['orders'] if o['id']==oid); customer=next(x for x in full['customers'] if x['id']==order['customer_id'])
                    snapshot={'order':order,'customer':customer,'settings':full['settings'],'issued':now()}
                    eid=c.execute('INSERT INTO invoices(order_id,created,snapshot) VALUES(?,?,?)',(oid,now(),json.dumps(snapshot,ensure_ascii=False))).lastrowid
                elif entity=='settings':
                    self.allowed(u,'settings')
                    for k in ['shop','address','phone','tax_number']:
                        if k in d: c.execute('UPDATE settings SET value=? WHERE key=?',(text(d[k],k=='shop'),k))
                    tax=money(d.get('tax_percent',0))
                    if tax>10000: raise ValueError('الضريبة يجب أن تكون بين ٠ و١٠٠٪')
                    c.execute("UPDATE settings SET value=? WHERE key='tax_bps'",(str(tax),))
                elif entity=='users':
                    self.allowed(u,'users'); role=d.get('role')
                    if role not in PERMISSIONS: raise ValueError('دور غير صالح')
                    pwd=text(d.get('password',''),True,256)
                    if len(pwd)<12: raise ValueError('كلمة المرور يجب أن تتكون من ١٢ حرفاً على الأقل')
                    employee=integer(d['employee_id']) if d.get('employee_id') else None
                    if role=='tailor' and not employee: raise ValueError('اربط حساب الخياط بموظف')
                    eid=c.execute('INSERT INTO users(username,name,password,role,employee_id) VALUES(?,?,?,?,?)',(text(d.get('username',''),True,100),text(d.get('name',''),True,150),password_hash(pwd),role,employee)).lastrowid
                elif entity=='permissions':
                    self.allowed(u,'users'); role=d.get('role'); perms=d.get('permissions')
                    if role not in ['reception','tailor'] or not isinstance(perms,list) or any(p not in PERMISSIONS['admin']+['status'] for p in perms): raise ValueError('صلاحيات غير صالحة')
                    if role=='tailor' and any(p not in ['read','status'] for p in perms): raise ValueError('حساب الخياط لا يحصل على صلاحيات مالية أو إدارية')
                    c.execute('UPDATE roles_permissions SET permissions=? WHERE role=?',(json.dumps(list(set(perms+['read']))),role))
                elif entity=='password':
                    row=c.execute('SELECT password FROM users WHERE id=?',(u['id'],)).fetchone()
                    if not verify(text(d.get('current',''),True,256),row['password']): raise ValueError('كلمة المرور الحالية غير صحيحة')
                    pwd=text(d.get('password',''),True,256)
                    if len(pwd)<12: raise ValueError('استخدم ١٢ حرفاً على الأقل')
                    c.execute('UPDATE users SET password=? WHERE id=?',(password_hash(pwd),u['id'])); c.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
                else: return self.send(404,{'error':'غير موجود'})
                audit(c,u,'تحديث' if method=='PUT' else 'إضافة',entity,eid); c.commit(); return self.send(200,{'ok':True,'id':eid})
        except PermissionError as e: self.send(403,{'error':str(e)})
        except sqlite3.IntegrityError: self.send(400,{'error':'تحقق من البيانات المرتبطة وعدم تكرار اسم المستخدم'})
        except (ValueError,TypeError,KeyError,AttributeError,OverflowError) as e: self.send(400,{'error':str(e) or 'بيانات غير صالحة'})
        except Exception:
            import traceback; traceback.print_exc(); self.send(500,{'error':'حدث خطأ داخلي، راجع سجل الخادم'})
    def data(self,c,u):
        def rows(q,args=()): return [dict(r) for r in c.execute(q,args)]
        tailor=u['role']=='tailor'; financial='payments' in json.loads(u['permissions']) or 'reports' in json.loads(u['permissions'])
        orders=rows('SELECT o.*,c.name customer,c.phone,e.name employee FROM orders o JOIN customers c ON c.id=o.customer_id LEFT JOIN employees e ON e.id=o.employee_id'+(' WHERE o.employee_id=?' if tailor else '')+' ORDER BY o.id DESC',(u['employee_id'],) if tailor else ())
        ids={o['id'] for o in orders}; cust={o['customer_id'] for o in orders}; mids={o['measurement_id'] for o in orders}
        payments=rows('SELECT * FROM payments ORDER BY id DESC') if financial and not tailor else []
        for o in orders:
            if financial and not tailor:
                o['net']=net(o); o['paid']=sum(p['amount'] for p in payments if p['order_id']==o['id']); o['remaining']=o['net']-o['paid']
            else:
                for k in ['total','discount','tax_bps']: o.pop(k,None)
        customers=rows('SELECT * FROM customers ORDER BY id DESC')
        if tailor: customers=[{k:v for k,v in r.items() if k in ['id','name','phone']} for r in customers if r['id'] in cust]
        measurements=rows('SELECT * FROM measurements ORDER BY id DESC')
        if tailor: measurements=[m for m in measurements if m['id'] in mids]
        alerts=[{'order_id':o['id'],'message':('متأخر عن التسليم' if o['due']<business_today().isoformat() else 'موعد التسليم اليوم' if o['due']==business_today().isoformat() else 'اقترب موعد التسليم')} for o in orders if o['status'] not in STATUSES[5:] and o['due']<=(business_today()+timedelta(days=2)).isoformat()]
        settings=dict(c.execute('SELECT key,value FROM settings'))
        return {'orders':orders,'customers':customers,'employees':rows('SELECT * FROM employees') if not tailor else rows('SELECT * FROM employees WHERE id=?',(u['employee_id'],)), 'measurements':measurements,'items':[i for i in rows('SELECT * FROM order_items') if i['order_id'] in ids], 'payments':payments,'invoices':rows('SELECT * FROM invoices') if financial and not tailor else [],'history':[h for h in rows('SELECT h.*,u.name user FROM order_status_history h JOIN users u ON u.id=h.user_id ORDER BY h.id DESC') if h['order_id'] in ids],'notifications':alerts,'settings':settings,'statuses':STATUSES,'users':rows('SELECT id,username,name,role,employee_id FROM users') if u['role']=='admin' else [],'roles':rows('SELECT * FROM roles_permissions') if u['role']=='admin' else [],'audit':rows('SELECT a.*,u.name user FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 100') if u['role']=='admin' else []}

if __name__=='__main__':
    init_db(); host=os.environ.get('TAILOR_HOST','127.0.0.1'); port=int(os.environ.get('PORT','8000'))
    print(f'Tailor Pro running on {host}:{port}',flush=True)
    ThreadingHTTPServer((host,port),Handler).serve_forever()
