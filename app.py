from flask import Flask, request, jsonify
from flask_cors import CORS
import gspread
from google.oauth2.service_account import Credentials
import os, json, hashlib, base64, uuid
from datetime import datetime, timedelta
import pytz

app = Flask(__name__)
CORS(app)

TZ = pytz.timezone('Asia/Taipei')

def now():
    return datetime.now(TZ).strftime('%Y/%m/%d %H:%M:%S')

def hash_pwd(s):
    return base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()

def get_gc():
    creds_json = os.environ.get('GOOGLE_CREDS')
    creds_dict = json.loads(creds_json)
    scopes = ['https://spreadsheets.google.com/feeds', 'https://www.googleapis.com/auth/drive']
    creds = Credentials.from_service_account_info(creds_dict, scopes=scopes)
    return gspread.authorize(creds)

def get_sheet(name):
    gc = get_gc()
    sheet_id = os.environ.get('SHEET_ID')
    ss = gc.open_by_key(sheet_id)
    return ss.worksheet(name)

def rows(sheet):
    data = sheet.get_all_records()
    return data

def find_row_index(sheet, col_name, value):
    """Returns 1-based row index (including header), or None"""
    records = sheet.get_all_values()
    headers = records[0]
    col_idx = headers.index(col_name)
    for i, row in enumerate(records[1:], start=2):
        if row[col_idx] == value:
            return i
    return None

# ── 認證 ──────────────────────────────────────

@app.route('/api/admin-login', methods=['POST'])
def admin_login():
    try:
        d = request.json
        email = d.get('email', '').strip()
        password = d.get('password', '')
        sh = get_sheet('管理員帳號')
        admins = rows(sh)
        admin = next((a for a in admins if a.get('Email') == email), None)
        if not admin:
            return jsonify({'ok': False, 'error': '帳號不存在'})
        if admin.get('密碼Hash') != hash_pwd(password):
            return jsonify({'ok': False, 'error': '密碼不正確'})
        token = str(uuid.uuid4())
        # Save session
        sess_sh = get_sheet('登入狀態')
        expires = (datetime.now(TZ) + timedelta(hours=8)).strftime('%Y/%m/%d %H:%M:%S')
        sess_sh.append_row([admin['ID'], admin['姓名'], admin['角色'], token, now(), expires, '-'])
        # Update last login
        idx = find_row_index(sh, 'Email', email)
        if idx:
            headers = sh.row_values(1)
            col = headers.index('最後登入') + 1
            sh.update_cell(idx, col, now())
        return jsonify({'ok': True, 'token': token, 'name': admin['姓名'], 'role': admin['角色'], 'regions': admin.get('地區權限', '')})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/staff-login', methods=['POST'])
def staff_login():
    try:
        d = request.json
        id_number = d.get('idNumber', '').upper().strip()
        phone = d.get('phone', '')
        sh = get_sheet('人員資料')
        staff_list = rows(sh)
        staff = next((s for s in staff_list if s.get('身份證字號') == id_number and s.get('帳號狀態') == '啟用中'), None)
        if not staff:
            return jsonify({'ok': False, 'error': '帳號不存在或尚未開通'})
        input4 = phone[-4:]
        stored_hash = staff.get('密碼Hash') or hash_pwd(staff.get('手機號碼', '')[-4:])
        if hash_pwd(input4) != stored_hash and hash_pwd(phone) != stored_hash:
            return jsonify({'ok': False, 'error': '手機號碼後 4 碼不正確'})
        token = str(uuid.uuid4())
        sess_sh = get_sheet('登入狀態')
        expires = (datetime.now(TZ) + timedelta(hours=8)).strftime('%Y/%m/%d %H:%M:%S')
        sess_sh.append_row([staff['ID'], staff['姓名'], 'STAFF', token, now(), expires, '-'])
        idx = find_row_index(sh, 'ID', staff['ID'])
        if idx:
            headers = sh.row_values(1)
            col = headers.index('最後登入') + 1
            sh.update_cell(idx, col, now())
        return jsonify({'ok': True, 'token': token, 'name': staff['姓名'], 'region': staff.get('服務地區', '')})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

def verify_token(token):
    try:
        sh = get_sheet('登入狀態')
        sessions = rows(sh)
        for s in sessions:
            if s.get('Token') == token:
                exp = datetime.strptime(s['到期時間'], '%Y/%m/%d %H:%M:%S').replace(tzinfo=TZ)
                if datetime.now(TZ) < exp:
                    return s
        return None
    except:
        return None

def is_admin(token):
    s = verify_token(token)
    return s and s.get('角色') in ('SUPER', 'MANAGER')

@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        token = request.json.get('token', '')
        sh = get_sheet('登入狀態')
        records = sh.get_all_values()
        headers = records[0]
        col = headers.index('Token')
        for i, row in enumerate(records[1:], start=2):
            if row[col] == token:
                sh.delete_rows(i)
                break
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': True})

# ── 地區 ──────────────────────────────────────

@app.route('/api/get-region-names', methods=['GET'])
def get_region_names():
    try:
        sh = get_sheet('地區設定')
        names = [r.get('地區') for r in rows(sh) if r.get('地區')]
        return jsonify({'ok': True, 'regions': names})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

# ── 新人填寫 ──────────────────────────────────

@app.route('/api/register-newbie', methods=['POST'])
def register_newbie():
    try:
        d = request.json
        name      = d.get('name', '').strip()
        id_number = d.get('idNumber', '').strip().upper()
        dob       = d.get('dob', '').strip()
        phone     = ''.join(filter(str.isdigit, d.get('phone', '')))
        email     = d.get('email', '').strip()
        address   = d.get('address', '').strip()
        ec_name   = d.get('ecName', '').strip()
        ec_rel    = d.get('ecRel', '').strip()
        ec_phone  = ''.join(filter(str.isdigit, d.get('ecPhone', '')))
        transport = d.get('transport', '').strip()
        vaccine   = d.get('vaccine', '').strip()
        region    = d.get('region', '').strip()
        referrer  = d.get('referrer', '').strip()

        if not name:      return jsonify({'ok': False, 'error': '請填寫：姓名'})
        if not id_number: return jsonify({'ok': False, 'error': '請填寫：身份證字號'})
        if not dob:       return jsonify({'ok': False, 'error': '請填寫：出生年月日'})
        if not phone:     return jsonify({'ok': False, 'error': '請填寫：手機號碼'})
        if not email:     return jsonify({'ok': False, 'error': '請填寫：電子郵件'})
        if not address:   return jsonify({'ok': False, 'error': '請填寫：聯絡地址'})
        if not ec_name:   return jsonify({'ok': False, 'error': '請填寫：緊急聯絡人姓名'})
        if not ec_rel:    return jsonify({'ok': False, 'error': '請填寫：緊急聯絡人關係'})
        if not ec_phone:  return jsonify({'ok': False, 'error': '請填寫：緊急聯絡人電話'})
        if not transport: return jsonify({'ok': False, 'error': '請填寫：交通工具'})
        if not vaccine:   return jsonify({'ok': False, 'error': '請填寫：新冠疫苗'})
        if not region:    return jsonify({'ok': False, 'error': '請填寫：服務地區'})

        import re
        if not re.match(r'^[A-Z][0-9]{9}$', id_number):
            return jsonify({'ok': False, 'error': '身份證字號格式不正確'})
        if not re.match(r'^\d{2}/\d{2}/\d{2}$', dob):
            return jsonify({'ok': False, 'error': '出生年月日格式：YY/MM/DD'})
        if len(phone) != 10 or not phone.startswith('09'):
            return jsonify({'ok': False, 'error': '手機號碼請填 09 開頭 10 碼'})

        staff_sh = get_sheet('人員資料')
        if any(r.get('身份證字號') == id_number for r in rows(staff_sh)):
            return jsonify({'ok': False, 'error': '此身份證字號已建檔'})

        pend_sh = get_sheet('待審核新人')
        if any(r.get('身份證字號') == id_number and r.get('審核狀態') == '待審核' for r in rows(pend_sh)):
            return jsonify({'ok': False, 'error': '您的資料已送出，請等待審核'})

        pid = 'P-' + str(int(datetime.now().timestamp() * 1000))
        pend_sh.append_row([
            pid, name, id_number, dob, phone, email, address,
            ec_name, ec_rel, ec_phone, transport, vaccine, region,
            referrer, now(), '待審核', ''
        ])
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

# ── 個人資料 ──────────────────────────────────

@app.route('/api/my-profile', methods=['POST'])
def my_profile():
    try:
        token = request.json.get('token', '')
        s = verify_token(token)
        if not s:
            return jsonify({'ok': False, 'error': '請重新登入'})
        return build_profile(s['人員ID'], False)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

def build_profile(staff_id, is_admin):
    staff_sh = get_sheet('人員資料')
    staff = next((r for r in rows(staff_sh) if r.get('ID') == staff_id), None)
    if not staff:
        return jsonify({'ok': False, 'error': '找不到人員資料'})

    rules_sh = get_sheet('規章同意記錄')
    rule = next((r for r in rows(rules_sh) if r.get('人員ID') == staff_id), None)

    contract_sh = get_sheet('契約記錄')
    contract = next((r for r in rows(contract_sh) if r.get('人員ID') == staff_id), None)

    docs_sh = get_sheet('證件記錄')
    all_docs = [r for r in rows(docs_sh) if r.get('人員ID') == staff_id]
    id_front = next((d for d in all_docs if d.get('文件類型') == 'ID_FRONT'), None)
    id_back  = next((d for d in all_docs if d.get('文件類型') == 'ID_BACK'), None)
    gc_doc   = next((d for d in all_docs if d.get('文件類型') == 'GOOD_CONDUCT'), None)

    bank_sh = get_sheet('銀行帳號')
    bank = next((r for r in rows(bank_sh) if r.get('人員ID') == staff_id), None)

    dep_sh = get_sheet('押金記錄')
    deposit = next((r for r in rows(dep_sh) if r.get('人員ID') == staff_id), None)

    region_sh = get_sheet('地區設定')
    region_info = next((r for r in rows(region_sh) if r.get('地區') == staff.get('服務地區')), None)

    id_num = staff.get('身份證字號', '')
    if not is_admin:
        id_num = '******' + id_num[6:]

    return jsonify({
        'ok': True,
        'staff': {
            'id': staff_id,
            'name': staff.get('姓名'),
            'idNumber': id_num,
            'dob': staff.get('出生年月日'),
            'phone': staff.get('手機號碼'),
            'email': staff.get('電子郵件'),
            'address': staff.get('聯絡地址'),
            'emergencyName': staff.get('緊急聯絡人姓名'),
            'emergencyRel': staff.get('緊急聯絡人關係'),
            'emergencyPhone': staff.get('緊急聯絡人電話'),
            'transport': staff.get('交通工具'),
            'vaccine': staff.get('新冠疫苗'),
            'region': staff.get('服務地區'),
            'status': staff.get('帳號狀態'),
            'hourlyRate': staff.get('時薪'),
            'approvedAt': staff.get('開通日期'),
        },
        'rules': rule,
        'contract': contract,
        'docs': {'idFront': id_front, 'idBack': id_back, 'gc': gc_doc},
        'allDocs': all_docs,
        'bank': bank,
        'deposit': deposit,
        'regionInfo': {'depBank': region_info.get('押金銀行'), 'depAccount': region_info.get('押金帳號')} if region_info else None,
    })

# ── 規章 ──────────────────────────────────────

@app.route('/api/agree-rules', methods=['POST'])
def agree_rules():
    try:
        token = request.json.get('token', '')
        s = verify_token(token)
        if not s: return jsonify({'ok': False, 'error': '請重新登入'})
        sh = get_sheet('規章同意記錄')
        if any(r.get('人員ID') == s['人員ID'] for r in rows(sh)):
            return jsonify({'ok': False, 'error': '您已同意過規章'})
        sh.append_row([s['人員ID'], s['姓名'], now(), '-', 'v2025.04'])
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

# ── 押金 ──────────────────────────────────────

@app.route('/api/submit-deposit', methods=['POST'])
def submit_deposit():
    try:
        d = request.json
        token = d.get('token', '')
        s = verify_token(token)
        if not s: return jsonify({'ok': False, 'error': '請重新登入'})
        dep = d.get('dep', {})
        if not dep.get('remitDate') or not dep.get('lastFive'):
            return jsonify({'ok': False, 'error': '請填寫匯款日期和帳號後5碼'})
        sh = get_sheet('押金記錄')
        if any(r.get('人員ID') == s['人員ID'] and r.get('對帳狀態') == '待對帳' for r in rows(sh)):
            return jsonify({'ok': False, 'error': '已有待對帳記錄'})
        sh.append_row([
            s['人員ID'], s['姓名'], dep.get('remitDate'), dep.get('remitTime', ''),
            dep.get('lastFive'), dep.get('amount', 2000), now(),
            '待對帳', '', '', '', '', '', '', '', '', '', '', '', ''
        ])
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

# ── 後台：待審核清單 ───────────────────────────

@app.route('/api/get-pending-list', methods=['POST'])
def get_pending_list():
    try:
        token = request.json.get('token', '')
        if not is_admin(token): return jsonify({'ok': False, 'error': '無權限'})
        sh = get_sheet('待審核新人')
        lst = [r for r in rows(sh) if r.get('審核狀態') == '待審核']
        return jsonify({'ok': True, 'list': lst})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/approve-account', methods=['POST'])
def approve_account():
    try:
        d = request.json
        token = d.get('token', '')
        if not is_admin(token): return jsonify({'ok': False, 'error': '無權限'})
        pending_id = d.get('pendingId', '')
        pend_sh = get_sheet('待審核新人')
        pending = next((r for r in rows(pend_sh) if r.get('ID') == pending_id), None)
        if not pending: return jsonify({'ok': False, 'error': '找不到待審核記錄'})

        staff_id = 'S-' + str(int(datetime.now().timestamp() * 1000))
        staff_sh = get_sheet('人員資料')
        staff_sh.append_row([
            staff_id, pending['姓名'], pending['身份證字號'], pending['出生年月日'],
            pending['手機號碼'], pending.get('電子郵件', ''), pending.get('聯絡地址', ''),
            pending.get('緊急聯絡人姓名', ''), pending.get('緊急聯絡人關係', ''), pending.get('緊急聯絡人電話', ''),
            pending.get('交通工具', ''), pending.get('新冠疫苗', ''), pending['服務地區'],
            pending.get('介紹人', ''), '啟用中', 200, pending['填寫時間'], now(), '', ''
        ])

        contract_sh = get_sheet('契約記錄')
        contract_sh.append_row([
            staff_id, pending['姓名'], pending['服務地區'],
            now(), '', '', '', 'v2025.04', '待簽署'
        ])

        idx = find_row_index(pend_sh, 'ID', pending_id)
        if idx:
            headers = pend_sh.row_values(1)
            pend_sh.update_cell(idx, headers.index('審核狀態') + 1, '已開通')
            pend_sh.update_cell(idx, headers.index('審核備註') + 1, '帳號:' + staff_id)

        return jsonify({'ok': True, 'staffId': staff_id, 'message': f'已開通 {pending["姓名"]}'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/reject-pending', methods=['POST'])
def reject_pending():
    try:
        d = request.json
        token = d.get('token', '')
        if not is_admin(token): return jsonify({'ok': False, 'error': '無權限'})
        pend_sh = get_sheet('待審核新人')
        idx = find_row_index(pend_sh, 'ID', d.get('pendingId', ''))
        if idx:
            headers = pend_sh.row_values(1)
            pend_sh.update_cell(idx, headers.index('審核狀態') + 1, '已退回')
            pend_sh.update_cell(idx, headers.index('審核備註') + 1, d.get('reason', ''))
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/get-account-list', methods=['POST'])
def get_account_list():
    try:
        token = request.json.get('token', '')
        if not is_admin(token): return jsonify({'ok': False, 'error': '無權限'})
        sh = get_sheet('人員資料')
        lst = [{
            'id': r['ID'], 'name': r['姓名'],
            'idNumber': r['身份證字號'][:6] + '****',
            'phone': r['手機號碼'], 'email': r.get('電子郵件', ''),
            'region': r['服務地區'], 'status': r['帳號狀態'],
            'approvedAt': r.get('開通日期', ''), 'lastLogin': r.get('最後登入', ''),
        } for r in rows(sh)]
        return jsonify({'ok': True, 'list': lst})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/toggle-account', methods=['POST'])
def toggle_account():
    try:
        d = request.json
        if not is_admin(d.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        sh = get_sheet('人員資料')
        staff = next((r for r in rows(sh) if r.get('ID') == d.get('staffId')), None)
        if not staff: return jsonify({'ok': False, 'error': '找不到帳號'})
        new_status = '已停用' if staff['帳號狀態'] == '啟用中' else '啟用中'
        idx = find_row_index(sh, 'ID', d['staffId'])
        headers = sh.row_values(1)
        sh.update_cell(idx, headers.index('帳號狀態') + 1, new_status)
        return jsonify({'ok': True, 'newStatus': new_status})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/get-deposit-list', methods=['POST'])
def get_deposit_list():
    try:
        if not is_admin(request.json.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        sh = get_sheet('押金記錄')
        return jsonify({'ok': True, 'list': rows(sh)})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/confirm-deposit', methods=['POST'])
def confirm_deposit():
    try:
        d = request.json
        token = d.get('token', '')
        s = verify_token(token)
        if not is_admin(token): return jsonify({'ok': False, 'error': '無權限'})
        ids = d.get('staffIds', [])
        sh = get_sheet('押金記錄')
        headers = sh.row_values(1)
        records = sh.get_all_values()
        id_col = headers.index('人員ID')
        for i, row in enumerate(records[1:], start=2):
            if row[id_col] in ids:
                sh.update_cell(i, headers.index('對帳狀態') + 1, '已對帳')
                sh.update_cell(i, headers.index('對帳時間') + 1, now())
                sh.update_cell(i, headers.index('對帳人員') + 1, s['姓名'] if s else '管理員')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/get-regions', methods=['POST'])
def get_regions():
    try:
        if not is_admin(request.json.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        sh = get_sheet('地區設定')
        return jsonify({'ok': True, 'regions': rows(sh)})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/get-admin-list', methods=['POST'])
def get_admin_list():
    try:
        if not is_admin(request.json.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        sh = get_sheet('管理員帳號')
        lst = [{'id': a['ID'], 'email': a['Email'], 'name': a['姓名'], 'role': a['角色'],
                'regions': a.get('地區權限', ''), 'createdAt': a.get('建立時間', ''),
                'lastLogin': a.get('最後登入', '')} for a in rows(sh)]
        return jsonify({'ok': True, 'list': lst})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/get-staff-list', methods=['POST'])
def get_staff_list():
    try:
        d = request.json
        if not is_admin(d.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        staff_rows = rows(get_sheet('人員資料'))
        rules_rows = rows(get_sheet('規章同意記錄'))
        contract_rows = rows(get_sheet('契約記錄'))
        doc_rows = rows(get_sheet('證件記錄'))
        bank_rows = rows(get_sheet('銀行帳號'))
        dep_rows = rows(get_sheet('押金記錄'))

        search = d.get('search', '').strip()
        page = int(d.get('page', 1))
        PAGE = 20

        lst = []
        for s in staff_rows:
            sid = s['ID']
            if search and search not in s.get('姓名', ''):
                continue
            r = next((x for x in rules_rows if x.get('人員ID') == sid), None)
            c = next((x for x in contract_rows if x.get('人員ID') == sid), None)
            idf = next((x for x in doc_rows if x.get('人員ID') == sid and x.get('文件類型') == 'ID_FRONT'), None)
            gc = next((x for x in doc_rows if x.get('人員ID') == sid and x.get('文件類型') == 'GOOD_CONDUCT'), None)
            bk = next((x for x in bank_rows if x.get('人員ID') == sid), None)
            dp = next((x for x in dep_rows if x.get('人員ID') == sid), None)
            lst.append({
                'id': sid, 'name': s['姓名'], 'region': s['服務地區'], 'status': s['帳號狀態'],
                'rules': r['同意時間'] if r else None,
                'contract': c['狀態'] if c else None,
                'idFront': idf['審核狀態'] if idf else None,
                'gc': gc['審核狀態'] if gc else None,
                'bank': '已設定' if bk else None,
                'deposit': dp['對帳狀態'] if dp else None,
            })

        total = len(lst)
        lst = lst[(page-1)*PAGE : page*PAGE]
        return jsonify({'ok': True, 'list': lst, 'total': total, 'page': page})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/get-staff-detail', methods=['POST'])
def get_staff_detail():
    try:
        d = request.json
        if not is_admin(d.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        return build_profile(d.get('staffId', ''), True)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/sign-contract', methods=['POST'])
def sign_contract():
    try:
        token = request.json.get('token', '')
        s = verify_token(token)
        if not s: return jsonify({'ok': False, 'error': '請重新登入'})
        sh = get_sheet('契約記錄')
        contract = next((r for r in rows(sh) if r.get('人員ID') == s['人員ID']), None)
        if not contract: return jsonify({'ok': False, 'error': '找不到契約'})
        if contract.get('狀態') == '已簽署': return jsonify({'ok': False, 'error': '已完成簽署'})
        idx = find_row_index(sh, '人員ID', s['人員ID'])
        headers = sh.row_values(1)
        sh.update_cell(idx, headers.index('簽署時間') + 1, now())
        sh.update_cell(idx, headers.index('狀態') + 1, '已簽署')
        return jsonify({'ok': True, 'signedAt': now()})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/update-bank', methods=['POST'])
def update_bank():
    try:
        d = request.json
        token = d.get('token', '')
        s = verify_token(token)
        if not s: return jsonify({'ok': False, 'error': '請重新登入'})
        bank = d.get('bank', {})
        sh = get_sheet('銀行帳號')
        exists = next((r for r in rows(sh) if r.get('人員ID') == s['人員ID']), None)
        acc = ''.join(filter(str.isdigit, bank.get('account', '')))
        if exists:
            idx = find_row_index(sh, '人員ID', s['人員ID'])
            headers = sh.row_values(1)
            sh.update_cell(idx, headers.index('銀行名稱') + 1, bank.get('bankName', ''))
            sh.update_cell(idx, headers.index('銀行帳號') + 1, acc)
            sh.update_cell(idx, headers.index('持有人') + 1, bank.get('holder', s['姓名']))
        else:
            sh.append_row([s['人員ID'], s['姓名'], bank.get('bankName', ''), bank.get('bankCode', ''), acc, bank.get('holder', s['姓名']), now()])
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/get-bank-list', methods=['POST'])
def get_bank_list():
    try:
        if not is_admin(request.json.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        return jsonify({'ok': True, 'list': rows(get_sheet('銀行帳號'))})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/get-doc-list', methods=['POST'])
def get_doc_list():
    try:
        if not is_admin(request.json.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        staff_rows = rows(get_sheet('人員資料'))
        docs = rows(get_sheet('證件記錄'))
        pending = []
        for d in docs:
            if d.get('審核狀態') == '待審核':
                st = next((s for s in staff_rows if s.get('ID') == d.get('人員ID')), {})
                d['staffIdNumber'] = st.get('身份證字號', '')
                d['staffDob'] = st.get('出生年月日', '')
                d['fileUrl'] = f"https://drive.google.com/file/d/{d['Drive檔案ID']}/view" if d.get('Drive檔案ID') else None
                pending.append(d)
        return jsonify({'ok': True, 'list': pending})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/review-doc', methods=['POST'])
def review_doc():
    try:
        d = request.json
        token = d.get('token', '')
        s = verify_token(token)
        if not is_admin(token): return jsonify({'ok': False, 'error': '無權限'})
        sh = get_sheet('證件記錄')
        records = sh.get_all_values()
        headers = records[0]
        for i, row in enumerate(records[1:], start=2):
            if row[headers.index('人員ID')] == d.get('staffId') and row[headers.index('文件類型')] == d.get('docType'):
                sh.update_cell(i, headers.index('審核狀態') + 1, d.get('status'))
                sh.update_cell(i, headers.index('審核時間') + 1, now())
                sh.update_cell(i, headers.index('審核人員') + 1, s['姓名'] if s else '管理員')
                break
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/save-region', methods=['POST'])
def save_region():
    try:
        d = request.json
        if not is_admin(d.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        r = d.get('region', {})
        sh = get_sheet('地區設定')
        idx = find_row_index(sh, '地區', r.get('地區', ''))
        if idx:
            headers = sh.row_values(1)
            for k, v in r.items():
                if k in headers:
                    sh.update_cell(idx, headers.index(k) + 1, v)
        else:
            sh.append_row([r.get('地區',''), r.get('公司名稱',''), r.get('統一編號',''),
                           r.get('公司地址',''), r.get('公司電話',''), r.get('負責人',''),
                           r.get('押金銀行',''), r.get('押金帳號',''), '', '', '', '', '', now()])
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/create-admin', methods=['POST'])
def create_admin():
    try:
        d = request.json
        if not is_admin(d.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        sh = get_sheet('管理員帳號')
        if any(r.get('Email') == d.get('email', '').strip() for r in rows(sh)):
            return jsonify({'ok': False, 'error': 'Email 已存在'})
        pwd = d.get('password', '')
        if len(pwd) < 6: return jsonify({'ok': False, 'error': '密碼至少 6 碼'})
        aid = 'ADMIN-' + str(int(datetime.now().timestamp() * 1000))
        sh.append_row([aid, d.get('email','').strip(), d.get('name','').strip(),
                       hash_pwd(pwd), d.get('role','MANAGER'), d.get('regions',''), now(), ''])
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/api/get-refund-list', methods=['POST'])
def get_refund_list():
    try:
        if not is_admin(request.json.get('token', '')): return jsonify({'ok': False, 'error': '無權限'})
        sh = get_sheet('押金記錄')
        lst = [r for r in rows(sh) if r.get('退款申請時間') and r.get('對帳狀態') == '已對帳']
        return jsonify({'ok': True, 'list': lst})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'ok': True, 'status': 'running'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
