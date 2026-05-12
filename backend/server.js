const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const XLSX = require('xlsx');
const cron = require('node-cron');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

const DB_PATH = process.env.DB_PATH || './data/tasks.db';
const JWT_SECRET = process.env.JWT_SECRET || 'syc-chile-secret-2025-changeme';
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rut TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    phone TEXT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT CHECK(role IN ('admin','user','viewer')) DEFAULT 'user',
    active INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT NOT NULL,
    description TEXT,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    start_time TEXT,
    end_time TEXT,
    priority TEXT CHECK(priority IN ('alta','media','baja')) DEFAULT 'media',
    status TEXT CHECK(status IN ('pendiente','en_progreso','completada','cancelada')) DEFAULT 'pendiente',
    alert_sent INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER,
    action TEXT NOT NULL,
    old_data TEXT,
    new_data TEXT,
    timestamp TEXT DEFAULT (datetime('now'))
  );
`);

// ─── Migrations: add columns if missing ───────────────────────────────────────
const auditCols = db.prepare("PRAGMA table_info(audit_log)").all().map(c => c.name);
if (!auditCols.includes('user_id')) db.exec("ALTER TABLE audit_log ADD COLUMN user_id INTEGER");
if (!auditCols.includes('ip'))      db.exec("ALTER TABLE audit_log ADD COLUMN ip TEXT");

const taskCols = db.prepare("PRAGMA table_info(tasks)").all().map(c => c.name);
if (!taskCols.includes('user_id'))  db.exec("ALTER TABLE tasks ADD COLUMN user_id INTEGER");

// ─── Default admin ────────────────────────────────────────────────────────────
const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get();
if (userCount.c === 0) {
  const hash = bcrypt.hashSync('Syccarrasco123', 10);
  db.prepare(`INSERT INTO users (rut, full_name, phone, email, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)`)
    .run('11111111-1', 'Administrador S&C', '+56900000000', 'aulavirtual@sycchile.com', hash, 'admin');
  console.log('[INIT] Admin creado: aulavirtual@sycchile.com / Syccarrasco123');
}

function auditLog(userId, taskId, action, oldData, newData, ip) {
  db.prepare(`INSERT INTO audit_log (user_id, task_id, action, old_data, new_data, ip) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(userId, taskId, action,
      oldData ? JSON.stringify(oldData) : null,
      newData ? JSON.stringify(newData) : null,
      ip || null);
}

// ─── Middleware ───────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'No autenticado' });
  try { req.user = jwt.verify(header.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token inválido o expirado' }); }
}
function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
    next();
  });
}
function requireNotViewer(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role === 'viewer') return res.status(403).json({ error: 'Sin permisos para esta acción' });
    next();
  });
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });
  const user = db.prepare('SELECT * FROM users WHERE email = ? AND active = 1').get(email.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, full_name: user.full_name }, JWT_SECRET, { expiresIn: '12h' });
  auditLog(user.id, null, 'LOGIN', null, { email: user.email }, req.ip);
  res.json({ token, user: { id: user.id, rut: user.rut, full_name: user.full_name, email: user.email, role: user.role } });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, rut, full_name, phone, email, role FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { current_password, new_password } = req.body;
  if (!current_password || !new_password) return res.status(400).json({ error: 'Campos requeridos' });
  if (new_password.length < 8) return res.status(400).json({ error: 'Mínimo 8 caracteres' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(current_password, user.password_hash))
    return res.status(401).json({ error: 'Contraseña actual incorrecta' });
  db.prepare("UPDATE users SET password_hash=?, updated_at=datetime('now') WHERE id=?")
    .run(bcrypt.hashSync(new_password, 10), req.user.id);
  res.json({ success: true });
});

// ─── Users ────────────────────────────────────────────────────────────────────
app.get('/api/users', requireAuth, (req, res) => {
  const users = db.prepare('SELECT id, rut, full_name, phone, email, role, active, created_at FROM users ORDER BY full_name').all();
  res.json(users);
});

app.post('/api/users', requireAdmin, (req, res) => {
  const { rut, full_name, phone, email, password, role } = req.body;
  if (!rut || !full_name || !email || !password) return res.status(400).json({ error: 'RUT, nombre, email y contraseña requeridos' });
  if (password.length < 8) return res.status(400).json({ error: 'Mínimo 8 caracteres' });
  const exists = db.prepare('SELECT id FROM users WHERE rut=? OR email=?').get(rut.toUpperCase(), email.toLowerCase());
  if (exists) return res.status(409).json({ error: 'RUT o email ya registrado' });
  const result = db.prepare(`INSERT INTO users (rut, full_name, phone, email, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(rut.toUpperCase(), full_name, phone||null, email.toLowerCase(), bcrypt.hashSync(password, 10), role||'user');
  const newUser = db.prepare('SELECT id, rut, full_name, phone, email, role, active FROM users WHERE id=?').get(result.lastInsertRowid);
  auditLog(req.user.id, null, 'CREATE_USER', null, { id: newUser.id, email: newUser.email }, req.ip);
  res.status(201).json(newUser);
});

app.put('/api/users/:id', requireAdmin, (req, res) => {
  const old = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Usuario no encontrado' });
  const { rut, full_name, phone, email, role, active, password } = req.body;
  let hash = old.password_hash;
  if (password) {
    if (password.length < 8) return res.status(400).json({ error: 'Mínimo 8 caracteres' });
    hash = bcrypt.hashSync(password, 10);
  }
  db.prepare(`UPDATE users SET rut=?, full_name=?, phone=?, email=?, password_hash=?, role=?, active=?, updated_at=datetime('now') WHERE id=?`)
    .run((rut||old.rut).toUpperCase(), full_name||old.full_name, phone||old.phone,
      (email||old.email).toLowerCase(), hash, role||old.role, active??old.active, req.params.id);
  const updated = db.prepare('SELECT id, rut, full_name, phone, email, role, active FROM users WHERE id=?').get(req.params.id);
  auditLog(req.user.id, null, 'UPDATE_USER', { id: old.id, role: old.role }, updated, req.ip);
  res.json(updated);
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  if (req.params.id == req.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
  const u = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'Usuario no encontrado' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  auditLog(req.user.id, null, 'DELETE_USER', { id: u.id, email: u.email }, null, req.ip);
  res.json({ success: true });
});

// ─── Tasks ────────────────────────────────────────────────────────────────────
app.get('/api/tasks', requireAuth, (req, res) => {
  const { date, month, year, status, priority, user_id } = req.query;
  const scopeId = req.user.role === 'user' ? req.user.id : (user_id || null);
  let q = `SELECT t.*, u.full_name as user_name FROM tasks t JOIN users u ON t.user_id=u.id WHERE 1=1`;
  const p = [];
  if (scopeId) { q += ' AND t.user_id=?'; p.push(scopeId); }
  if (date) { q += ' AND (t.start_date<=? AND t.end_date>=?)'; p.push(date, date); }
  if (month && year) {
    const ym = `${year}-${String(month).padStart(2,'0')}`;
    q += ` AND (strftime('%Y-%m',t.start_date)=? OR strftime('%Y-%m',t.end_date)=?)`; p.push(ym, ym);
  }
  if (status) { q += ' AND t.status=?'; p.push(status); }
  if (priority) { q += ' AND t.priority=?'; p.push(priority); }
  q += ' ORDER BY t.start_date ASC, t.start_time ASC';
  res.json(db.prepare(q).all(...p));
});

app.get('/api/tasks/alerts/pending', requireAuth, (req, res) => {
  const tomorrow = new Date(); tomorrow.setDate(tomorrow.getDate()+1);
  const ts = tomorrow.toISOString().split('T')[0];
  let q = `SELECT t.*, u.full_name as user_name FROM tasks t JOIN users u ON t.user_id=u.id
           WHERE t.end_date=? AND t.status NOT IN ('completada','cancelada') AND t.alert_sent=0`;
  const p = [ts];
  if (req.user.role === 'user') { q += ' AND t.user_id=?'; p.push(req.user.id); }
  res.json(db.prepare(q).all(...p));
});

app.get('/api/tasks/:id', requireAuth, (req, res) => {
  const task = db.prepare('SELECT t.*, u.full_name as user_name FROM tasks t JOIN users u ON t.user_id=u.id WHERE t.id=?').get(req.params.id);
  if (!task) return res.status(404).json({ error: 'Tarea no encontrada' });
  if (req.user.role === 'user' && task.user_id !== req.user.id) return res.status(403).json({ error: 'Sin acceso' });
  res.json(task);
});

app.post('/api/tasks', requireNotViewer, (req, res) => {
  const { name, description, start_date, end_date, start_time, end_time, priority, user_id } = req.body;
  if (!name || !start_date || !end_date) return res.status(400).json({ error: 'Nombre y fechas requeridos' });
  const targetId = (req.user.role === 'admin' && user_id) ? user_id : req.user.id;
  const result = db.prepare(`INSERT INTO tasks (user_id, name, description, start_date, end_date, start_time, end_time, priority) VALUES (?,?,?,?,?,?,?,?)`)
    .run(targetId, name, description||'', start_date, end_date, start_time||null, end_time||null, priority||'media');
  const newTask = db.prepare('SELECT t.*, u.full_name as user_name FROM tasks t JOIN users u ON t.user_id=u.id WHERE t.id=?').get(result.lastInsertRowid);
  auditLog(req.user.id, result.lastInsertRowid, 'CREATE', null, newTask, req.ip);
  res.status(201).json(newTask);
});

app.put('/api/tasks/:id', requireNotViewer, (req, res) => {
  const old = db.prepare('SELECT * FROM tasks WHERE id=?').get(req.params.id);
  if (!old) return res.status(404).json({ error: 'Tarea no encontrada' });
  if (req.user.role === 'user' && old.user_id !== req.user.id) return res.status(403).json({ error: 'Sin acceso' });
  const { name, description, start_date, end_date, start_time, end_time, priority, status } = req.body;
  db.prepare(`UPDATE tasks SET name=?, description=?, start_date=?, end_date=?, start_time=?, end_time=?, priority=?, status=?, updated_at=datetime('now') WHERE id=?`)
    .run(name??old.name, description??old.description, start_date??old.start_date, end_date??old.end_date,
      start_time??old.start_time, end_time??old.end_time, priority??old.priority, status??old.status, req.params.id);
  const updated = db.prepare('SELECT t.*, u.full_name as user_name FROM tasks t JOIN users u ON t.user_id=u.id WHERE t.id=?').get(req.params.id);
  auditLog(req.user.id, req.params.id, 'UPDATE', old, updated, req.ip);
  res.json(updated);
});

app.delete('/api/tasks/:id', requireAdmin, (req, res) => {
  const task = db.prepare('SELECT * FROM tasks WHERE id=?').get(req.params.id);
  if (!task) return res.status(404).json({ error: 'Tarea no encontrada' });
  db.prepare('DELETE FROM tasks WHERE id=?').run(req.params.id);
  auditLog(req.user.id, req.params.id, 'DELETE', task, null, req.ip);
  res.json({ success: true });
});

// ─── Audit ────────────────────────────────────────────────────────────────────
const isSuperAdmin = (req) => req.user.email === process.env.SUPERADMIN_EMAIL || req.user.role === 'superadmin';

app.get('/api/audit', requireAuth, (req, res) => {
  if (req.user.role !== 'admin' && !isSuperAdmin(req)) return res.status(403).json({ error: 'Acceso denegado' });
  const { action, user_id, from, to } = req.query;
  let q = `SELECT a.*, u.full_name as actor_name FROM audit_log a LEFT JOIN users u ON a.user_id=u.id WHERE 1=1`;
  const p = [];
  if (action) { q += ' AND a.action=?'; p.push(action); }
  if (user_id) { q += ' AND a.user_id=?'; p.push(user_id); }
  if (from) { q += ' AND a.timestamp >= ?'; p.push(from); }
  if (to) { q += ' AND a.timestamp <= ?'; p.push(to+' 23:59:59'); }
  q += ' ORDER BY a.timestamp DESC LIMIT 2000';
  res.json(db.prepare(q).all(...p));
});

app.delete('/api/audit/bulk', requireAuth, (req, res) => {
  if (!isSuperAdmin(req)) return res.status(403).json({ error: 'Solo el superadmin puede borrar auditoría' });
  const { ids } = req.body;
  if (!ids || !ids.length) return res.status(400).json({ error: 'IDs requeridos' });
  db.prepare(`DELETE FROM audit_log WHERE id IN (${ids.map(()=>'?').join(',')})`).run(...ids);
  res.json({ success: true, deleted: ids.length });
});

app.delete('/api/audit/all', requireAuth, (req, res) => {
  if (!isSuperAdmin(req)) return res.status(403).json({ error: 'Solo el superadmin puede borrar auditoría' });
  db.prepare('DELETE FROM audit_log').run();
  res.json({ success: true });
});

app.delete('/api/audit/:id', requireAuth, (req, res) => {
  if (!isSuperAdmin(req)) return res.status(403).json({ error: 'Solo el superadmin puede borrar auditoría' });
  db.prepare('DELETE FROM audit_log WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// ─── Stats ────────────────────────────────────────────────────────────────────
app.get('/api/stats', requireAuth, (req, res) => {
  const scopeId = req.user.role === 'user' ? req.user.id : null;
  const where = scopeId ? `WHERE t.user_id=${scopeId}` : '';

  const byStatus   = db.prepare(`SELECT status, COUNT(*) as count FROM tasks t ${where} GROUP BY status`).all();
  const byPriority = db.prepare(`SELECT priority, COUNT(*) as count FROM tasks t ${where} GROUP BY priority`).all();
  const byUser     = db.prepare(`SELECT u.full_name, u.id as user_id,
    SUM(CASE WHEN t.status='completada' THEN 1 ELSE 0 END) as completada,
    SUM(CASE WHEN t.status='en_progreso' THEN 1 ELSE 0 END) as en_progreso,
    SUM(CASE WHEN t.status='pendiente' THEN 1 ELSE 0 END) as pendiente,
    SUM(CASE WHEN t.status='cancelada' THEN 1 ELSE 0 END) as cancelada,
    COUNT(*) as total
    FROM tasks t JOIN users u ON t.user_id=u.id ${where}
    GROUP BY t.user_id ORDER BY total DESC`).all();
  const byWeek     = db.prepare(`SELECT strftime('%Y-W%W', start_date) as period,
    COUNT(*) as total, SUM(CASE WHEN status='completada' THEN 1 ELSE 0 END) as completada
    FROM tasks t ${where} GROUP BY period ORDER BY period DESC LIMIT 8`).all().reverse();
  const byMonth    = db.prepare(`SELECT strftime('%Y-%m', start_date) as period,
    COUNT(*) as total, SUM(CASE WHEN status='completada' THEN 1 ELSE 0 END) as completada
    FROM tasks t ${where} GROUP BY period ORDER BY period DESC LIMIT 12`).all().reverse();
  const byYear     = db.prepare(`SELECT strftime('%Y', start_date) as period,
    COUNT(*) as total, SUM(CASE WHEN status='completada' THEN 1 ELSE 0 END) as completada
    FROM tasks t ${where} GROUP BY period ORDER BY period`).all();

  res.json({ byStatus, byPriority, byUser, byWeek, byMonth, byYear });
});

// ─── Export ───────────────────────────────────────────────────────────────────
// export with token in query support
app.get('/api/export/excel', (req, res, next) => {
  if (req.query._t) req.headers.authorization = 'Bearer '+req.query._t;
  next();
}, requireAuth, (req, res) => {
  const scopeId = req.user.role === 'user' ? req.user.id : null;
  let q = `SELECT t.*, u.full_name as user_name FROM tasks t JOIN users u ON t.user_id=u.id`;
  if (scopeId) q += ` WHERE t.user_id=${scopeId}`;
  q += ' ORDER BY t.start_date ASC';
  const tasks = db.prepare(q).all();
  const wb = XLSX.utils.book_new();
  const ws = XLSX.utils.json_to_sheet(tasks.map(t => ({
    'ID': t.id, 'Usuario': t.user_name, 'Nombre': t.name, 'Descripción': t.description,
    'Fecha Inicio': t.start_date, 'Fecha Término': t.end_date,
    'Hora Inicio': t.start_time||'', 'Hora Término': t.end_time||'',
    'Prioridad': t.priority, 'Estado': t.status, 'Creada': t.created_at
  })));
  ws['!cols'] = [{wch:5},{wch:22},{wch:30},{wch:38},{wch:13},{wch:13},{wch:11},{wch:11},{wch:9},{wch:13},{wch:19}];
  XLSX.utils.book_append_sheet(wb, ws, 'Tareas');
  if (req.user.role === 'admin') {
    const us = db.prepare('SELECT id, rut, full_name, phone, email, role, active, created_at FROM users ORDER BY full_name').all();
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(us.map(u => ({
      'ID': u.id, 'RUT': u.rut, 'Nombre': u.full_name, 'Teléfono': u.phone||'',
      'Email': u.email, 'Rol': u.role, 'Activo': u.active?'Sí':'No', 'Creado': u.created_at
    }))), 'Usuarios');
    const al = db.prepare(`SELECT a.*, u.full_name as actor FROM audit_log a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.timestamp DESC`).all();
    XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(al.map(a => ({
      'ID': a.id, 'Actor': a.actor||'Sistema', 'Acción': a.action,
      'ID Tarea': a.task_id||'', 'IP': a.ip||'', 'Timestamp': a.timestamp
    }))), 'Auditoría');
  }
  const buf = XLSX.write(wb, { type:'buffer', bookType:'xlsx' });
  res.setHeader('Content-Disposition', `attachment; filename="syc_tareas_${new Date().toISOString().split('T')[0]}.xlsx"`);
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.send(buf);
});

// ─── Cron ─────────────────────────────────────────────────────────────────────
cron.schedule('0 8 * * *', () => {
  const tomorrow = new Date(); tomorrow.setDate(tomorrow.getDate()+1);
  const ts = tomorrow.toISOString().split('T')[0];
  db.prepare(`SELECT * FROM tasks WHERE end_date=? AND status NOT IN ('completada','cancelada') AND alert_sent=0`)
    .all(ts).forEach(t => {
      db.prepare('UPDATE tasks SET alert_sent=1 WHERE id=?').run(t.id);
      console.log(`[ALERTA] "${t.name}" vence mañana`);
    });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`API en puerto ${PORT}`));

// placeholder - replaced below
