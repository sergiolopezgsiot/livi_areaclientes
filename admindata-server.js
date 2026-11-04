const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const ADMIN_USER = 'admin';
const ADMIN_PASS = 'Global2026!';
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// token -> { createdAt }
const adminTokens = new Map();

function safeCompare(a, b) {
    const bufA = Buffer.from(String(a || ''));
    const bufB = Buffer.from(String(b || ''));
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
}

function issueAdminToken() {
    const token = crypto.randomBytes(32).toString('hex');
    adminTokens.set(token, { createdAt: Date.now() });
    return token;
}

function requireAdminAuth(req, res, next) {
    const auth = req.headers.authorization || '';
    if (!auth.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'No autorizado' });
    }
    const token = auth.substring(7).trim();
    const session = adminTokens.get(token);
    if (!session) {
        return res.status(401).json({ success: false, error: 'Sesión inválida o expirada' });
    }
    if (Date.now() - session.createdAt > TOKEN_TTL_MS) {
        adminTokens.delete(token);
        return res.status(401).json({ success: false, error: 'Sesión expirada' });
    }
    next();
}

async function getValidTables(pool) {
    const [rows] = await pool.query('SHOW TABLES');
    return rows.map(r => Object.values(r)[0]).filter(Boolean);
}

async function getTableColumns(pool, table) {
    const [cols] = await pool.query(`SHOW COLUMNS FROM \`${table}\``);
    return cols.map(c => ({
        name: c.Field,
        type: c.Type,
        nullable: c.Null === 'YES',
        key: c.Key || '',
        default: c.Default,
        extra: c.Extra || ''
    }));
}

function getPrimaryKeys(columns) {
    const pks = columns.filter(c => c.key === 'PRI').map(c => c.name);
    if (pks.length > 0) return pks;
    // Fallback if no explicit PK: use all columns
    return columns.map(c => c.name);
}

function normalizeColumnValue(val, colMeta) {
    if (val === undefined) return undefined;
    if (val === null) return null;
    const type = (colMeta.type || '').toLowerCase();
    const isAutoInc = (colMeta.extra || '').toLowerCase().includes('auto_increment');

    if (val === '' && (colMeta.nullable || isAutoInc || type.includes('int') || type.includes('decimal') || type.includes('float') || type.includes('double') || type.includes('date') || type.includes('time'))) {
        return null;
    }
    if (typeof val === 'object') {
        return JSON.stringify(val);
    }
    return val;
}

function setupAdminDataRoutes(app, pool) {
    const serveAdminPage = (req, res) => {
        res.sendFile(path.join(__dirname, 'admindata.html'));
    };

    app.get('/admindata', serveAdminPage);
    app.get('/clientes/admindata', serveAdminPage);

    // ─── Auth ────────────────────────────────────────────────────
    const handleLogin = (req, res) => {
        const { username, password } = req.body || {};
        if (safeCompare(username, ADMIN_USER) && safeCompare(password, ADMIN_PASS)) {
            return res.json({ success: true, token: issueAdminToken() });
        }
        return res.status(401).json({ success: false, error: 'Usuario o contraseña incorrectos' });
    };

    app.post('/admindata/api/login', handleLogin);
    app.post('/clientes/admindata/api/login', handleLogin);

    const handleLogout = (req, res) => {
        const auth = req.headers.authorization || '';
        if (auth.startsWith('Bearer ')) {
            adminTokens.delete(auth.substring(7).trim());
        }
        res.json({ success: true });
    };

    app.post('/admindata/api/logout', requireAdminAuth, handleLogout);
    app.post('/clientes/admindata/api/logout', requireAdminAuth, handleLogout);

    // ─── List Tables ─────────────────────────────────────────────
    const handleListTables = async (req, res) => {
        try {
            const tables = await getValidTables(pool);
            const tableDetails = [];
            for (const table of tables) {
                try {
                    const [[countRow]] = await pool.query(`SELECT COUNT(*) AS cnt FROM \`${table}\``);
                    const columns = await getTableColumns(pool, table);
                    tableDetails.push({
                        name: table,
                        count: Number(countRow?.cnt || 0),
                        columns,
                        primaryKeys: getPrimaryKeys(columns)
                    });
                } catch (err) {
                    tableDetails.push({ name: table, count: 0, columns: [], primaryKeys: [] });
                }
            }
            res.json({ success: true, tables: tableDetails });
        } catch (error) {
            console.error('Error listing tables in /admindata:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    };

    app.get('/admindata/api/tables', requireAdminAuth, handleListTables);
    app.get('/clientes/admindata/api/tables', requireAdminAuth, handleListTables);

    // ─── Read Table Rows ─────────────────────────────────────────
    const handleGetTableData = async (req, res) => {
        try {
            const { table } = req.params;
            const validTables = await getValidTables(pool);
            if (!validTables.includes(table)) {
                return res.status(404).json({ success: false, error: 'Tabla no encontrada' });
            }

            const columns = await getTableColumns(pool, table);
            const primaryKeys = getPrimaryKeys(columns);
            const colNames = columns.map(c => c.name);

            const page = Math.max(1, parseInt(req.query.page, 10) || 1);
            const limit = Math.min(500, Math.max(1, parseInt(req.query.limit, 10) || 50));
            const offset = (page - 1) * limit;
            const search = String(req.query.search || '').trim();
            const sortBy = colNames.includes(req.query.sortBy) ? req.query.sortBy : (primaryKeys[0] || colNames[0]);
            const sortDir = String(req.query.sortDir || 'DESC').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

            let whereClause = '';
            const params = [];

            if (search) {
                const likeClauses = colNames.map(col => `CAST(\`${col}\` AS CHAR) LIKE ?`);
                whereClause = `WHERE (${likeClauses.join(' OR ')})`;
                for (let i = 0; i < colNames.length; i++) {
                    params.push(`%${search}%`);
                }
            }

            const [[countRow]] = await pool.query(
                `SELECT COUNT(*) AS total FROM \`${table}\` ${whereClause}`,
                params
            );
            const total = Number(countRow?.total || 0);

            const orderClause = sortBy ? `ORDER BY \`${sortBy}\` ${sortDir}` : '';
            const [rows] = await pool.query(
                `SELECT * FROM \`${table}\` ${whereClause} ${orderClause} LIMIT ? OFFSET ?`,
                [...params, limit, offset]
            );

            res.json({
                success: true,
                table,
                columns,
                primaryKeys,
                rows,
                total,
                page,
                limit,
                sortBy,
                sortDir
            });
        } catch (error) {
            console.error('Error reading table in /admindata:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    };

    app.get('/admindata/api/tables/:table', requireAdminAuth, handleGetTableData);
    app.get('/clientes/admindata/api/tables/:table', requireAdminAuth, handleGetTableData);

    // ─── Create Row ──────────────────────────────────────────────
    const handleCreateRow = async (req, res) => {
        try {
            const { table } = req.params;
            const validTables = await getValidTables(pool);
            if (!validTables.includes(table)) {
                return res.status(404).json({ success: false, error: 'Tabla no encontrada' });
            }

            const columns = await getTableColumns(pool, table);
            const colMap = new Map(columns.map(c => [c.name, c]));
            const rawData = { ...(req.body?.data || req.body || {}) };

            // Optional plain-password hashing helper if table has password_hash
            if (rawData._new_password && colMap.has('password_hash')) {
                rawData.password_hash = await bcrypt.hash(String(rawData._new_password), 10);
            }
            delete rawData._new_password;

            const insertCols = [];
            const insertVals = [];

            for (const [key, val] of Object.entries(rawData)) {
                const colMeta = colMap.get(key);
                if (!colMeta) continue;
                const isAutoInc = (colMeta.extra || '').toLowerCase().includes('auto_increment');
                if (isAutoInc && (val === '' || val === null || val === undefined)) {
                    continue;
                }
                const normalized = normalizeColumnValue(val, colMeta);
                if (normalized === undefined) continue;
                insertCols.push(`\`${key}\``);
                insertVals.push(normalized);
            }

            let sql;
            if (insertCols.length === 0) {
                sql = `INSERT INTO \`${table}\` () VALUES ()`;
            } else {
                const placeholders = insertCols.map(() => '?').join(', ');
                sql = `INSERT INTO \`${table}\` (${insertCols.join(', ')}) VALUES (${placeholders})`;
            }

            const [result] = await pool.query(sql, insertVals);
            res.status(201).json({
                success: true,
                insertId: result.insertId,
                affectedRows: result.affectedRows
            });
        } catch (error) {
            console.error('Error creating row in /admindata:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    };

    app.post('/admindata/api/tables/:table', requireAdminAuth, handleCreateRow);
    app.post('/clientes/admindata/api/tables/:table', requireAdminAuth, handleCreateRow);

    // ─── Update Row ──────────────────────────────────────────────
    const handleUpdateRow = async (req, res) => {
        try {
            const { table } = req.params;
            const validTables = await getValidTables(pool);
            if (!validTables.includes(table)) {
                return res.status(404).json({ success: false, error: 'Tabla no encontrada' });
            }

            const columns = await getTableColumns(pool, table);
            const colMap = new Map(columns.map(c => [c.name, c]));

            const pk = req.body?.pk || {};
            const rawData = { ...(req.body?.data || {}) };

            if (rawData._new_password && colMap.has('password_hash')) {
                rawData.password_hash = await bcrypt.hash(String(rawData._new_password), 10);
            }
            delete rawData._new_password;

            const whereParts = [];
            const whereVals = [];
            for (const [k, v] of Object.entries(pk)) {
                if (!colMap.has(k)) continue;
                if (v === null) {
                    whereParts.push(`\`${k}\` IS NULL`);
                } else {
                    whereParts.push(`\`${k}\` = ?`);
                    whereVals.push(v);
                }
            }

            if (whereParts.length === 0) {
                return res.status(400).json({ success: false, error: 'Se requiere clave primaria (pk) para actualizar' });
            }

            const setParts = [];
            const setVals = [];
            for (const [k, v] of Object.entries(rawData)) {
                const colMeta = colMap.get(k);
                if (!colMeta) continue;
                const normalized = normalizeColumnValue(v, colMeta);
                if (normalized === undefined) continue;
                setParts.push(`\`${k}\` = ?`);
                setVals.push(normalized);
            }

            if (setParts.length === 0) {
                return res.status(400).json({ success: false, error: 'No hay campos para actualizar' });
            }

            const sql = `UPDATE \`${table}\` SET ${setParts.join(', ')} WHERE ${whereParts.join(' AND ')} LIMIT 1`;
            const [result] = await pool.query(sql, [...setVals, ...whereVals]);

            res.json({
                success: true,
                affectedRows: result.affectedRows
            });
        } catch (error) {
            console.error('Error updating row in /admindata:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    };

    app.put('/admindata/api/tables/:table', requireAdminAuth, handleUpdateRow);
    app.put('/clientes/admindata/api/tables/:table', requireAdminAuth, handleUpdateRow);

    // ─── Delete Row ──────────────────────────────────────────────
    const handleDeleteRow = async (req, res) => {
        try {
            const { table } = req.params;
            const validTables = await getValidTables(pool);
            if (!validTables.includes(table)) {
                return res.status(404).json({ success: false, error: 'Tabla no encontrada' });
            }

            const columns = await getTableColumns(pool, table);
            const colMap = new Map(columns.map(c => [c.name, c]));
            const pk = req.body?.pk || {};

            const whereParts = [];
            const whereVals = [];
            for (const [k, v] of Object.entries(pk)) {
                if (!colMap.has(k)) continue;
                if (v === null) {
                    whereParts.push(`\`${k}\` IS NULL`);
                } else {
                    whereParts.push(`\`${k}\` = ?`);
                    whereVals.push(v);
                }
            }

            if (whereParts.length === 0) {
                return res.status(400).json({ success: false, error: 'Se requiere clave primaria (pk) para eliminar' });
            }

            const sql = `DELETE FROM \`${table}\` WHERE ${whereParts.join(' AND ')} LIMIT 1`;
            const [result] = await pool.query(sql, whereVals);

            res.json({
                success: true,
                affectedRows: result.affectedRows
            });
        } catch (error) {
            console.error('Error deleting row in /admindata:', error);
            res.status(500).json({ success: false, error: error.message });
        }
    };

    app.delete('/admindata/api/tables/:table', requireAdminAuth, handleDeleteRow);
    app.delete('/clientes/admindata/api/tables/:table', requireAdminAuth, handleDeleteRow);
}

module.exports = { setupAdminDataRoutes };

