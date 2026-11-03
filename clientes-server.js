const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

// In-memory token store for the clientes area
const clienteTokens = new Map(); // token -> iduser

function setupClientesRoutes(app, pool) {
    app.get('/', (req, res) => {
        res.sendFile(path.join(__dirname, 'index.html'));
    });

    app.get('/clientes', (req, res) => {
        res.sendFile(path.join(__dirname, 'index.html'));
    });

    // ─── Auth Middleware ─────────────────────────────────────────
    function requireAuth(req, res, next) {
        const auth = req.headers.authorization;
        if (!auth || !auth.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        const token = auth.substring(7);
        const iduser = clienteTokens.get(token);
        if (!iduser) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.clienteId = iduser;
        next();
    }

    function issueToken(iduser) {
        const token = crypto.randomBytes(32).toString('hex');
        clienteTokens.set(token, iduser);
        return token;
    }

    function requireExternalClientAuth(req, res, next) {
        const expectedToken = process.env.CLIENTES_API_TOKEN;
        if (!expectedToken) {
            return res.status(500).json({ error: 'CLIENTES_API_TOKEN is not configured' });
        }

        const authHeader = req.headers.authorization || '';
        const match = authHeader.match(/^Bearer\s+(.+)$/i);
        if (!match) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const providedToken = match[1];
        const expectedBuffer = Buffer.from(expectedToken);
        const providedBuffer = Buffer.from(providedToken);

        if (providedBuffer.length !== expectedBuffer.length ||
            !crypto.timingSafeEqual(expectedBuffer, providedBuffer)) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        next();
    }

    function normalizeEmail(value) {
        return String(value || '').trim().toLowerCase();
    }

    function parsePains(value) {
        if (typeof value === 'string') {
            try {
                const parsed = JSON.parse(value);
                return Array.isArray(parsed) ? parsed : [parsed];
            } catch (error) {
                return [];
            }
        }
        if (Array.isArray(value)) return value;
        return [];
    }

    // ─── Auth Endpoints ──────────────────────────────────────────
    async function handleRegister(req, res) {
        const { nombre, email, telefono, password } = req.body;
        if (!nombre || !email || !password) {
            return res.status(400).json({ success: false, error: 'Nombre, email y contraseña son obligatorios' });
        }

        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();

            const [existing] = await connection.query(
                'SELECT iduser, password_hash FROM registros WHERE email = ?', [email]
            );

            const passwordHash = await bcrypt.hash(password, 10);
            let iduser;

            if (existing.length > 0) {
                if (existing[0].password_hash) {
                    await connection.rollback();
                    return res.status(409).json({ success: false, error: 'Ya existe una cuenta con este email. Inicia sesión.' });
                }
                iduser = existing[0].iduser;
                await connection.query(
                    'UPDATE registros SET password_hash = ?, nombre = ?, telefono = COALESCE(?, telefono) WHERE iduser = ?',
                    [passwordHash, nombre, telefono || null, iduser]
                );
            } else {
                const [insertRes] = await connection.query(
                    'INSERT INTO registros (nombre, email, telefono, password_hash) VALUES (?, ?, ?, ?)',
                    [nombre, email, telefono || null, passwordHash]
                );
                iduser = insertRes.insertId;
                await connection.query('INSERT INTO houses (iduser) VALUES (?)', [iduser]);
            }

            await connection.commit();
            res.json({ success: true, token: issueToken(iduser) });
        } catch (error) {
            await connection.rollback();
            console.error('Error in /clientes/api/register:', error);
            res.status(500).json({ success: false, error: 'Internal Server Error' });
        } finally {
            connection.release();
        }
    }

    app.post('/clientes/api/register', handleRegister);
    app.post('/api/register', handleRegister);

    async function handleLogin(req, res) {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, error: 'Email y contraseña son obligatorios' });
        }
        try {
            const [rows] = await pool.query('SELECT iduser, password_hash FROM registros WHERE email = ?', [email]);
            const user = rows[0];
            if (!user || !user.password_hash || !(await bcrypt.compare(password, user.password_hash))) {
                return res.status(401).json({ success: false, error: 'Credenciales incorrectas' });
            }
            res.json({ success: true, token: issueToken(user.iduser) });
        } catch (error) {
            console.error('Error in /clientes/api/login:', error);
            res.status(500).json({ success: false, error: 'Internal Server Error' });
        }
    }

    app.post('/clientes/api/login', handleLogin);
    app.post('/api/login', handleLogin);

    function handleLogout(req, res) {
        clienteTokens.delete(req.headers.authorization.substring(7));
        res.json({ success: true });
    }

    app.post('/clientes/api/logout', requireAuth, handleLogout);
    app.post('/api/logout', requireAuth, handleLogout);

    async function handleClienteLookup(req, res) {
        const email = normalizeEmail(req.query.email);
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!email || !emailPattern.test(email)) {
            return res.status(400).json({ success: false, error: 'Email inválido' });
        }

        try {
            const [registroRows] = await pool.query(
                `SELECT iduser, nombre, email, telefono, localidad, convive, urgencia, pains, personas, fecha_registro
                 FROM registros WHERE email = ? LIMIT 1`,
                [email]
            );

            if (registroRows.length === 0) {
                return res.status(404).json({ success: false, error: 'Cliente no encontrado' });
            }

            const cliente = { ...registroRows[0] };
            delete cliente.password_hash;
            cliente.pains = parsePains(cliente.pains);

            const [houseRows] = await pool.query(
                `SELECT id, iduser, tipo_vivienda, uso_vivienda, sistema_actual, zonas, presupuesto, prioridad, superficie
                 FROM houses WHERE iduser = ? LIMIT 1`,
                [cliente.iduser]
            );
            const house = houseRows[0] || null;

            let devices = [];
            if (house) {
                const [deviceRows] = await pool.query(
                    `SELECT hd.house_id, hd.device_id, hd.cantidad, hd.eleccion,
                            d.id, d.label, d.price, d.pricediscount, d.image_url
                     FROM house_devices hd
                     JOIN devices d ON hd.device_id = d.id
                     WHERE hd.house_id = ?`,
                    [house.id]
                );
                devices = deviceRows;
            }

            return res.json({ success: true, cliente, house, devices });
        } catch (error) {
            console.error('Error in /api/cliente:', error);
            return res.status(500).json({ success: false, error: 'Internal Server Error' });
        }
    }

    app.get('/api/cliente', requireExternalClientAuth, handleClienteLookup);
    app.get('/clientes/api/cliente', requireExternalClientAuth, handleClienteLookup);

    // ─── Data Endpoints (scoped to req.clienteId) ─────────────────
    async function handleGetMe(req, res) {
        try {
            const [registroRes] = await pool.query('SELECT * FROM registros WHERE iduser = ?', [req.clienteId]);
            if (registroRes.length === 0) return res.status(404).json({ error: 'Not found' });

            const registro = registroRes[0];
            delete registro.password_hash;
            if (typeof registro.pains === 'string') {
                try { registro.pains = JSON.parse(registro.pains); } catch (e) { registro.pains = []; }
            }
            if (!registro.pains) registro.pains = [];

            const [houseRes] = await pool.query('SELECT * FROM houses WHERE iduser = ?', [req.clienteId]);
            const house = houseRes[0] || null;
            let devices = [];

            if (house) {
                const [devRes] = await pool.query(`
                    SELECT hd.*, d.label, d.price, d.pricediscount, d.image_url
                    FROM house_devices hd
                    JOIN devices d ON hd.device_id = d.id
                    WHERE hd.house_id = ?`, [house.id]);
                devices = devRes;
            }

            res.json({ registro, house, devices });
        } catch (e) { res.status(500).json({ error: e.message }); }
    }

    app.get('/clientes/api/me', requireAuth, handleGetMe);
    app.get('/api/me', requireAuth, handleGetMe);

    async function handleUpdateRegistro(req, res) {
        const { nombre, telefono, localidad, convive, urgencia, pains, personas } = req.body;
        const painsArray = Array.isArray(pains) ? pains : (pains ? [pains] : []);
        try {
            await pool.query(
                'UPDATE registros SET nombre=?, telefono=?, localidad=?, convive=?, urgencia=?, pains=?, personas=? WHERE iduser=?',
                [nombre, telefono, localidad, convive, urgencia, JSON.stringify(painsArray), personas || null, req.clienteId]
            );
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    }

    app.put('/clientes/api/me/registro', requireAuth, handleUpdateRegistro);
    app.put('/api/me/registro', requireAuth, handleUpdateRegistro);

    async function handleUpdateVivienda(req, res) {
        const { tipo_vivienda, uso_vivienda, sistema_actual, zonas, presupuesto, prioridad, superficie } = req.body;
        try {
            const [houseRes] = await pool.query('SELECT id FROM houses WHERE iduser = ?', [req.clienteId]);
            if (houseRes.length === 0) return res.status(404).json({ error: 'House not found' });

            await pool.query(
                'UPDATE houses SET tipo_vivienda=?, uso_vivienda=?, sistema_actual=?, zonas=?, presupuesto=?, prioridad=?, superficie=? WHERE iduser=?',
                [tipo_vivienda, uso_vivienda, sistema_actual, zonas, presupuesto, prioridad, superficie, req.clienteId]
            );
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: e.message }); }
    }

    app.put('/clientes/api/me/vivienda', requireAuth, handleUpdateVivienda);
    app.put('/api/me/vivienda', requireAuth, handleUpdateVivienda);
}

module.exports = { setupClientesRoutes };

