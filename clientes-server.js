const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

// In-memory token store for the clientes area
const clienteTokens = new Map(); // token -> iduser
const passwordResetTokens = new Map(); // token -> { iduser, email, expiresAt }
const RESET_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour

function createSmtpTransporter() {
    const host = process.env.SMTP_HOST;
    const port = Number(process.env.SMTP_PORT || 587);
    const secure = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || port === 465;
    const user = process.env.SMTP_USER || 'info@smartlivi.es';
    const pass = process.env.SMTP_PASS;

    if (!host || !pass) {
        return null;
    }

    return nodemailer.createTransport({
        host,
        port,
        secure,
        auth: { user, pass }
    });
}

function buildResetEmailHtml(nombre, resetUrl) {
    const greeting = nombre ? `Hola <strong>${nombre}</strong>,` : 'Hola,';
    return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Restaurar contraseña · Livi</title>
</head>
<body style="margin:0; padding:0; background-color:#f4f5f7; font-family: Arial, sans-serif; color:#222222;">
  <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color:#f4f5f7;">
    <tr>
      <td align="center" style="padding: 30px 10px;">
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width:600px; background-color:#ffffff; border-radius:8px; overflow:hidden; text-align:left;">
          <tr>
            <td style="padding:30px 30px 20px 30px; text-align:center; border-bottom:1px solid #eeeeee;">
              <a href="https://www.smartlivi.es" style="text-decoration:none;">
                <img src="https://smartlivi.es/assets/logolivi1.png" width="120" alt="Livi" style="width:120px; max-width:100%; height:auto; border:none; display:block; margin:0 auto;">
              </a>
            </td>
          </tr>
          <tr>
            <td style="padding:30px; font-size:14px; line-height:22px; color:#222222;">
              <h1 style="margin:0 0 16px 0; font-size:22px; line-height:28px; font-weight:bold; color:#1d1d1f;">
                Restaurar tu contraseña de Livi
              </h1>
              <p style="margin:0 0 14px 0;">${greeting}</p>
              <p style="margin:0 0 20px 0;">
                Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en el Área de Clientes de <strong>Livi</strong>.
                Haz clic en el siguiente botón para elegir una nueva contraseña (este enlace caduca en 1 hora):
              </p>
              <table role="presentation" border="0" cellspacing="0" cellpadding="0" style="margin: 24px 0;">
                <tr>
                  <td align="center" style="border-radius:44px; background-color:#0605fe;">
                    <a href="${resetUrl}" target="_blank" style="font-size:14px; font-family:Arial, sans-serif; color:#ffffff; text-decoration:none; padding:12px 24px; border-radius:44px; border:1px solid #0605fe; display:inline-block; font-weight:bold;">
                      Restaurar contraseña
                    </a>
                  </td>
                </tr>
              </table>
              <p style="margin:0 0 12px 0; font-size:12px; color:#6e6e73;">
                Si el botón no funciona, copia y pega este enlace en tu navegador:<br>
                <a href="${resetUrl}" style="color:#0605fe; word-break:break-all;">${resetUrl}</a>
              </p>
              <p style="margin:20px 0 0 0; font-size:12px; color:#86868b;">
                Si no has solicitado este cambio, puedes ignorar este correo de forma segura.
              </p>
            </td>
          </tr>
          <tr>
            <td style="padding:20px 30px; background-color:#f9f9fb; color:#888888; font-size:11px; text-align:center; border-top:1px solid #eeeeee;">
              &copy; 2026 Global Smart IoT. Todos los derechos reservados.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

function setupClientesRoutes(app, pool, options = {}) {
    app.get('/', (req, res) => {
        res.sendFile(path.join(__dirname, 'index.html'));
    });

    app.get('/clientes', (req, res) => {
        res.sendFile(path.join(__dirname, 'index.html'));
    });

    app.get('/restaurar', (req, res) => {
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

    // ─── Password Recovery Endpoints ─────────────────────────────
    async function handleForgotPassword(req, res) {
        const email = normalizeEmail(req.body.email);
        const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!email || !emailPattern.test(email)) {
            return res.status(400).json({ success: false, error: 'Introduce un email válido' });
        }

        try {
            const [rows] = await pool.query(
                'SELECT iduser, nombre, email FROM registros WHERE email = ? LIMIT 1',
                [email]
            );

            if (rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    error: 'No existe ninguna cuenta asociada a este email.'
                });
            }

            const user = rows[0];
            const resetToken = crypto.randomBytes(32).toString('hex');
            passwordResetTokens.set(resetToken, {
                iduser: user.iduser,
                email: user.email,
                expiresAt: Date.now() + RESET_TOKEN_TTL_MS
            });

            const baseUrl = (process.env.APP_BASE_URL || `${req.protocol}://${req.get('host')}`).replace(/\/+$/, '');
            const resetUrl = `${baseUrl}/?reset_token=${resetToken}`;

            const transporter = options.transporter || createSmtpTransporter();
            if (!transporter) {
                return res.status(500).json({
                    success: false,
                    error: 'El envío de correo (SMTP) no está configurado todavía en el servidor.'
                });
            }

            const fromAddress = process.env.SMTP_FROM || `"Livi" <${process.env.SMTP_USER || 'info@smartlivi.es'}>`;
            await transporter.sendMail({
                from: fromAddress,
                to: user.email,
                subject: 'Restaurar tu contraseña · Área de Clientes Livi',
                html: buildResetEmailHtml(user.nombre, resetUrl),
                text: `Hola ${user.nombre || ''},\n\nPara restaurar tu contraseña en el Área de Clientes de Livi, abre este enlace (válido durante 1 hora):\n${resetUrl}\n\nSi no lo has solicitado, ignora este mensaje.`
            });

            return res.json({
                success: true,
                message: 'Te hemos enviado un email con las instrucciones para restaurar tu contraseña.'
            });
        } catch (error) {
            console.error('Error in /clientes/api/forgot-password:', error);
            return res.status(500).json({
                success: false,
                error: 'No se pudo enviar el correo de restauración. Revisa la configuración SMTP.'
            });
        }
    }

    app.post('/clientes/api/forgot-password', handleForgotPassword);
    app.post('/api/forgot-password', handleForgotPassword);

    function getValidResetEntry(token) {
        if (!token) return null;
        const entry = passwordResetTokens.get(token);
        if (!entry) return null;
        if (Date.now() > entry.expiresAt) {
            passwordResetTokens.delete(token);
            return null;
        }
        return entry;
    }

    function handleVerifyResetToken(req, res) {
        const token = String(req.query.token || '').trim();
        const entry = getValidResetEntry(token);
        if (!entry) {
            return res.status(400).json({
                success: false,
                error: 'El enlace de restauración no es válido o ha caducado.'
            });
        }
        return res.json({ success: true, email: entry.email });
    }

    app.get('/clientes/api/verify-reset-token', handleVerifyResetToken);
    app.get('/api/verify-reset-token', handleVerifyResetToken);

    async function handleResetPassword(req, res) {
        const { token, password, confirmPassword } = req.body;
        const entry = getValidResetEntry(String(token || '').trim());

        if (!entry) {
            return res.status(400).json({
                success: false,
                error: 'El enlace de restauración no es válido o ha caducado.'
            });
        }

        if (!password || String(password).length < 6) {
            return res.status(400).json({
                success: false,
                error: 'La contraseña debe tener al menos 6 caracteres.'
            });
        }

        if (confirmPassword !== undefined && password !== confirmPassword) {
            return res.status(400).json({
                success: false,
                error: 'Las contraseñas no coinciden.'
            });
        }

        try {
            const passwordHash = await bcrypt.hash(password, 10);
            await pool.query(
                'UPDATE registros SET password_hash = ? WHERE iduser = ?',
                [passwordHash, entry.iduser]
            );
            passwordResetTokens.delete(String(token).trim());

            return res.json({
                success: true,
                token: issueToken(entry.iduser),
                message: 'Tu contraseña se ha actualizado correctamente.'
            });
        } catch (error) {
            console.error('Error in /clientes/api/reset-password:', error);
            return res.status(500).json({
                success: false,
                error: 'Error al guardar la nueva contraseña.'
            });
        }
    }

    app.post('/clientes/api/reset-password', handleResetPassword);
    app.post('/api/reset-password', handleResetPassword);

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

