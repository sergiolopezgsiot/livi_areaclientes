require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const path = require('path');
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { setupClientesRoutes } = require('./clientes-server');
const { setupAdminDataRoutes } = require('./admindata-server');

const s3Client = new S3Client({
    region: process.env.AWS_REGION || 'us-east-1'
});
const BUCKET_MEDIA = process.env.AWS_BUCKET_MEDIA || 'smarthome-media';

const app = express();
const PORT = process.env.PORT || 3000;

// MySQL connection (same configuration as livi_landing)
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test DB connection and auto-migration
pool.getConnection()
    .then(async (connection) => {
        console.log('Conectado a la base de datos mysql en AWS de GlobalSmart');
        try {
            const [rows] = await connection.query(
                `SELECT COUNT(*) AS cnt FROM INFORMATION_SCHEMA.COLUMNS
                 WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'registros' AND COLUMN_NAME = 'password_hash'`,
                [process.env.DB_NAME]
            );
            if (rows[0].cnt === 0) {
                await connection.query('ALTER TABLE registros ADD COLUMN password_hash VARCHAR(255) NULL');
                console.log('Migración aplicada: registros.password_hash creada');
            }
        } catch (migrationErr) {
            console.error('Error running auto-migration', migrationErr);
        } finally {
            connection.release();
        }
    })
    .catch(err => {
        console.error('Error acquiring client', err.stack);
    });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve private images from S3 via redirect to presigned URL
app.get('/uploads/:filename', async (req, res) => {
    try {
        const command = new GetObjectCommand({
            Bucket: BUCKET_MEDIA,
            Key: `uploads/${req.params.filename}`
        });
        const url = await getSignedUrl(s3Client, command, { expiresIn: 3600 });
        res.redirect(url);
    } catch (error) {
        console.error('Error generating presigned URL:', error);
        res.status(404).send('Not found');
    }
});

// Fetch dynamic configurador data (used by the clientes area for houseTypes and priorities)
app.get('/api/configurador-data', async (req, res) => {
    try {
        const [devicesRows] = await pool.query('SELECT * FROM devices');
        const [groupsRows] = await pool.query('SELECT * FROM device_groups');
        const [prioritiesRows] = await pool.query('SELECT * FROM priorities');
        const [houseTypesRows] = await pool.query('SELECT * FROM house_types');

        const parsedDevices = devicesRows.map(d => {
            let parsedTags = d.tags;
            if (typeof d.tags === 'string') {
                try {
                    parsedTags = JSON.parse(d.tags);
                } catch (e) {
                    parsedTags = [d.tags];
                }
            }
            return { ...d, tags: parsedTags };
        });

        res.status(200).json({
            success: true,
            devices: parsedDevices,
            groups: groupsRows,
            priorities: prioritiesRows,
            houseTypes: houseTypesRows
        });
    } catch (error) {
        console.error('Error fetching configurador data:', error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});

// Clientes routes (mounted at / and /clientes)
setupClientesRoutes(app, pool);

// Admin Data CRUD routes (mounted at /admindata and /clientes/admindata)
setupAdminDataRoutes(app, pool);

// Serve static files from root directory
app.use(express.static(__dirname));

app.listen(PORT, '0.0.0.0', () => {
    console.log(`LIVI Clientes server running on http://0.0.0.0:${PORT}/`);
});

