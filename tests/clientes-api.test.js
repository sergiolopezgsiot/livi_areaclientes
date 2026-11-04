const http = require('http');
const express = require('express');
const assert = require('assert');
const { setupClientesRoutes } = require('../clientes-server');
const { setupAdminDataRoutes } = require('../admindata-server');

function createFakePool() {
  return {
    query(sql, params) {
      const value = Array.isArray(params) ? params[0] : null;

      if (sql.includes('FROM registros WHERE email = ?')) {
        if (value === 'sergio@keycode.es') {
          return Promise.resolve([[{ iduser: 42, nombre: 'Sergio', email: 'sergio@keycode.es', password_hash: 'hash-should-be-removed' }]]);
        }
        return Promise.resolve([[]]);
      }

      if (sql.includes('FROM houses WHERE iduser = ?')) {
        if (value === 42) {
          return Promise.resolve([[{ id: 7, iduser: 42, tipo_vivienda: 'Piso', presupuesto: 15000 }]]);
        }
        return Promise.resolve([[]]);
      }

      if (sql.includes('FROM house_devices') && sql.includes('JOIN devices')) {
        if (value === 7) {
          return Promise.resolve([[
            { house_id: 7, device_id: 11, cantidad: 2, eleccion: 'base', label: 'Termostato', price: 120, pricediscount: 100, image_url: 'https://example.com/t.jpg' },
            { house_id: 7, device_id: 12, cantidad: 1, eleccion: 'plus', label: 'Cámara', price: 200, pricediscount: 180, image_url: 'https://example.com/c.jpg' }
          ]]);
        }
        return Promise.resolve([[]]);
      }

      if (sql === 'SHOW TABLES') {
        return Promise.resolve([[{ Tables_in_db: 'registros' }, { Tables_in_db: 'devices' }]]);
      }

      if (sql.includes('SHOW COLUMNS FROM `registros`')) {
        return Promise.resolve([[
          { Field: 'iduser', Type: 'int(11)', Null: 'NO', Key: 'PRI', Default: null, Extra: 'auto_increment' },
          { Field: 'nombre', Type: 'varchar(255)', Null: 'NO', Key: '', Default: null, Extra: '' },
          { Field: 'email', Type: 'varchar(255)', Null: 'NO', Key: '', Default: null, Extra: '' },
          { Field: 'password_hash', Type: 'varchar(255)', Null: 'YES', Key: '', Default: null, Extra: '' }
        ]]);
      }

      if (sql.includes('SHOW COLUMNS FROM `devices`')) {
        return Promise.resolve([[
          { Field: 'id', Type: 'varchar(64)', Null: 'NO', Key: 'PRI', Default: null, Extra: '' },
          { Field: 'label', Type: 'varchar(255)', Null: 'NO', Key: '', Default: null, Extra: '' }
        ]]);
      }

      if (sql.includes('SELECT COUNT(*) AS cnt FROM') || sql.includes('SELECT COUNT(*) AS total FROM')) {
        return Promise.resolve([[{ cnt: 1, total: 1 }]]);
      }

      if (sql.startsWith('SELECT * FROM `registros`')) {
        return Promise.resolve([[{ iduser: 42, nombre: 'Sergio', email: 'sergio@keycode.es', password_hash: '$2b$10$xxx' }]]);
      }

      if (sql.startsWith('INSERT INTO `registros`')) {
        return Promise.resolve([{ insertId: 99, affectedRows: 1 }]);
      }

      if (sql.startsWith('UPDATE `registros`')) {
        return Promise.resolve([{ affectedRows: 1 }]);
      }

      if (sql.startsWith('DELETE FROM `registros`')) {
        return Promise.resolve([{ affectedRows: 1 }]);
      }

      return Promise.resolve([[]]);
    }
  };
}

function requestJson(app, pathName, method = 'GET', headers = {}, body) {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const port = server.address().port;
      const payload = body ? JSON.stringify(body) : null;
      const req = http.request({
        hostname: '127.0.0.1',
        port,
        path: pathName,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...headers,
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          try {
            const response = data ? JSON.parse(data) : {};
            server.close();
            resolve({ status: res.statusCode, body: response });
          } catch (error) {
            server.close();
            reject(new Error(`Respuesta no JSON en ${pathName}: ${data.slice(0, 200)}`));
          }
        });
      });

      req.on('error', (err) => {
        server.close();
        reject(err);
      });

      if (payload) req.write(payload);
      req.end();
    });
  });
}

(async () => {
  process.env.CLIENTES_API_TOKEN = 'test-token';
  const app = express();
  app.use(express.json());
  setupClientesRoutes(app, createFakePool());
  setupAdminDataRoutes(app, createFakePool());

  const missingToken = await requestJson(app, '/api/cliente?email=sergio@keycode.es');
  assert.strictEqual(missingToken.status, 401, 'Debe requerir bearer token');

  const validResponse = await requestJson(app, '/api/cliente?email=sergio@keycode.es', 'GET', {
    Authorization: 'Bearer test-token'
  });

  assert.strictEqual(validResponse.status, 200, 'Debe responder 200 con token válido');
  assert.strictEqual(validResponse.body.cliente.email, 'sergio@keycode.es');
  assert.strictEqual(validResponse.body.house.id, 7);
  assert.strictEqual(validResponse.body.devices.length, 2);
  assert.ok(!('password_hash' in validResponse.body.cliente), 'No debe devolver password_hash');

  // Test AdminData Auth & CRUD
  const badLogin = await requestJson(app, '/admindata/api/login', 'POST', {}, {
    username: 'admin',
    password: 'wrong'
  });
  assert.strictEqual(badLogin.status, 401, 'Debe rechazar clave incorrecta en admindata');

  const okLogin = await requestJson(app, '/admindata/api/login', 'POST', {}, {
    username: 'admin',
    password: 'Global2026!'
  });
  assert.strictEqual(okLogin.status, 200, 'Debe permitir login admin con Global2026!');
  assert.ok(okLogin.body.token, 'Debe devolver token de admin');

  const adminHeaders = { Authorization: `Bearer ${okLogin.body.token}` };

  const tablesRes = await requestJson(app, '/admindata/api/tables', 'GET', adminHeaders);
  assert.strictEqual(tablesRes.status, 200);
  assert.strictEqual(tablesRes.body.tables.length, 2);

  const rowsRes = await requestJson(app, '/admindata/api/tables/registros', 'GET', adminHeaders);
  assert.strictEqual(rowsRes.status, 200);
  assert.strictEqual(rowsRes.body.rows.length, 1);

  const createRes = await requestJson(app, '/admindata/api/tables/registros', 'POST', adminHeaders, {
    data: { nombre: 'Nuevo', email: 'nuevo@livi.es', _new_password: 'secret' }
  });
  assert.strictEqual(createRes.status, 201);
  assert.strictEqual(createRes.body.insertId, 99);

  const updateRes = await requestJson(app, '/admindata/api/tables/registros', 'PUT', adminHeaders, {
    pk: { iduser: 42 },
    data: { nombre: 'Sergio Editado' }
  });
  assert.strictEqual(updateRes.status, 200);
  assert.strictEqual(updateRes.body.affectedRows, 1);

  const deleteRes = await requestJson(app, '/admindata/api/tables/registros', 'DELETE', adminHeaders, {
    pk: { iduser: 42 }
  });
  assert.strictEqual(deleteRes.status, 200);
  assert.strictEqual(deleteRes.body.affectedRows, 1);

  console.log('clientes-api and admindata CRUD tests passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
