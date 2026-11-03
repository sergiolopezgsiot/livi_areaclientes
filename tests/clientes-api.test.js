const http = require('http');
const express = require('express');
const assert = require('assert');
const { setupClientesRoutes } = require('../clientes-server');

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

  console.log('clientes-api test passed');
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

