// server.js

const https = require('https');
const http = require('http');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const util = require('util');
const exec = util.promisify(require('child_process').exec);
const { spawn } = require('child_process');
const path = require('path');
const app = express();
const multer = require("multer");
const port = 443; // Port HTTPS
const cookieParser = require('cookie-parser');
const winston = require('winston');
const validator = require('validator');
const csurf = require('csurf');
const nodemailer = require('nodemailer');

require('dotenv').config(); // Carregar variables de configuració des d'un fitxer .env
const SECRET_KEY = process.env.JWT_SECRET; // Clau secreta per a signar els tokens JWT
const SECRET_KEY_REFRESH = process.env.JWT_SECRET_REFRESH; // Clau secreta per a signar els tokens JWT

const options = { // Certificats SSL per HTTPS
  key: fs.readFileSync(process.env.SSL_KEY_PATH),
  cert: fs.readFileSync(process.env.SSL_CERT_PATH)
};

const pool = new Pool({ // Connexió a la base de dades PostgreSQL
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
  idleTimeoutMillis: 2000 // Temps màxim d'inactivitat de la connexió abans de tancar-la
});

// Configurar multer para almacenamiento temporal
const upload = multer({
  dest: "/srv/facturacio/tmp", // Directorio temporal
});

function generarPlaceholders(arrays, prefijo = '') {
  return arrays.flat().map(texto =>
    `#${texto.replace(/\s+/g, '_')}${prefijo ? '_' + prefijo : ''}`
  );
}

app.use(bodyParser.json()); // Middleware necessari per gestionar el JSON i permetre CORS
app.use(cors()); // Middleware necessari per permetre CORS
app.use(express.static('/srv/facturacio/public')); // Serveix arxius estàtics des de la carpeta pública
app.use('/pdf', express.static('/srv/facturacio/data')); // Serveix arxius PDF des de la carpeta de dades
app.use(cookieParser());
app.use(express.json());

// Configurar CSRF usando cookies
const csrfProtection = csurf({ cookie: true });

app.use(csrfProtection);

// Middleware para manejar errores de CSRF
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).send('CSRF Token inválido o faltante');
  }
  next(err);
});

// Ruta para obtener el token CSRF y enviarlo al frontend
app.get('/get-csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

const verifyAuth = async (req, res) => {
  try {
    const accessToken = req.cookies.auth_token;
    const refreshToken = req.cookies.refresh_token;
    const sessionCookie = req.cookies.session;
    // Si no hay ninguna cookie de sesión, se deniega el acceso
    if (!sessionCookie) {
      //console.log('No hi ha cap sessió activa');
      return [null, false];
    }
    // Si no hay ningún token, se deniega el acceso
    if (!accessToken && !refreshToken) {
      //console.log('Ningún token proporcionado');
      //return res.status(401).json({ mensaje: 'Ningún token proporcionado' });
      return [null, false];
    }
    // Intentar verificar el token de acceso
    if (accessToken) {
      try {
        //console.log('Verificando el token de acceso...');
        const decoded = jwt.verify(accessToken, SECRET_KEY);
        req.user = decoded; // Almacenar el usuario en la solicitud
        //console.log('Token de acceso válido');
        //return next();
        return [decoded.email, false];
      } catch (error) {
        //console.log('Error en el token de acceso:', error.message);
        // Si el error no es por expiración, se rechaza directamente
        if (error.name !== 'TokenExpiredError') {
          //return res.status(401).json({ mensaje: 'Token no válido' });
          return [null, false];
        }
      }
    }
    // Intentar renovar el token si hay un refresh token disponible
    if (refreshToken) {
      try {
        //console.log('Intentando verificar el token de refresco...');
        const decodedRefresh = jwt.verify(refreshToken, SECRET_KEY_REFRESH);
        const email = decodedRefresh.email;
        // Verificar si el refresh token existe en la base de datos
        const result = await pool.query(
          `SELECT * FROM usuaris.sessions 
           WHERE email = $1 
           AND refresh_token = $2 
           AND data_creacio > NOW() - INTERVAL '7 days'`,
          [email, refreshToken]
        );
        // Si no existe en la BD o no coincide, se rechaza la solicitud
        if (result.rows.length === 0) {
          //console.log('Refresh token no válido o sesión no encontrada');
          res.clearCookie('auth_token', {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
          });
          res.clearCookie('refresh_token', {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict',
          });
          res.clearCookie('session', {
            secure: true,     // Solo se envía a través de HTTPS
            sameSite: 'Strict', // Protege contra CSRF
          });
          //return res.status(401).json({ mensaje: 'Refresh token inválido' });
          return [null, true];
        }
        //console.log('Generando nuevos tokens...');
        // Generar el token JWT
        const newAccessToken = jwt.sign({ email }, SECRET_KEY, { expiresIn: '15m' });
        // Generar refreshtoken
        const newRefreshToken = jwt.sign({ email }, SECRET_KEY_REFRESH, { expiresIn: '7d' });
        // Guardar el refresh token en la base de datos
        const updateResult = await pool.query(
          'UPDATE usuaris.sessions SET refresh_token = $1, data_creacio = NOW() WHERE refresh_token = $2 AND email = $3',
          [newRefreshToken, refreshToken, email]
        );
        if (updateResult.rowCount === 0) {
          //console.log('Error al actualizar el refresh token en la base de datos.');
          return [null, true];
        }
        // Configurar la cookie segura
        res.cookie('auth_token', newAccessToken, {
          httpOnly: true,   // No accesible desde JavaScript
          secure: true,     // Solo se envía a través de HTTPS
          sameSite: 'Strict', // Protege contra CSRF
          maxAge: 900000,  // 15 mins
        });
        res.cookie('refresh_token', newRefreshToken, {
          httpOnly: true,   // No accesible desde JavaScript
          secure: true,     // Solo se envía a través de HTTPS
          sameSite: 'Strict', // Protege contra CSRF
          maxAge: 604800000,  // 7 dies
        });
        res.cookie('session', 'true', {
          secure: true,     // Solo se envía a través de HTTPS
          sameSite: 'Strict', // Protege contra CSRF
        });
        //req.user = { email }; // Guardar el usuario en req.user
        //console.log('Tokens renovados con éxito');
        //return next();
        return [email, false];
      } catch (refreshError) {
        //console.log('Error al verificar el refresh token:', refreshError.message);
        await pool.query(
          'DELETE FROM usuaris.sessions WHERE email = $1 AND refresh_token = $2',
          [email, refreshToken]
        );
        res.clearCookie('auth_token', {
          httpOnly: true,
          secure: true,
          sameSite: 'Strict',
        });
        res.clearCookie('refresh_token', {
          httpOnly: true,
          secure: true,
          sameSite: 'Strict',
        });
        res.clearCookie('session', {
          secure: true,     // Solo se envía a través de HTTPS
          sameSite: 'Strict', // Protege contra CSRF
        });
        //return res.status(401).json({ mensaje: 'Error al renovar el token, inicie sesión nuevamente' });
        return [null, true];
      }
    }
    // Si no hay refresh token o ha fallado, se deniega el acceso
    //return res.status(401).json({ mensaje: 'Token no válido o expirado' });
    return [null, false];
  } catch (error) {
    //console.error('Error en el middleware de autenticación:', error);
    //return res.status(401).json({ mensaje: 'Error interno del servidor' });
    return [null, false];
  }
}

const authMiddleware = async (req, res, next) => {
  console.log('Ruta a pedir:', req.url);
  const [user, caducada] = await verifyAuth(req, res);
  if (user) {
    console.log('Autenticado:', user);
    req.user = user;
    return next();
  } else {
    console.log('No autenticado');
    if (caducada === true) {
      return res.status(408).json({ mensaje: 'Sessió caducada' });
    } else {
      return res.status(401).json({ mensaje: 'No autenticado' });
    }
  }
};

updateEstatFactura = async (Sèrie, Número, userSchema) => {
  if (!Sèrie || !Número || !userSchema) {
    throw new Error('Sèrie, Número o userSchema no proporcionats per actualitzar l\'estat de la factura');
  }
  try {
    const [nombre_clients, nombre_linies, nombre_pagament] = await Promise.all([
      pool.query(`
        SELECT COUNT(*) 
        FROM "${userSchema}".dades_factures 
        WHERE "Sèrie" = $1 AND "Número" = $2;
      `, [Sèrie, Número]),
      pool.query(`
        SELECT COUNT(*) 
        FROM "${userSchema}".dades_linia_factura 
        WHERE "Sèrie factura" = $1 AND "Número factura" = $2;
      `, [Sèrie, Número]),
      pool.query(`
        SELECT COUNT(*) 
        FROM "${userSchema}".dades_pagament_factura 
        WHERE "Sèrie factura" = $1 AND "Número factura" = $2;
      `, [Sèrie, Número])
    ]);
    let estat_factura = "Esborrany";
    if (
      parseInt(nombre_clients.rows[0].count) > 0 &&
      parseInt(nombre_linies.rows[0].count) > 0 &&
      parseInt(nombre_pagament.rows[0].count) > 0
    ) {
      estat_factura = "Preparada";
    }
    await pool.query(`
      UPDATE "${userSchema}".dades_factures
      SET "Estat" = $1
      WHERE "Sèrie" = $2 AND "Número" = $3;
    `, [estat_factura, Sèrie, Número]);
    //console.log('--------------------------------Estat de la factura actualitzat a:', estat_factura);
  } catch (error) {
    winston.error('Error en updateEstatFactura:', error);
    throw new Error('Error en el servidor al actualitzar estat de la factura');
  }
};

app.use('/private', authMiddleware, express.static('/srv/facturacio/private'));

// Configuración para servir archivos estáticos desde la carpeta "web"
app.use('/pdfjs', express.static(path.join(__dirname, 'web'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.mjs')) {
      res.setHeader('Content-Type', 'application/javascript');
    } else if (filePath.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
    } else if (filePath.endsWith('.html')) {
      res.setHeader('Content-Type', 'text/html');
    }
  }
}));

// Configuración adicional para servir archivos desde la carpeta "build"
app.use('/build', express.static(path.join(__dirname, 'build'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.mjs')) {
      res.setHeader('Content-Type', 'application/javascript');
    }
  }
}));

app.post('/logged', async (req, res) => {
  console.log('logged');
  const [user, caducada] = await verifyAuth(req, res);
  if (user) {
    req.user = user; // Esto solo afecta el request actual, no se mantiene entre peticiones
    res.status(200).json({ logged: true, user }); // Enviar datos del usuario
  } else {
    res.status(401).json({ logged: false });
  }
});

/*
app.get('/private/*', async (req, res) => {
  console.log('Ruta a pedir:', req.url);
    const requestedFile = path.join('/srv/facturacio/private', req.path.replace('/private/', ''));
    try {
    if (fs.existsSync(requestedFile)) {
      res.sendFile(requestedFile);
    } else {
      res.status(404).send('Archivo no encontrado');
    }
  } catch (error) {
    winston.error('Error al procesar los archivos HTML:', error);
    res.status(500).send('Error interno del servidor');
  }
});
*/

app.get('/', (req, res) => { // Servir el login
  console.log('Servint log_in.html');
  const filePath = '/srv/facturacio/public/log_in.html'
  if (fs.existsSync(filePath)) { // Comprovem si el fitxer existeix abans de servir-lo
    res.sendFile(filePath);
  } else {
    winston.error('Error servint log_in.html, no existeix a la ruta especificada.');
    res.status(404).send('Log_in no trobat');
  }
});

// Ruta protegida con CSRF para logout
app.post('/logout', async (req, res) => {
  console.log('Tancant la sessió');
  try {
    const refreshToken = req.cookies.refresh_token;
    if (refreshToken) {
      const decodedRefresh = jwt.verify(refreshToken, SECRET_KEY_REFRESH);
      const email = decodedRefresh.email;
      await pool.query(
        'DELETE FROM usuaris.sessions WHERE email = $1 AND refresh_token = $2',
        [email, refreshToken]
      );
    }
    res.clearCookie('auth_token', {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
    });
    res.clearCookie('refresh_token', {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
    });
    res.clearCookie('session', {
      secure: true,     // Solo se envía a través de HTTPS
      sameSite: 'Strict', // Protege contra CSRF
    });
    res.status(200).send('Sesión cerrada correctamente');
  } catch (error) {
    //console.error('Error al cerrar la sesión:', error);
    res.status(500).send('Error al cerrar la sesión');
  }
});

app.post('/log_in', async (req, res) => {
  let { email, contrasenya } = req.body;
  if (email && typeof email === 'string') {
    email = email.trim();
  }
  if (!email || !contrasenya) { // Comprovar si s'han proporcionat les dades necessàries
    return res.status(400).json({ missatge: 'Si us plau, completeu tots els camps' });
  }
  try {
    const result = await pool.query('SELECT * FROM usuaris.usuaris WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      const usuariDb = result.rows[0];
      const passwordValidat = await bcrypt.compare(contrasenya, usuariDb.contrasenya);
      if (passwordValidat) {
        // Generar el token JWT
        const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '15m' });
        // Generar refreshtoken
        const refreshToken = jwt.sign({ email }, SECRET_KEY_REFRESH, { expiresIn: '7d' });
        // 🔹 Guardar el refresh token en la base de datos
        await pool.query(
          'INSERT INTO usuaris.sessions (email, refresh_token) VALUES ($1, $2)',
          [email, refreshToken]
        );
        // Configurar la cookie segura
        res.cookie('auth_token', token, {
          httpOnly: true,   // No accesible desde JavaScript
          secure: true,     // Solo se envía a través de HTTPS
          sameSite: 'Strict', // Protege contra CSRF
          maxAge: 900000,  // 15 mins
        });
        res.cookie('refresh_token', refreshToken, {
          httpOnly: true,   // No accesible desde JavaScript
          secure: true,     // Solo se envía a través de HTTPS
          sameSite: 'Strict', // Protege contra CSRF
          maxAge: 604800000,  // 7 dies
        });
        res.cookie('session', 'true', {
          secure: true,     // Solo se envía a través de HTTPS
          sameSite: 'Strict', // Protege contra CSRF
        });
        res.status(200).json({ missatge: 'Login correcte' });
      } else {
        res.status(401).json({ missatge: 'Contrasenya incorrecta' });
      }
    } else {
      res.status(404).json({ missatge: 'Usuari no trobat' });
    }
  } catch (error) {
    winston.error('Error en /log_in:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.post('/sign_in', async (req, res) => { // Ruta de registre d'usuari
  let { email, contrasenya } = req.body;
  if (email && typeof email === 'string') {
    email = email.trim();
  }
  if (email.length > 128) {
    return res.status(400).json({ missatge: 'El correu electrònic és massa llarg' });
  }
  if (contrasenya.length > 128) {
    return res.status(400).json({ missatge: 'La contrasenya és massa llarga' });
  }
  if (!validator.isEmail(email)) {
    return res.status(400).json({ missatge: 'El correu electrònic no és vàlid' });
  }
  if (!validator.isStrongPassword(contrasenya, {
    minLength: 8,
    minLowercase: 1,
    minUppercase: 1,
    minNumbers: 1,
    minSymbols: 1,
  })) {
    return res.status(400).json({ missatge: 'La contrasenya no és vàlida' });
  }
  try {
    const userCheck = await pool.query('SELECT * FROM usuaris.usuaris WHERE email = $1', [email]); // Mira si ja un usuari amb aquest email
    if (userCheck.rows.length > 0) { // Comprovem si l'usuari ja existeix
      return res.status(400).json({ missatge: 'Aquest correu ja està registrat' });
    }
    const hashedPassword = await bcrypt.hash(contrasenya, 10); // Encripta la contrasenya abans de guardar-la
    const userSchema = encodeURIComponent(email); // Substiteix els caràcters prohibits segons URI per crear un nom únic
    const userPath = `/srv/facturacio/data/${userSchema}`; // Assigna els directoris per al nou usuari
    try {
      if (!fs.existsSync(userPath)) { // Crea els directoris necessaris si no existeixen
        fs.mkdirSync(userPath, { recursive: true });
        fs.mkdirSync(`${userPath}/factures`);
        fs.mkdirSync(`${userPath}/dades`);
      }
    } catch (error) {
      winston.error('Error al crear directoris:', error);
      return res.status(500).json({ missatge: `Error al configurar l'usuari` });
    }
    await pool.query('BEGIN'); // Inicia la transacción
    await pool.query( // Insereix el nou usuari a la base de dades
      'INSERT INTO usuaris.usuaris (email, contrasenya, path) VALUES ($1, $2, $3)', [email, hashedPassword, userPath]
    );
    await pool.query(`CREATE SCHEMA IF NOT EXISTS "${userSchema}"`); // Creem l'esquema per a l'usuari
    await pool.query(`
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_personals (
          "Nom i cognoms o raó social" TEXT NOT NULL,
          "Número d'identificació fiscal" VARCHAR(15) NOT NULL,
          "Tipus de persona" TEXT NOT NULL,
          "Tipus de residència" TEXT NOT NULL,
          "Direcció" TEXT NOT NULL,
          "Codi Postal" VARCHAR(10) NOT NULL,
          "Població" TEXT NOT NULL,
          "Província" TEXT NOT NULL,
          "País" TEXT NOT NULL,
          FOREIGN KEY ("Tipus de persona") REFERENCES persona.persona("persona") ON UPDATE CASCADE ON DELETE RESTRICT,
          FOREIGN KEY ("Tipus de residència") REFERENCES residencia.residencia("residencia") ON UPDATE CASCADE ON DELETE RESTRICT,
          FOREIGN KEY ("País") REFERENCES pais.pais("pais") ON UPDATE CASCADE ON DELETE RESTRICT
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_personals_opcionals (
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_pagament (
          "id" INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          "Mitjà de pagament" TEXT NOT NULL,
          "Compte d'abonament" TEXT,
          "BIC/SWIFT" TEXT,
          "Informació addicional" TEXT,
          FOREIGN KEY ("Mitjà de pagament") REFERENCES pagament.pagament(mitja_pagament) ON UPDATE CASCADE ON DELETE RESTRICT
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_clients (
          "Nom i cognoms o raó social" TEXT NOT NULL UNIQUE,
          "Número d'identificació fiscal" VARCHAR(15) NOT NULL primary key,
          "Tipus de persona" TEXT NOT NULL,
          "Tipus de residència" TEXT NOT NULL,
          "Direcció" TEXT NOT NULL,
          "Codi Postal" VARCHAR(10) NOT NULL,
          "Població" TEXT NOT NULL,
          "Província" TEXT NOT NULL,
          "País" TEXT NOT NULL,
          "Codi de l'òrgan gestor" VARCHAR(20),
          "Codi de la unitat tramitadora" VARCHAR(20),
          "Codi de l'oficina comptable" VARCHAR(20),
          FOREIGN KEY ("Tipus de persona") REFERENCES persona.persona("persona") ON UPDATE CASCADE ON DELETE RESTRICT,
          FOREIGN KEY ("Tipus de residència") REFERENCES residencia.residencia("residencia") ON UPDATE CASCADE ON DELETE RESTRICT,
          FOREIGN KEY ("País") REFERENCES pais.pais("pais") ON UPDATE CASCADE ON DELETE RESTRICT
        ); 
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_clients_opcionals (
          "Número d'identificació fiscal" VARCHAR(15) NOT NULL primary key,
          "Correu electrònic" TEXT,
          FOREIGN KEY ("Número d'identificació fiscal") REFERENCES "${userSchema}".dades_clients("Número d'identificació fiscal") ON UPDATE CASCADE ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_productes (
          "Codi" VARCHAR(15) PRIMARY KEY, 
          "Descripció" TEXT NOT NULL UNIQUE,
          "Unitats" VARCHAR(20) NOT NULL,
          "Preu unitari" DECIMAL(10,2) NOT NULL,
          FOREIGN KEY ("Unitats") REFERENCES unitats.unitats("unitat") ON UPDATE CASCADE ON DELETE RESTRICT
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_productes_opcionals (
          "Codi" VARCHAR(15) PRIMARY KEY,
          FOREIGN KEY ("Codi") REFERENCES "${userSchema}".dades_productes("Codi") ON UPDATE CASCADE ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_series (
          "Codi" VARCHAR(15) PRIMARY KEY, 
          "Descripció" TEXT NOT NULL,
          "Prefix" VARCHAR(15),
          "Sufix" VARCHAR(15),
          "Número actual" INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_factures (
          "Sèrie" VARCHAR(15) NOT NULL,
          "Número" INTEGER NOT NULL, 
          "Data" DATE NOT NULL,
          "Estat" TEXT NOT NULL,
          "Client" VARCHAR(15),
          "id" INTEGER GENERATED ALWAYS AS IDENTITY UNIQUE,
          FOREIGN KEY ("Sèrie") REFERENCES "${userSchema}".dades_series("Codi") ON UPDATE CASCADE ON DELETE RESTRICT,
          FOREIGN KEY ("Client") REFERENCES "${userSchema}".dades_clients("Número d'identificació fiscal") ON UPDATE CASCADE ON DELETE CASCADE,
          PRIMARY KEY ("Sèrie", "Número")
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_factures_opcionals (
          "Sèrie" VARCHAR(15) NOT NULL,
          "Número" INTEGER NOT NULL, 
          FOREIGN KEY ("Sèrie", "Número") REFERENCES "${userSchema}".dades_factures("Sèrie", "Número") ON UPDATE CASCADE ON DELETE CASCADE,
          PRIMARY KEY ("Sèrie", "Número")
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_linia_factura (
          "Sèrie factura" VARCHAR(15) NOT NULL,
          "Número factura" INTEGER NOT NULL,
          "Codi producte" VARCHAR(15) NOT NULL,
          "Quantitat" DECIMAL(15,6) NOT NULL CHECK ("Quantitat" > 0),
          "Descripció" TEXT NOT NULL,
          "Data operació" DATE NOT NULL,
          "Preu unitari" DECIMAL(10,2) NOT NULL,
          "id" INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          FOREIGN KEY ("Sèrie factura", "Número factura") REFERENCES "${userSchema}".dades_factures("Sèrie", "Número") ON UPDATE CASCADE ON DELETE CASCADE,
          FOREIGN KEY ("Codi producte") REFERENCES "${userSchema}".dades_productes("Codi") ON UPDATE CASCADE ON DELETE RESTRICT
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_linia_factura_opcionals (
          "id" INTEGER PRIMARY KEY,
          FOREIGN KEY ("id") REFERENCES "${userSchema}".dades_linia_factura("id") ON UPDATE CASCADE ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".impost_linia_factura (
          "linia factura" INTEGER NOT NULL,
          "impost" VARCHAR(15) NOT NULL,
          "Base imposable" DECIMAL(15,2) NOT NULL,
          "Tipus impositiu" DECIMAL(5,2),
          "id" INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          FOREIGN KEY ("linia factura") REFERENCES "${userSchema}".dades_linia_factura("id") ON UPDATE CASCADE ON DELETE CASCADE,
          FOREIGN KEY ("impost") REFERENCES impostos.impostos("Codi") ON UPDATE CASCADE ON DELETE CASCADE,
          UNIQUE ("linia factura", "impost", "Tipus impositiu")
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".descompte_linia_factura (
          "linia factura" INTEGER NOT NULL,
          "Descripció" TEXT,
          "Base descompte" DECIMAL(15,2) NOT NULL,
          "Percentatge" DECIMAL(5,2),
          "id" INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          FOREIGN KEY ("linia factura") REFERENCES "${userSchema}".dades_linia_factura("id") ON UPDATE CASCADE ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".impost_producte (
          "codi producte" VARCHAR(15) NOT NULL,
          "impost" VARCHAR(15) NOT NULL,
          "Base imposable" DECIMAL(15,2),
          "Tipus impositiu" DECIMAL(5,2),
          "id" INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          FOREIGN KEY ("codi producte") REFERENCES "${userSchema}".dades_productes("Codi") ON UPDATE CASCADE ON DELETE CASCADE,
          FOREIGN KEY ("impost") REFERENCES impostos.impostos("Codi") ON UPDATE CASCADE ON DELETE CASCADE,
          UNIQUE ("codi producte", "impost", "Tipus impositiu")
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".mitja_transport_nou (
          "Data primera entrada servei" DATE NOT NULL,
          "Distància fins entrega" DECIMAL(15,6),
          "Hores fins entrega" DECIMAL(15,6),
          "linia factura" INTEGER NOT NULL,
          FOREIGN KEY ("linia factura") REFERENCES "${userSchema}".dades_linia_factura("id") ON UPDATE CASCADE ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".pagaments_anticipats (
          "Sèrie factura" VARCHAR(15) NOT NULL,
          "Número factura" INTEGER NOT NULL,
          "Data" DATE NOT NULL,
          "Import" DECIMAL(15,2) NOT NULL,
          "id" INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          FOREIGN KEY ("Sèrie factura", "Número factura") REFERENCES "${userSchema}".dades_factures("Sèrie", "Número") ON UPDATE CASCADE ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".circumstancies_factures (
          "Sèrie factura" VARCHAR(15) NOT NULL,
          "Número factura" INTEGER NOT NULL,
          "Descripció" TEXT NOT NULL,
          "id" INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          FOREIGN KEY ("Sèrie factura", "Número factura") REFERENCES "${userSchema}".dades_factures("Sèrie", "Número") ON UPDATE CASCADE ON DELETE CASCADE,
          FOREIGN KEY ("Descripció") REFERENCES circumstancies.circumstancies("descripció") ON UPDATE CASCADE ON DELETE RESTRICT,
          UNIQUE ("Sèrie factura", "Número factura", "Descripció")
        );
        CREATE TABLE IF NOT EXISTS "${userSchema}".dades_pagament_factura (
          "Sèrie factura" VARCHAR(15) NOT NULL,
          "Número factura" INTEGER NOT NULL,
          "Subtotal" VARCHAR(15) NOT NULL,
          "Total" VARCHAR(15) NOT NULL,
          "Data termini" DATE,
          "Mitjà de pagament" INTEGER,
          "id" INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          FOREIGN KEY ("Sèrie factura", "Número factura") REFERENCES "${userSchema}".dades_factures("Sèrie", "Número") ON UPDATE CASCADE ON DELETE CASCADE,
          FOREIGN KEY ("Mitjà de pagament") REFERENCES "${userSchema}".dades_pagament("id") ON UPDATE CASCADE ON DELETE RESTRICT
          );
      `);
    // Generar el token JWT
    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '15m' });
    // Generar refreshtoken
    const refreshToken = jwt.sign({ email }, SECRET_KEY_REFRESH, { expiresIn: '7d' });
    // Guardar el refresh token en la base de datos
    await pool.query(
      'INSERT INTO usuaris.sessions (email, refresh_token) VALUES ($1, $2)',
      [email, refreshToken]
    );
    // Configurar la cookie segura
    res.cookie('auth_token', token, {
      httpOnly: true,   // No accesible desde JavaScript
      secure: true,     // Solo se envía a través de HTTPS
      sameSite: 'Strict', // Protege contra CSRF
      maxAge: 900000,  // 15 mins
    });
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,   // No accesible desde JavaScript
      secure: true,     // Solo se envía a través de HTTPS
      sameSite: 'Strict', // Protege contra CSRF
      maxAge: 604800000,  // 7 dies
    });
    res.cookie('session', 'true', {
      secure: true,     // Solo se envía a través de HTTPS
      sameSite: 'Strict', // Protege contra CSRF
    });
    await pool.query('COMMIT'); // Si todo va bien, se guardan los cambios
    res.status(200).json({ missatge: 'Registre correcte' });
  } catch (error) {
    await pool.query('ROLLBACK'); // Si falla algo, deshace todo
    winston.error('Error en /signin:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

/*
// Fallback para rutas no definidas: sirve index.html
app.use((req, res) => {
  console.log('Ruta no definida:', req.url);
  const filePath = '/srv/facturacio/public/log_in.html';
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    winston.error('Error servint log_in.html, no existeix a la ruta especificada.');
    res.status(404).send('log_in.html no trobat');
  }
});
*/

/*
//Com que es tràfic intern creat pe les urls falss de navigateto cal comprovar si l'usuari està autenticat
app.get('*', authMiddleware, async (req, res) => {

  console.log('Ruta teoricamente autenticada:', req.url);

  const filePathLogIn = '/srv/facturacio/public/log_in.html';
  const filePathDashboard = '/srv/facturacio/private/dashboard.html';

  if (fs.existsSync(filePathLogIn) && fs.existsSync(filePathDashboard)) {
    try {
      // Leer el archivo base (log_in.html)
      let logInHTML = fs.readFileSync(filePathLogIn, 'utf-8');
      // Injectar CSS en el `<head>`
      logInHTML = logInHTML.replace('</head>', `<link rel="stylesheet" href="/private/dashboard.css"></head>`);
      // Leer el contenido del dashboard
      const dashboardHTML = fs.readFileSync(filePathDashboard, 'utf-8');
      // Reemplazar el contenido del `<body>` del archivo base con el dashboard
      logInHTML = logInHTML.replace(/<body>[\s\S]*<\/body>/, `<body>${dashboardHTML}</body>`);
      logInHTML = logInHTML.replace(
        /<!-- START_CONTAINER_CONTENT -->[\s\S]*?<!-- END_CONTAINER_CONTENT -->/,
        `<!-- START_CONTAINER_CONTENT -->${dashboardHTML}<!-- END_CONTAINER_CONTENT -->`
      );
      // Enviar el HTML modificado al cliente
      res.send(logInHTML);
    } catch (error) {
      winston.error('Error al procesar los archivos HTML:', error);
      res.status(500).send('Error interno del servidor');
    }
  } else {
    winston.error('Error: No se encontraron los archivos HTML requeridos.');
    res.status(404).send('Fitxers no trobats');
  }
});
*/

app.get('/dades_personals', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas de ambas tablas
    const [columnes, columnesOpcionals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_personals']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_personals_opcionals'])
    ]);
    const [dades, dadesOpcionals] = await Promise.all([
      pool.query(`
          SELECT ${columnes.rows.map(row => `"${row.column_name}"`).join(', ')}
          FROM "${userSchema}".dades_personals;
        `),
      pool.query(`
          SELECT ${columnesOpcionals.rows.map(row => `"${row.column_name}"`).join(', ')}
          FROM "${userSchema}".dades_personals_opcionals;
        `)
    ]);
    // Responder con los datos obtenidos
    res.json({
      camps: columnes.rows.map(row => row.column_name), // Nombres de columnas de dades_personals
      valors: dades.rows, // Datos de dades_personals
      camps_opcionals: columnesOpcionals.rows.map(row => row.column_name), // Nombres de columnas de dades_personals_opcionals
      valors_opcionals: dadesOpcionals.rows // Datos de dades_personals_opcionals
    });
    console.log('Dades personals enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_personals:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_clients', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas de ambas tablas
    const [columnes, columnesOpcionals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_clients']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_clients_opcionals'])
    ]);
    // Filtrar la columna conflictiva de opcionales
    const campsOpcionals = columnesOpcionals.rows
      .map(row => row.column_name)
      .filter(col => col !== "Número d'identificació fiscal");
    // Generar lista completa de columnas con prefijos de tabla correctos
    const columnsQuery = [
      ...columnes.rows.map(row => `"${userSchema}".dades_clients."${row.column_name}"`),
      ...campsOpcionals.map(col => `"${userSchema}".dades_clients_opcionals."${col}"`)
    ].join(', ');
    // Consultamos los datos con LEFT JOIN para evitar resultados vacíos
    const dades = await pool.query(`
      SELECT ${columnsQuery}
      FROM "${userSchema}".dades_clients
      LEFT JOIN "${userSchema}".dades_clients_opcionals
      ON "${userSchema}".dades_clients."Número d'identificació fiscal" = "${userSchema}".dades_clients_opcionals."Número d'identificació fiscal";
    `);
    // Responder con los datos obtenidos
    res.json({
      camps: columnes.rows.map(row => row.column_name),
      camps_opcionals: campsOpcionals,
      valors: dades.rows,
    });
    console.log('Dades de clients enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_clients:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/camps-clients', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas de ambas tablas
    const [columnes, columnesOpcionals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_clients']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_clients_opcionals'])
    ]);
    // Filtrar "Número d'identificació fiscal" de columnesOpcionals
    const campsOpcionals = columnesOpcionals.rows
      .map(row => row.column_name)
      .filter(col => col !== "Número d'identificació fiscal");
    // Responder con los datos obtenidos
    res.json({
      camps: columnes.rows.map(row => row.column_name),
      camps_opcionals: campsOpcionals
    });
    console.log('Dades de camps-clients enviades correctament');
  } catch (error) {
    winston.error('Error en /camps-clients:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.patch('/dades_personals', authMiddleware, async (req, res) => {
  console.log('PATCH /dades_personals');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { obligatoris, opcionals, eliminats, nous_valor } = req.body;
    const trimObjectValues = (obj) =>
      Object.fromEntries(
        Object.entries(obj).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value])
      );
    if (obligatoris && typeof obligatoris === 'object' && Object.keys(obligatoris).length > 0) {
      obligatoris = trimObjectValues(obligatoris);
    }
    if (opcionals && typeof opcionals === 'object' && Object.keys(opcionals).length > 0) {
      opcionals = trimObjectValues(opcionals);
    }
    if (nous_valor && typeof nous_valor === 'object' && Object.keys(nous_valor).length > 0) {
      nous_valor = trimObjectValues(nous_valor);
    }
    if (Array.isArray(eliminats) && eliminats.length > 0) {
      eliminats = eliminats.map(columna => columna.trim());
    }
    //console.log('-Obligatoris:', obligatoris);
    //console.log('-opcionals:', opcionals);
    //console.log('-eliminats:', eliminats);
    //console.log('-nous_valor:', nous_valor);
    // Actualizar datos obligatorios en la tabla `dades_personals`
    // Actualizar datos obligatorios en la tabla `dades_personals`
    //NO FUNCIONA SI NO HI HAN VALORS A ACTUALITZAR, PRIMER MIRA SI HI HAN VALORS A ACTUALITZAR
    if (obligatoris && Object.keys(obligatoris).length > 0) {
      const result = await pool.query(`SELECT 1 FROM "${userSchema}".dades_personals LIMIT 1`);
      if (result.rowCount > 0) { // UPDATE si existe
        const updates = Object.keys(obligatoris)
          .map((col, index) => `"${col}" = $${index + 1}`)
          .join(', ');
        const updateQuery = `UPDATE "${userSchema}".dades_personals SET ${updates}`;
        await pool.query(updateQuery, Object.values(obligatoris));
      } else { // INSERT si no existe
        const columns = Object.keys(obligatoris).map(col => `"${col}"`).join(', ');
        const placeholders = Object.values(obligatoris)
          .map((_, index) => `$${index + 1}`)
          .join(', ');
        const insertQuery = `INSERT INTO "${userSchema}".dades_personals (${columns}) VALUES (${placeholders})`;
        await pool.query(insertQuery, Object.values(obligatoris));
      }
      //console.log('Datos obligatorios actualizados.');
    }
    // Eliminar columnas del array `eliminats`
    if (eliminats && eliminats.length > 0) {
      const dropColumnsQuery = eliminats
        .map((columna) => `DROP COLUMN IF EXISTS "${columna}"`)
        .join(', ');
      const query = `
      ALTER TABLE "${userSchema}".dades_personals_opcionals
      ${dropColumnsQuery};
    `;
      await pool.query(query);
      //console.log('Columnas eliminadas:', eliminats);
    }
    // Modificar datos existentes en `dades_personals_opcionals`
    if (opcionals && Object.keys(opcionals).length > 0) {
      const updates = Object.entries(opcionals)
        .map(([columna], index) => `"${columna}" = $${index + 1}`)
        .join(', ')
      const query = `
        UPDATE "${userSchema}".dades_personals_opcionals
        SET ${updates};
      `;
      await pool.query(query, Object.values(opcionals));
      //console.log('Datos opcionales existentes actualizados.');
    }
    //console.log('Datos opcionales actualizados.');
    // Añadir nuevas columnas y valores desde `nous_valor`
    if (nous_valor && Object.keys(nous_valor).length > 0) {
      // Generar una sola consulta para añadir columnas
      const addColumnsQuery = Object.keys(nous_valor)
        .map((columna) => `ADD COLUMN IF NOT EXISTS "${columna}" TEXT`)
        .join(', ');
      const alterTableQuery = `
          ALTER TABLE "${userSchema}".dades_personals_opcionals
          ${addColumnsQuery};
          `;
      await pool.query(alterTableQuery);
      const result = await pool.query(`SELECT 1 FROM "${userSchema}".dades_personals_opcionals LIMIT 1`);
      if (result.rowCount > 0) { // UPDATE si existe
        const updates = Object.keys(nous_valor)
          .map((col, index) => `"${col}" = $${index + 1}`)
          .join(', ');
        const updateQuery = `UPDATE "${userSchema}".dades_personals_opcionals SET ${updates}`;
        await pool.query(updateQuery, Object.values(nous_valor));
      } else { // INSERT si no existe
        const columns = Object.keys(nous_valor).map(col => `"${col}"`).join(', ');
        const placeholders = Object.values(nous_valor)
          .map((_, index) => `$${index + 1}`)
          .join(', ');
        const insertQuery = `INSERT INTO "${userSchema}".dades_personals_opcionals (${columns}) VALUES (${placeholders})`;
        await pool.query(insertQuery, Object.values(nous_valor));
      }
      //console.log(`Columnas añadidas y valores actualizados:`, nous_valor);
    }
    return res.status(200).json({ missatge: 'Dades personals actualitzades correctament' });
  } catch (error) {
    winston.error('Error en /dades_personals (PATCH):', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.patch('/modificar_client', authMiddleware, async (req, res) => {
  console.log('PATCH /modificar_client');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { cambios, cambiosOpcionales, dniCliente } = req.body;
    const trimObjectValues = (obj) =>
      Object.fromEntries(
        Object.entries(obj).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value])
      );
    if (cambios && typeof cambios === 'object' && Object.keys(cambios).length > 0) {
      cambios = trimObjectValues(cambios);
    }
    if (cambiosOpcionales && typeof cambiosOpcionales === 'object' && Object.keys(cambiosOpcionales).length > 0) {
      cambiosOpcionales = trimObjectValues(cambiosOpcionales);
    }
    if (dniCliente && typeof dniCliente === 'string') {
      dniCliente = dniCliente.trim();
    }
    console.log('-cambios:', cambios);
    console.log('-cambiosOpcionales:', cambiosOpcionales);
    console.log('-dniCliente:', dniCliente);
    if (dniCliente && dniCliente !== "") {
      let queries = []; // Lista de promesas para ejecutar las consultas en paralelo
      if (cambiosOpcionales && Object.keys(cambiosOpcionales).length > 0) {
        const updates = Object.keys(cambiosOpcionales)
          .map((col, index) => `"${col}" = $${index + 1}`)
          .join(', ');
        const updateQuery = `UPDATE "${userSchema}".dades_clients_opcionals SET ${updates} WHERE "Número d'identificació fiscal" = $${Object.keys(cambiosOpcionales).length + 1}`;
        queries.push(pool.query(updateQuery, [...Object.values(cambiosOpcionales), dniCliente]));
      }
      if (cambios && Object.keys(cambios).length > 0) {
        const updates = Object.keys(cambios)
          .map((col, index) => `"${col}" = $${index + 1}`)
          .join(', ');
        const updateQuery = `UPDATE "${userSchema}".dades_clients SET ${updates} WHERE "Número d'identificació fiscal" = $${Object.keys(cambios).length + 1}`;
        queries.push(pool.query(updateQuery, [...Object.values(cambios), dniCliente]));
      }
      await Promise.all(queries); // Ejecutar todas las consultas en paralelo
      res.status(200).json({ missatge: 'Client modificado correctamente' });
      console.log('Datos actualizados.');
    } else {
      console.log('Datos no válidos para la actualización');
      res.status(400).json({ missatge: 'Datos no válidos para la actualización' });
    }
  } catch (error) {
    console.log('Error en /modificar_client:', error);
    winston.error('Error en /modificar_client:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.patch('/camps-clients', authMiddleware, async (req, res) => {
  console.log('PATCH /camps-clients');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { eliminats, nous } = req.body;
    if (Array.isArray(eliminats) && eliminats.length > 0) {
      eliminats = eliminats.map(columna => columna.trim());
    }
    if (Array.isArray(nous) && nous.length > 0) {
      nous = nous.map(columna => columna.trim());
    }
    console.log('-eliminats:', eliminats);
    console.log('-nous:', nous);
    // Eliminar columnas del array `eliminats`
    if (eliminats && eliminats.length > 0) {
      eliminats = eliminats.filter(columna => columna !== "Número d'identificació fiscal");
      if (eliminats.length > 0) { // Solo ejecuta la consulta si hay columnas válidas para eliminar
        const dropColumnsQuery = eliminats
          .map((columna) => `DROP COLUMN IF EXISTS "${columna}"`)
          .join(', ');
        const query = `
          ALTER TABLE "${userSchema}".dades_clients_opcionals
          ${dropColumnsQuery};
        `;
        await pool.query(query);
      }
      //console.log('Columnas eliminadas:', eliminats);
    }
    // Añadir nuevas columnas desde `nous`
    if (nous && nous.length > 0) {
      // Generar una sola consulta para añadir columnas
      const addColumnsQuery = nous
        .map((columna) => `ADD COLUMN IF NOT EXISTS "${columna}" TEXT`)
        .join(', ');
      const alterTableQuery = `
          ALTER TABLE "${userSchema}".dades_clients_opcionals
          ${addColumnsQuery};
        `;
      await pool.query(alterTableQuery);
      //console.log('Columnas añadidas:', nous);
    }
    res.status(200).json({ missatge: 'Client modificado correctamente' });
  } catch (error) {
    winston.error('Error en /camps-clients:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/camps-productes', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas de ambas tablas
    const [columnes, columnesOpcionals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_productes']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_productes_opcionals'])
    ]);
    const campsOpcionals = columnesOpcionals.rows
      .map(row => row.column_name)
      .filter(col => col !== "Codi");
    // Responder con los datos obtenidos
    res.json({
      camps: columnes.rows.map(row => row.column_name),
      camps_opcionals: campsOpcionals
    });
    console.log('Dades de camps-productes enviades correctament');
  } catch (error) {
    winston.error('Error en /camps-productes:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.patch('/camps-productes', authMiddleware, async (req, res) => {
  console.log('PATCH /camps-productes');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { eliminats, nous } = req.body;
    if (Array.isArray(eliminats) && eliminats.length > 0) {
      eliminats = eliminats.map(columna => columna.trim());
    }
    if (Array.isArray(nous) && nous.length > 0) {
      nous = nous.map(columna => columna.trim());
    }
    console.log('-eliminats:', eliminats);
    console.log('-nous:', nous);
    // Eliminar columnas del array `eliminats`
    if (eliminats && eliminats.length > 0) {
      eliminats = eliminats.filter(columna => columna !== "Codi");
      if (eliminats.length > 0) { // Solo ejecuta la consulta si hay columnas válidas para eliminar
        const dropColumnsQuery = eliminats
          .map((columna) => `DROP COLUMN IF EXISTS "${columna}"`)
          .join(', ');
        const query = `
          ALTER TABLE "${userSchema}".dades_productes_opcionals
          ${dropColumnsQuery};
        `;
        await pool.query(query);
      }
      //console.log('Columnas eliminadas:', eliminats);
    }
    // Añadir nuevas columnas desde `nous`
    if (nous && nous.length > 0) {
      // Generar una sola consulta para añadir columnas
      const addColumnsQuery = nous
        .map((columna) => `ADD COLUMN IF NOT EXISTS "${columna}" TEXT`)
        .join(', ');
      const alterTableQuery = `
          ALTER TABLE "${userSchema}".dades_productes_opcionals
          ${addColumnsQuery};
        `;
      await pool.query(alterTableQuery);
      //console.log('Columnas añadidas:', nous);
    }
    res.status(200).json({ missatge: 'producte modificado correctamente' });
  } catch (error) {
    winston.error('Error en /camps-productes:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_productes', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas de ambas tablas
    const [columnes, columnesOpcionals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_productes']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_productes_opcionals'])
    ]);
    // Filtrar la columna conflictiva de opcionales
    const campsOpcionals = columnesOpcionals.rows
      .map(row => row.column_name)
      .filter(col => col !== "Codi");
    // Generar lista completa de columnas con prefijos de tabla correctos
    const columnsQuery = [
      ...columnes.rows.map(row => `"${userSchema}".dades_productes."${row.column_name}"`),
      ...campsOpcionals.map(col => `"${userSchema}".dades_productes_opcionals."${col}"`)
    ].join(', ');
    // Consultamos los datos con LEFT JOIN para evitar resultados vacíos
    // Consultamos los datos con LEFT JOIN para evitar resultados vacíos
    const dades = await pool.query(`
      SELECT 
        ${columnsQuery},
        COALESCE(impostos_json, '[]') AS impostos
      FROM "${userSchema}".dades_productes
      LEFT JOIN "${userSchema}".dades_productes_opcionals
      ON "${userSchema}".dades_productes."Codi" = "${userSchema}".dades_productes_opcionals."Codi"
      LEFT JOIN (
        SELECT 
          "codi producte", 
          json_agg(
            json_build_object(
              'id', "id",
              'impost', "impost",
              'Base imposable', "Base imposable",
              'Tipus impositiu', "Tipus impositiu"
            )
          ) AS impostos_json
        FROM "${userSchema}".impost_producte
        GROUP BY "codi producte"
      ) ip ON "${userSchema}".dades_productes."Codi" = ip."codi producte";
    `);
    // Responder con los datos obtenidos
    res.json({
      camps: columnes.rows.map(row => row.column_name),
      camps_opcionals: campsOpcionals,
      valors: dades.rows,
    });
    console.log('Dades de productes enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_productes:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.patch('/modificar_producte', authMiddleware, async (req, res) => {
  console.log('PATCH /modificar_producte');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { cambios, cambiosOpcionales, dniCliente, impostosProducteNous, impostosProducteEliminats, impostosProducteModificats } = req.body;
    const trimObjectValues = (obj) =>
      Object.fromEntries(
        Object.entries(obj).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value])
      );
    if (cambios && typeof cambios === 'object' && Object.keys(cambios).length > 0) {
      cambios = trimObjectValues(cambios);
    }
    if (cambiosOpcionales && typeof cambiosOpcionales === 'object' && Object.keys(cambiosOpcionales).length > 0) {
      cambiosOpcionales = trimObjectValues(cambiosOpcionales);
    }
    if (dniCliente && typeof dniCliente === 'string') {
      dniCliente = dniCliente.trim();
    }
    console.log('-cambios:', cambios);
    console.log('-cambiosOpcionales:', cambiosOpcionales);
    console.log('-dniCliente:', dniCliente);
    console.log('-impostosProducteNous:', impostosProducteNous);
    console.log('-impostosProducteEliminats:', impostosProducteEliminats);
    console.log('-impostosProducteModificats:', impostosProducteModificats);
    if (dniCliente && dniCliente !== "") {
      var updateQuery = null;
      var updateQueryOpcional = null;
      if (cambios && Object.keys(cambios).length > 0) {
        const updates = Object.keys(cambios)
          .map((col, index) => `"${col}" = $${index + 1}`)
          .join(', ');
        updateQuery = `UPDATE "${userSchema}".dades_productes SET ${updates} WHERE "Codi" = $${Object.keys(cambios).length + 1}`;
      }
      if (cambiosOpcionales && Object.keys(cambiosOpcionales).length > 0) {
        const updates = Object.keys(cambiosOpcionales)
          .map((col, index) => `"${col}" = $${index + 1}`)
          .join(', ');
        updateQueryOpcional = `UPDATE "${userSchema}".dades_productes_opcionals SET ${updates} WHERE "Codi" = $${Object.keys(cambiosOpcionales).length + 1}`;
      }
      let insertImpostProducteQuery;
      let impostosValues;
      // Insertar impuestos si existen
      if (impostosProducteNous.length > 0) {
        const placeholdersImpostos = impostosProducteNous
          .map((_, index) => `($1, $${index * 3 + 2}, $${index * 3 + 3}, $${index * 3 + 4})`)
          .join(', ');
        insertImpostProducteQuery = `
          INSERT INTO "${userSchema}".impost_producte 
          ("codi producte", "impost", "Base imposable", "Tipus impositiu") 
          VALUES ${placeholdersImpostos}
        `;
        impostosValues = impostosProducteNous.flatMap(({ impostTipus, baseImposableCalc, impostTipusImpositiu }) => [
          impostTipus, // No añadir `cambios["Codi"]` aquí
          baseImposableCalc !== null ? Number(baseImposableCalc) : null,
          impostTipusImpositiu !== null ? Number(impostTipusImpositiu) : null
        ]);
      }
      var eliminarImpostosProducteQuery = null;
      var idsImpostosAEliminar = null;
      if (impostosProducteEliminats && impostosProducteEliminats.length > 0) {
        idsImpostosAEliminar = impostosProducteEliminats; // Ya es un array de IDs
        const placeholders = idsImpostosAEliminar.map((_, i) => `$${i + 1}`).join(', ');
        eliminarImpostosProducteQuery = `
          DELETE FROM "${userSchema}".impost_producte
          WHERE "id" IN (${placeholders})`;
      }
      var values = [];
      var updateImpostQuery = null;
      if (impostosProducteModificats && impostosProducteModificats.length > 0) {
        const placeholders = [];
        impostosProducteModificats.forEach((impost, index) => {
          const idImpost = Number(impost.idImpost);
          const impostTipus = impost.impostTipus;
          const baseImposableCalc = parseFloat(impost.baseImposableCalc) || null;
          const impostTipusImpositiu = parseFloat(impost.impostTipusImpositiu) || null;
          values.push(impostTipus, baseImposableCalc, impostTipusImpositiu, idImpost);
          const startIndex = index * 4 + 1;
          placeholders.push(`($${startIndex}::text, $${startIndex + 1}::numeric, $${startIndex + 2}::numeric, $${startIndex + 3}::integer)`);
        });
        updateImpostQuery = `
            UPDATE "${userSchema}".impost_producte
            SET "impost" = x.impost,
                "Base imposable" = x."Base imposable",
                "Tipus impositiu" = x."Tipus impositiu"
            FROM (VALUES ${placeholders.join(', ')}) AS x("impost", "Base imposable", "Tipus impositiu", "id")
            WHERE "${userSchema}".impost_producte."id" = x.id`;
      }
      // Ejecutar ambas consultas en una transacción
      await pool.query('BEGIN');
      if (updateQueryOpcional) {
        await pool.query(updateQueryOpcional, [...Object.values(cambiosOpcionales), dniCliente]);
      }
      // Insertar impuestos solo si existen
      if (insertImpostProducteQuery && impostosValues) {
        await pool.query(insertImpostProducteQuery, [dniCliente, ...impostosValues]);
      }
      // Eliminar impuestos solo si existen
      if (eliminarImpostosProducteQuery && idsImpostosAEliminar) {
        await pool.query(eliminarImpostosProducteQuery, idsImpostosAEliminar);
      }
      // Eliminar impuestos solo si existen
      if (updateImpostQuery && values) {
        await pool.query(updateImpostQuery, values);
      }
      if (updateQuery) {
        await pool.query(updateQuery, [...Object.values(cambios), dniCliente]);
      }
      await pool.query('COMMIT');
      res.status(200).json({ missatge: 'Producte modificado correctamente' });
      console.log('Datos actualizados.');
    } else {
      console.log('Datos no válidos para la actualización');
      res.status(400).json({ missatge: 'Datos no válidos para la actualización' });
    }
  } catch (error) {
    console.log('Error en /modificar_producte:', error);
    winston.error('Error en /modificar_producte:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.delete('/eliminar_producte', authMiddleware, async (req, res) => {
  console.log('DELETE /eliminar_producte');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { dniCliente } = req.body;
    if (dniCliente && typeof dniCliente === 'string') {
      dniCliente = dniCliente.trim();
    }
    console.log('-dniCliente:', dniCliente);
    if (dniCliente && dniCliente !== "") {
      // Query para la eliminación
      const deleteQuery = `DELETE FROM "${userSchema}".dades_productes WHERE "Codi" = $1`;
      // Ejecutar la consulta con los valores actualizados
      await pool.query(deleteQuery, [dniCliente]);
      res.status(200).json({ missatge: 'Producte eliminat correctament' });
    } else {
      res.status(500).json({ missatge: 'Datos no válidos para la eliminación' });
    }
  } catch (error) {
    winston.error('Error en /eliminar_producte:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.post('/afegir_producte', authMiddleware, async (req, res) => {
  console.log('POST /afegir_producte');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { cambios, cambiosOpcionales, impostosProducteNous } = req.body;
    // Función para limpiar los valores de un objeto (eliminar espacios en blanco)
    const trimObjectValues = (obj) =>
      Object.fromEntries(
        Object.entries(obj).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value])
      );
    // Validar y limpiar datos
    if (cambios && typeof cambios === 'object' && Object.keys(cambios).length > 0) {
      cambios = trimObjectValues(cambios);
    } else {
      return res.status(500).json({ missatge: 'Datos no válidos para la inserción' });
    }
    if (!cambiosOpcionales || typeof cambiosOpcionales !== 'object') {
      cambiosOpcionales = {}; // Si no hay datos opcionales, usar un objeto vacío
    } else {
      cambiosOpcionales = trimObjectValues(cambiosOpcionales);
    }
    // Asegurar que cambiosOpcionales tenga el DNI del productee
    cambiosOpcionales["Codi"] = cambios["Codi"];
    console.log('- cambios:', cambios);
    console.log('- cambios opcionales:', cambiosOpcionales);
    console.log('- impostosProducteNous:', impostosProducteNous);
    // Crear lista de columnas y valores para dades_productes
    const columns = Object.keys(cambios).map(col => `"${col}"`).join(', ');
    const values = Object.values(cambios);
    const placeholders = values.map((_, index) => `$${index + 1}`).join(', ');
    // Crear lista de columnas y valores para dades_productes_opcionals
    const columnsOpcionals = Object.keys(cambiosOpcionales).map(col => `"${col}"`).join(', ');
    const valuesOpcionals = Object.values(cambiosOpcionales);
    const placeholdersOpcionals = valuesOpcionals.map((_, index) => `$${index + 1}`).join(', ');
    // Queries de inserción
    const insertProducteQuery = `INSERT INTO "${userSchema}".dades_productes (${columns}) VALUES (${placeholders})`;
    const insertProducteQueryOpcionals = `INSERT INTO "${userSchema}".dades_productes_opcionals (${columnsOpcionals}) VALUES (${placeholdersOpcionals})`;
    let insertImpostProducteQuery;
    let impostosValues;
    // Insertar impuestos si existen
    if (impostosProducteNous.length > 0) {
      const placeholdersImpostos = impostosProducteNous
        .map((_, index) => `($1, $${index * 3 + 2}, $${index * 3 + 3}, $${index * 3 + 4})`)
        .join(', ');
      insertImpostProducteQuery = `
        INSERT INTO "${userSchema}".impost_producte 
        ("codi producte", "impost", "Base imposable", "Tipus impositiu") 
        VALUES ${placeholdersImpostos}
      `;
      impostosValues = impostosProducteNous.flatMap(({ impostTipus, baseImposableCalc, impostTipusImpositiu }) => [
        impostTipus, // No añadir `cambios["Codi"]` aquí
        baseImposableCalc !== null ? Number(baseImposableCalc) : null,
        impostTipusImpositiu !== null ? Number(impostTipusImpositiu) : null
      ]);
    }
    // Ejecutar ambas consultas en una transacción
    await pool.query('BEGIN');
    await pool.query(insertProducteQuery, values);
    await pool.query(insertProducteQueryOpcionals, valuesOpcionals);
    // Insertar impuestos solo si existen
    if (insertImpostProducteQuery && impostosValues) {
      await pool.query(insertImpostProducteQuery, [cambios["Codi"], ...impostosValues]);
    }
    await pool.query('COMMIT');
    res.status(200).json({ missatge: 'producte insertat correctament' });
  } catch (error) {
    await pool.query('ROLLBACK'); // Revertir cambios en caso de error
    console.error('Error en /afegir_producte:', error);
    winston.error('Error en /afegir_producte:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});




app.get('/camps-factures', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas de ambas tablas
    const [columnes, columnesOpcionals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_factures']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_factures_opcionals'])
    ]);
    const campsOpcionals = columnesOpcionals.rows
      .map(row => row.column_name)
      .filter(col => col !== "Sèrie" && col !== "Número");
    // Responder con los datos obtenidos
    res.json({
      camps: columnes.rows.map(row => row.column_name).filter(col => col !== "Estat" && col !== "Client" && col !== "id"),
      camps_opcionals: campsOpcionals
    });
    console.log('Dades de camps-factures enviades correctament');
  } catch (error) {
    winston.error('Error en /camps-factures:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.patch('/camps-factures', authMiddleware, async (req, res) => {
  console.log('PATCH /camps-factures');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { eliminats, nous } = req.body;
    if (Array.isArray(eliminats) && eliminats.length > 0) {
      eliminats = eliminats.map(columna => columna.trim());
    }
    if (Array.isArray(nous) && nous.length > 0) {
      nous = nous.map(columna => columna.trim());
    }
    console.log('-eliminats:', eliminats);
    console.log('-nous:', nous);
    // Eliminar columnas del array `eliminats`
    if (eliminats && eliminats.length > 0) {
      eliminats = eliminats.filter(col => col !== "Sèrie" && col !== "Número" && col !== "id");
      if (eliminats.length > 0) { // Solo ejecuta la consulta si hay columnas válidas para eliminar
        const dropColumnsQuery = eliminats
          .map((columna) => `DROP COLUMN IF EXISTS "${columna}"`)
          .join(', ');
        const query = `
          ALTER TABLE "${userSchema}".dades_factures_opcionals
          ${dropColumnsQuery};
        `;
        await pool.query(query);
      }
      //console.log('Columnas eliminadas:', eliminats);
    }
    // Añadir nuevas columnas desde `nous`
    if (nous && nous.length > 0) {
      // Generar una sola consulta para añadir columnas
      const addColumnsQuery = nous
        .map((columna) => `ADD COLUMN IF NOT EXISTS "${columna}" TEXT`)
        .join(', ');
      const alterTableQuery = `
          ALTER TABLE "${userSchema}".dades_factures_opcionals
          ${addColumnsQuery};
        `;
      await pool.query(alterTableQuery);
    }
    res.status(200).json({ missatge: 'factura modificado correctamente' });
  } catch (error) {
    winston.error('Error en /camps-factures:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_series', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas de la tabla
    const columnesObligatories = await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = $1 AND table_name = $2;
    `, [userSchema, 'dades_series']);
    // Obtener todas las columnas de la tabla
    const columnes = columnesObligatories.rows.map(row => row.column_name);
    // Separar las columnas obligatorias y opcionales
    const campsOpcionales = columnes.filter(col => col === "Prefix" || col === "Sufix");
    const campsObligatoris = columnes.filter(col => !campsOpcionales.includes(col) && col !== "Número actual");
    // Construir la consulta con todas las columnas necesarias
    const columnsQuery = columnes.map(col => `"${col}"`).join(', ');
    // Obtener los datos de la tabla
    const dades = await pool.query(`
      SELECT ${columnsQuery}
      FROM "${userSchema}".dades_series;
    `);
    // Responder con los datos obtenidos
    res.json({
      camps: campsObligatoris,
      camps_opcionals: campsOpcionales,
      valors: dades.rows,
    });
    console.log('Dades de series enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_series:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.delete('/eliminar_serie', authMiddleware, async (req, res) => {
  console.log('DELETE /eliminar_serie');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { dniCliente } = req.body;
    if (dniCliente && typeof dniCliente === 'string') {
      dniCliente = dniCliente.trim();
    }
    console.log('-dniCliente:', dniCliente);
    if (dniCliente && dniCliente !== "") {
      // Query para la eliminación
      const deleteQuery = `DELETE FROM "${userSchema}".dades_series WHERE "Codi" = $1`;
      // Ejecutar la consulta con los valores actualizados
      await pool.query(deleteQuery, [dniCliente]);
      res.status(200).json({ missatge: 'serie eliminat correctament' });
    } else {
      res.status(500).json({ missatge: 'Datos no válidos para la eliminación' });
    }
  } catch (error) {
    winston.error('Error en /eliminar_serie:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.post('/afegir_serie', authMiddleware, async (req, res) => {
  console.log('POST /afegir_serie');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { cambios, cambiosOpcionales } = req.body;
    // Función para limpiar los valores de un objeto (eliminar espacios en blanco)
    const trimObjectValues = (obj) =>
      Object.fromEntries(
        Object.entries(obj).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value])
      );
    // Validar y limpiar datos
    if (!cambios || typeof cambios !== 'object' || Object.keys(cambios).length === 0) {
      return res.status(400).json({ missatge: 'Datos no válidos para la inserción' });
    }
    cambios["Número actual"] = 0; // Inicializar el número actual en 0
    cambios = trimObjectValues(cambios);
    if (!cambiosOpcionales || typeof cambiosOpcionales !== 'object') {
      cambiosOpcionales = {}; // Si no hay datos opcionales, usar un objeto vacío
    } else {
      cambiosOpcionales = trimObjectValues(cambiosOpcionales);
    }
    console.log('- Cambios obligatorios:', cambios);
    console.log('- Cambios opcionales:', cambiosOpcionales);
    // Unir columnas y valores en una sola inserción
    const allColumns = [...Object.keys(cambios), ...Object.keys(cambiosOpcionales)]
      .map(col => `"${col}"`).join(', ');
    const allValues = [...Object.values(cambios), ...Object.values(cambiosOpcionales)];
    const placeholders = allValues.map((_, index) => `$${index + 1}`).join(', ');
    // Query de inserción
    const insertSerieQuery = `
      INSERT INTO "${userSchema}".dades_series (${allColumns}) 
      VALUES (${placeholders})
    `;
    // Ejecutar la consulta dentro de una transacción para mayor seguridad
    await pool.query('BEGIN');
    await pool.query(insertSerieQuery, allValues);
    await pool.query('COMMIT');
    res.status(200).json({ missatge: 'Sèrie inserida correctament' });
  } catch (error) {
    console.error('Error en /afegir_serie:', error);
    winston.error('Error en /afegir_serie:', error);
    await pool.query('ROLLBACK'); // Revertir cambios si hubo un error
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_series_factura', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas de la tabla
    const columnesObligatories = await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = $1 AND table_name = $2;
    `, [userSchema, 'dades_series']);
    // Obtener todas las columnas de la tabla
    const columnes = columnesObligatories.rows.map(row => row.column_name);
    // Separar las columnas obligatorias y opcionales
    const campsOpcionales = columnes.filter(col => col === "Prefix" || col === "Sufix");
    const campsObligatoris = columnes.filter(col => !campsOpcionales.includes(col) && col !== "Número actual");
    // Construir la consulta con todas las columnas necesarias
    const columnsQuery = columnes.map(col => `"${col}"`).join(', ');
    // Obtener los datos de la tabla
    const dades = await pool.query(`
      SELECT ${columnsQuery}
      FROM "${userSchema}".dades_series;
    `);
    // Responder con los datos obtenidos
    res.json({
      camps_series: campsObligatoris,
      camps_opcionals_series: campsOpcionales,
      valors_series: dades.rows,
    });
    console.log('Dades de series enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_series:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});


app.post('/afegir_client', authMiddleware, async (req, res) => {
  console.log('POST /afegir_client');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { cambios, cambiosOpcionales } = req.body;
    // Función para limpiar los valores de un objeto (eliminar espacios en blanco)
    const trimObjectValues = (obj) =>
      Object.fromEntries(
        Object.entries(obj).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value])
      );
    // Validar y limpiar datos
    if (cambios && typeof cambios === 'object' && Object.keys(cambios).length > 0) {
      cambios = trimObjectValues(cambios);
    } else {
      return res.status(500).json({ missatge: 'Datos no válidos para la inserción' });
    }
    if (!cambiosOpcionales || typeof cambiosOpcionales !== 'object') {
      cambiosOpcionales = {}; // Si no hay datos opcionales, usar un objeto vacío
    } else {
      cambiosOpcionales = trimObjectValues(cambiosOpcionales);
    }
    // Asegurar que cambiosOpcionales tenga el DNI del cliente
    cambiosOpcionales["Número d'identificació fiscal"] = cambios["Número d'identificació fiscal"];
    console.log('- cambios:', cambios);
    console.log('- cambios opcionales:', cambiosOpcionales);
    // Crear lista de columnas y valores para dades_clients
    const columns = Object.keys(cambios).map(col => `"${col}"`).join(', ');
    const values = Object.values(cambios);
    const placeholders = values.map((_, index) => `$${index + 1}`).join(', ');
    // Crear lista de columnas y valores para dades_clients_opcionals
    const columnsOpcionals = Object.keys(cambiosOpcionales).map(col => `"${col}"`).join(', ');
    const valuesOpcionals = Object.values(cambiosOpcionales);
    const placeholdersOpcionals = valuesOpcionals.map((_, index) => `$${index + 1}`).join(', ');
    // Queries de inserción
    const insertClientQuery = `INSERT INTO "${userSchema}".dades_clients (${columns}) VALUES (${placeholders})`;
    const insertClientQueryOpcionals = `INSERT INTO "${userSchema}".dades_clients_opcionals (${columnsOpcionals}) VALUES (${placeholdersOpcionals})`;
    // Ejecutar ambas consultas en una transacción
    await pool.query('BEGIN');
    await pool.query(insertClientQuery, values);
    await pool.query(insertClientQueryOpcionals, valuesOpcionals);
    await pool.query('COMMIT');
    res.status(200).json({ missatge: 'Client insertat correctament' });
  } catch (error) {
    await pool.query('ROLLBACK'); // Revertir cambios en caso de error
    console.error('Error en /afegir_client:', error);
    winston.error('Error en /afegir_client:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.delete('/eliminar_client', authMiddleware, async (req, res) => {
  console.log('DELETE /eliminar_client');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { dniCliente } = req.body;
    if (dniCliente && typeof dniCliente === 'string') {
      dniCliente = dniCliente.trim();
    }
    console.log('-dniCliente:', dniCliente);
    if (dniCliente && dniCliente !== "") {
      // Query para la eliminación
      const deleteQuery = `DELETE FROM "${userSchema}".dades_clients WHERE "Número d'identificació fiscal" = $1`;
      // Ejecutar la consulta con los valores actualizados
      await pool.query(deleteQuery, [dniCliente]);
      res.status(200).json({ missatge: 'Client eliminat correctament' });
    } else {
      res.status(500).json({ missatge: 'Datos no válidos para la eliminación' });
    }
  } catch (error) {
    winston.error('Error en /eliminar_client:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.post('/afegir_factura_serie', authMiddleware, async (req, res) => {
  console.log('POST /afegir_factura_serie');
  let transaccionIniciada = false; // Flag para saber si se inició una transacción
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { cambios, cambiosOpcionales } = req.body;
    // Función para limpiar los valores de un objeto (eliminar espacios en blanco)
    const trimObjectValues = (obj) =>
      Object.fromEntries(
        Object.entries(obj).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value])
      );
    // Validar y limpiar datos
    if (cambios && typeof cambios === 'object' && Object.keys(cambios).length > 0) {
      cambios["Estat"] = "Esborrany";
      cambios = trimObjectValues(cambios);
    } else {
      return res.status(500).json({ missatge: 'Datos no válidos para la inserción' });
    }
    if (!cambiosOpcionales || typeof cambiosOpcionales !== 'object') {
      cambiosOpcionales = {};
    } else {
      cambiosOpcionales = trimObjectValues(cambiosOpcionales);
    }
    cambiosOpcionales["Sèrie"] = cambios["Sèrie"];
    cambiosOpcionales["Número"] = cambios["Número"];
    console.log('- cambios:', cambios);
    console.log('- cambios opcionales:', cambiosOpcionales);
    const facturaIdRebuda = cambios["id"];
    await pool.query('BEGIN'); // Iniciar transacción
    transaccionIniciada = true; // Marcar transacción iniciada
    if (facturaIdRebuda) { // Es un UPDATE
      const setQuery = Object.keys(cambios)
        .filter(col => col !== "id")
        .map((col, i) => `"${col}" = $${i + 1}`)
        .join(', ');
      const updateFacturaQuery = `
        UPDATE "${userSchema}".dades_factures
        SET ${setQuery}
        WHERE "id" = $${Object.keys(cambios).length}
        RETURNING "id"`;
      const updateValues = [...Object.values(cambios).filter((_, i) => Object.keys(cambios)[i] !== "id"), facturaIdRebuda];
      const result = await pool.query(updateFacturaQuery, updateValues);
      const facturaId = result.rows[0].id;
      // Corrección en `UPDATE` de opcionales
      if (Object.keys(cambiosOpcionales).length > 2) {
        const setQueryOpcionales = Object.keys(cambiosOpcionales)
          .map((col, i) => `"${col}" = $${i + 1}`)
          .join(', ');
        const updateFacturaQueryOpcionals = `
          UPDATE "${userSchema}".dades_factures_opcionals
          SET ${setQueryOpcionales}
          WHERE "Sèrie" = $${Object.keys(cambiosOpcionales).length - 1} 
          AND "Número" = $${Object.keys(cambiosOpcionales).length}`;
        const updateValuesOpcionales = Object.values(cambiosOpcionales);
        await pool.query(updateFacturaQueryOpcionals, updateValuesOpcionales);
      }
      const updateNumeroSerie = `
        UPDATE "${userSchema}".dades_series
        SET "Número actual" = $1
        WHERE "Codi" = $2 AND $1 > "Número actual"
      `;
      await pool.query(updateNumeroSerie, [cambios["Número"], cambios["Sèrie"]]);
      //Obtenir prefix i sufix de la sèrie
      const dades = await pool.query(`
        SELECT "Prefix", "Sufix"
        FROM "${userSchema}".dades_series
        WHERE "Codi" = $1;
      `, [cambios["Sèrie"]]);
      await pool.query('COMMIT');
      await updateEstatFactura(cambios["Sèrie"], cambios["Número"], userSchema)
      res.status(200).json({
        missatge: 'Factura insertada correctament',
        id: facturaId,
        prefixSerie: dades.rows[0].Prefix,
        sufixSerie: dades.rows[0].Sufix
      });
    } else { // Es un INSERT
      const columns = Object.keys(cambios).map(col => `"${col}"`).join(', ');
      const values = Object.values(cambios);
      const placeholders = values.map((_, index) => `$${index + 1}`).join(', ');
      const insertFacturaQuery = `
        INSERT INTO "${userSchema}".dades_factures (${columns})
        VALUES (${placeholders})
        RETURNING "id"`;
      const result = await pool.query(insertFacturaQuery, values);
      const facturaId = result.rows[0].id;
      const columnsOpcionals = Object.keys(cambiosOpcionales).map(col => `"${col}"`).join(', ');
      const valuesOpcionals = Object.values(cambiosOpcionales);
      const placeholdersOpcionals = valuesOpcionals.map((_, index) => `$${index + 1}`).join(', ');
      const insertFacturaQueryOpcionals = `
          INSERT INTO "${userSchema}".dades_factures_opcionals (${columnsOpcionals})
          VALUES (${placeholdersOpcionals})`;
      await pool.query(insertFacturaQueryOpcionals, valuesOpcionals);
      const updateNumeroSerie = `
        UPDATE "${userSchema}".dades_series
        SET "Número actual" = $1
        WHERE "Codi" = $2 AND $1 > "Número actual"
      `;
      await pool.query(updateNumeroSerie, [cambios["Número"], cambios["Sèrie"]]);
      //Obtenir prefix i sufix de la sèrie
      const dades = await pool.query(`
        SELECT "Prefix", "Sufix"
        FROM "${userSchema}".dades_series
        WHERE "Codi" = $1;
      `, [cambios["Sèrie"]]);
      await pool.query('COMMIT');
      await updateEstatFactura(cambios["Sèrie"], cambios["Número"], userSchema)
      res.status(200).json({
        missatge: 'Factura insertada correctament',
        id: facturaId,
        prefixSerie: dades.rows[0].Prefix,
        sufixSerie: dades.rows[0].Sufix
      });
    }
  } catch (error) {
    if (transaccionIniciada) {
      await pool.query('ROLLBACK');
    }
    console.error('Error en /afegir_factura:', error);
    winston.error('Error en /afegir_factura:', error);
    if (error.code === '23505') {
      return res.status(409).json({ missatge: 'Ja existeix una factura amb aquest número en aquesta sèrie' });
    }
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_factura_id', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    let { id } = req.query; // Usar req.query en lugar de req.body para GET
    if (!id) {
      return res.status(400).json({ missatge: 'ID de factura no proporcionado' });
    }
    // Obtener los nombres de las columnas de ambas tablas
    const [columnes, columnesOpcionals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_factures']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_factures_opcionals'])
    ]);
    // Filtrar columnas no necesarias
    const camps = columnes.rows
      .map(row => row.column_name)
      .filter(col => col !== "Estat" && col !== "Client");
    const campsOpcionals = columnesOpcionals.rows
      .map(row => row.column_name)
      .filter(col => col !== "Sèrie" && col !== "Número");
    // Construir lista de columnas con prefijo de tabla
    const columnsQuery = [
      ...camps.map(col => `"${userSchema}".dades_factures."${col}"`),
      ...campsOpcionals.map(col => `"${userSchema}".dades_factures_opcionals."${col}"`)
    ].join(', ');
    // Ejecutar la consulta con LEFT JOIN para incluir datos opcionales si existen
    const dades = await pool.query(`
      SELECT ${columnsQuery}
      FROM "${userSchema}".dades_factures
      LEFT JOIN "${userSchema}".dades_factures_opcionals
      ON "${userSchema}".dades_factures."Sèrie" = "${userSchema}".dades_factures_opcionals."Sèrie" 
      AND "${userSchema}".dades_factures."Número" = "${userSchema}".dades_factures_opcionals."Número"
      WHERE "${userSchema}".dades_factures."id" = $1;
    `, [id]);
    if (dades.rows.length === 0) {
      return res.status(404).json({ missatge: 'Factura no trobada' });
    }
    res.json({
      camps: camps,
      camps_opcionals: campsOpcionals,
      valors: dades.rows[0], // Devolver solo el primer resultado
    });
    console.log('Dades de factura enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_factura_id:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.post('/afegir_factura_client', authMiddleware, async (req, res) => {
  console.log('POST /afegir_factura_client');
  let transaccionIniciada = false; // Flag para saber si la transacción se inició
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { facturaId, clientIdSelect } = req.body;
    console.log('- facturaId:', facturaId);
    console.log('- clientIdSelect:', clientIdSelect);
    if (!facturaId || !clientIdSelect) {
      return res.status(400).json({ missatge: 'Datos no válidos para la inserción' }); // 400 = Bad Request
    }
    clientIdSelect = clientIdSelect.trim();
    // Iniciar transacción antes de la consulta
    await pool.query('BEGIN');
    transaccionIniciada = true;
    const updateFacturaQuery = `
        UPDATE "${userSchema}".dades_factures
        SET "Client" = $1
        WHERE "id" = $2`;
    const updateValues = [clientIdSelect, facturaId];
    const result = await pool.query(updateFacturaQuery, updateValues);
    if (result.rowCount === 0) {
      throw new Error('Factura no encontrada o no se pudo actualizar'); // Lanzamos error si no se actualizó ninguna fila
    }
    const resultat = await pool.query(`
      SELECT "Sèrie", "Número"
      FROM "${userSchema}".dades_factures
      WHERE "id" = $1;
    `, [facturaId]);
    const { "Sèrie": serie, "Número": numero } = resultat.rows[0];
    await pool.query('COMMIT'); // Confirmar transacción
    await updateEstatFactura(serie, numero, userSchema);
    res.status(200).json({ missatge: 'Client insertat correctament' });
  } catch (error) {
    if (transaccionIniciada) {
      await pool.query('ROLLBACK'); // Revertir cambios solo si se inició una transacción
    }
    console.error('Error en /afegir_factura_client:', error);
    winston.error('Error en /afegir_factura_client:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_factura_client', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    const id = req.query.id; // Usar req.query en lugar de req.body para GET
    if (!id) {
      return res.status(400).json({ missatge: 'ID de factura no proporcionado' });
    }
    // Obtener el ID del cliente asociado a la factura
    const clientIdResult = await pool.query(`
      SELECT "Client"
      FROM "${userSchema}".dades_factures
      WHERE "id" = $1;
    `, [id]);
    if (clientIdResult.rows.length === 0) {
      return res.status(404).json({ missatge: 'Factura no trobada' });
    }
    const clientId = clientIdResult.rows[0]?.Client ?? null;
    console.log('Dades del client enviades correctament:', clientId);
    res.json({ clientId });
  } catch (error) {
    console.error('Error en /dades_factura_client:', error);
    winston.error('Error en /dades_factura_client:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/camps-linia-factura', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas de ambas tablas
    const [columnes, columnesOpcionals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_linia_factura']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_linia_factura_opcionals'])
    ]);
    // Responder con los datos obtenidos
    res.json({
      camps: columnes.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "Codi producte" && col !== "id" && col !== "Preu unitari"),
      camps_opcionals: columnesOpcionals.rows.map(row => row.column_name).filter(col => col !== "id")
    });
    console.log('Dades de camps-linia-factura enviades correctament');
  } catch (error) {
    winston.error('Error en /camps-linia-factura:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.patch('/camps-linia-factura', authMiddleware, async (req, res) => {
  console.log('PATCH /camps-linia-factura');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { eliminats, nous } = req.body;
    if (Array.isArray(eliminats) && eliminats.length > 0) {
      eliminats = eliminats.map(columna => columna.trim());
    }
    if (Array.isArray(nous) && nous.length > 0) {
      nous = nous.map(columna => columna.trim());
    }
    console.log('-eliminats:', eliminats);
    console.log('-nous:', nous);
    // Eliminar columnas del array `eliminats`
    if (eliminats && eliminats.length > 0) {
      eliminats = eliminats.filter(col => col !== "id");
      if (eliminats.length > 0) { // Solo ejecuta la consulta si hay columnas válidas para eliminar
        const dropColumnsQuery = eliminats
          .map((columna) => `DROP COLUMN IF EXISTS "${columna}"`)
          .join(', ');
        const query = `
          ALTER TABLE "${userSchema}".dades_linia_factura_opcionals
          ${dropColumnsQuery};
        `;
        await pool.query(query);
      }
      //console.log('Columnas eliminadas:', eliminats);
    }
    // Añadir nuevas columnas desde `nous`
    if (nous && nous.length > 0) {
      // Generar una sola consulta para añadir columnas
      const addColumnsQuery = nous
        .map((columna) => `ADD COLUMN IF NOT EXISTS "${columna}" TEXT`)
        .join(', ');
      const alterTableQuery = `
          ALTER TABLE "${userSchema}".dades_linia_factura_opcionals
          ${addColumnsQuery};
        `;
      await pool.query(alterTableQuery);
    }
    res.status(200).json({ missatge: 'linia factura modificado correctamente' });
  } catch (error) {
    winston.error('Error en /camps-linia-factura:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.post('/afegir_linia_factura', authMiddleware, async (req, res) => {
  console.log('POST /afegir_linia_factura');
  let transaccionIniciada = false; // Flag para saber si se inició una transacción
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { cambios, cambiosOpcionales, impostosEliminats, impostosAfegits, impostosModificats, descomptesEliminats, descomptesAfegits, descomptesModificats, mitjaTransportNou = [] } = req.body;
    // Función para limpiar los valores de un objeto (eliminar espacios en blanco)
    const trimObjectValues = (obj) =>
      Object.fromEntries(
        Object.entries(obj).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value])
      );
    // Validar y limpiar datos
    if (cambios && typeof cambios === 'object' && Object.keys(cambios).length > 0) {
      cambios = trimObjectValues(cambios);
    } else {
      return res.status(500).json({ missatge: 'Datos no válidos para la inserción' });
    }
    if (!cambiosOpcionales || typeof cambiosOpcionales !== 'object') {
      cambiosOpcionales = {};
    } else {
      cambiosOpcionales = trimObjectValues(cambiosOpcionales);
    }
    console.log('- cambios:', cambios);
    console.log('- cambios opcionales:', cambiosOpcionales);
    console.log('- impostosEliminats:', impostosEliminats);
    console.log('- impostosAfegits:', impostosAfegits);
    console.log('- impostosModificats:', impostosModificats);
    console.log('- descomptesEliminats:', descomptesEliminats);
    console.log('- descomptesAfegits:', descomptesAfegits);
    console.log('- descomptesModificats:', descomptesModificats);
    console.log('- mitjaTransportNou:', mitjaTransportNou);
    const liniaRebuda = cambios["id"];
    await pool.query('BEGIN'); // Iniciar transacción
    transaccionIniciada = true; // Marcar transacción iniciada
    if (liniaRebuda) { // Es un UPDATE
      //console.log('Es un UPDATE');
      if (Object.keys(cambios).length > 1) {
        const setQuery = Object.keys(cambios)
          .filter(col => col !== "id")
          .map((col, i) => `"${col}" = $${i + 1}`)
          .join(', ');
        const updateFacturaQuery = `
        UPDATE "${userSchema}".dades_linia_factura
        SET ${setQuery}
        WHERE "id" = $${Object.keys(cambios).length}`;
        const updateValues = [...Object.values(cambios).filter((_, i) => Object.keys(cambios)[i] !== "id"), liniaRebuda];
        await pool.query(updateFacturaQuery, updateValues);
      }
      // Corrección en `UPDATE` de opcionales
      if (Object.keys(cambiosOpcionales).length > 0) {
        const setQueryOpcionales = Object.keys(cambiosOpcionales)
          .map((col, i) => `"${col}" = $${i + 1}`)
          .join(', ');
        const updateFacturaQueryOpcionals = `
        UPDATE "${userSchema}".dades_linia_factura_opcionals
        SET ${setQueryOpcionales}
        WHERE "id" = $${Object.keys(cambiosOpcionales).length + 1}`; // FIX
        const updateValuesOpcionales = [...Object.values(cambiosOpcionales), liniaRebuda];
        await pool.query(updateFacturaQueryOpcionals, updateValuesOpcionales);
      }
      if (impostosEliminats && impostosEliminats.length > 0) {
        const idsImpostosAEliminar = impostosEliminats; // Ya es un array de IDs
        const placeholders = idsImpostosAEliminar.map((_, i) => `$${i + 1}`).join(', ');
        const deleteImpostQuery = `
          DELETE FROM "${userSchema}".impost_linia_factura
          WHERE "id" IN (${placeholders})`;
        await pool.query(deleteImpostQuery, idsImpostosAEliminar);
      }
      if (impostosModificats && impostosModificats.length > 0) {
        const values = [];
        const placeholders = [];
        impostosModificats.forEach((impost, index) => {
          const idImpost = Number(impost.idImpost);
          const valorImpost = impost.impostTipus;
          const baseImposableImpost = parseFloat(impost.baseImposableCalc) || 0;
          const percImpost = parseFloat(impost.impostTipusImpositiu) || null;
          values.push(valorImpost, baseImposableImpost, percImpost, idImpost);
          const startIndex = index * 4 + 1;
          placeholders.push(`($${startIndex}::text, $${startIndex + 1}::numeric, $${startIndex + 2}::numeric, $${startIndex + 3}::integer)`);
        });
        const updateImpostQuery = `
            UPDATE "${userSchema}".impost_linia_factura
            SET "impost" = x.impost,
                "Base imposable" = x."Base imposable",
                "Tipus impositiu" = x."Tipus impositiu"
            FROM (VALUES ${placeholders.join(', ')}) AS x("impost", "Base imposable", "Tipus impositiu", "id")
            WHERE "${userSchema}".impost_linia_factura."id" = x.id`;
        await pool.query(updateImpostQuery, values);
      }
      if (impostosAfegits && impostosAfegits.length > 0) {
        const values = [];
        const placeholders = [];
        impostosAfegits.forEach((impost, index) => {
          const valorImpost = impost.impostTipus;
          const baseImposableImpost = impost.baseImposableCalc;
          const percImpost = impost.impostTipusImpositiu || null; // Si es '' o undefined, se convierte en null
          // Añadir los valores al array y generar los placeholders dinámicamente
          values.push(liniaRebuda, valorImpost, baseImposableImpost, percImpost);
          // Calcular el desplazamiento de placeholders correctamente
          const startIndex = index * 4 + 1;
          placeholders.push(`($${startIndex}, $${startIndex + 1}, $${startIndex + 2}, $${startIndex + 3})`);
        });
        const insertImpostQuery = `
          INSERT INTO "${userSchema}".impost_linia_factura ("linia factura", "impost", "Base imposable", "Tipus impositiu")
          VALUES ${placeholders.join(', ')}`;
        await pool.query(insertImpostQuery, values);
      }
      if (descomptesEliminats && descomptesEliminats.length > 0) {
        const idsDescomtesAEliminar = descomptesEliminats; // Ya es un array de IDs
        const placeholders = idsDescomtesAEliminar.map((_, i) => `$${i + 1}`).join(', ');
        const deleteDescomtesQuery = `
          DELETE FROM "${userSchema}".descompte_linia_factura
          WHERE "id" IN (${placeholders})`;
        await pool.query(deleteDescomtesQuery, idsDescomtesAEliminar);
      }
      if (descomptesModificats && descomptesModificats.length > 0) {
        const values = [];
        const placeholders = [];
        descomptesModificats.forEach((descompte, index) => {
          const idDescompte = Number(descompte.id);
          const descompteDescripcio = descompte.descompteDescripcio || null;
          const baseImposableDescompte = parseFloat(descompte.baseImposableCalc);
          const percDescompte = parseFloat(descompte.descompteTipusDescompte) || null;
          values.push(descompteDescripcio, baseImposableDescompte, percDescompte, idDescompte);
          const startIndex = index * 4 + 1;
          placeholders.push(`($${startIndex}::text, $${startIndex + 1}::numeric, $${startIndex + 2}::numeric, $${startIndex + 3}::integer)`);
        });
        const updateDescompteQuery = `
            UPDATE "${userSchema}".descompte_linia_factura
            SET "Descripció" = x."Descripció",
                "Base descompte" = x."Base descompte",
                "Percentatge" = x."Percentatge"
            FROM (VALUES ${placeholders.join(', ')}) AS x("Descripció", "Base descompte", "Percentatge", "id")
            WHERE "${userSchema}".descompte_linia_factura."id" = x.id`;
        await pool.query(updateDescompteQuery, values);
      }
      if (descomptesAfegits && descomptesAfegits.length > 0) {
        const values = [];
        const placeholders = [];
        descomptesAfegits.forEach((descompte, index) => {
          const descompteDescripcio = descompte.descompteDescripcio || null;
          const baseImposableDescompte = parseFloat(descompte.baseImposableCalc);
          const percDescompte = parseFloat(descompte.descompteTipusDescompte) || null;
          // Añadir los valores al array y generar los placeholders dinámicamente
          values.push(liniaRebuda, descompteDescripcio, baseImposableDescompte, percDescompte);
          // Calcular el desplazamiento de placeholders correctamente
          const startIndex = index * 4 + 1;
          placeholders.push(`($${startIndex}, $${startIndex + 1}, $${startIndex + 2}, $${startIndex + 3})`);
        });
        const insertDescompteQuery = `
          INSERT INTO "${userSchema}".descompte_linia_factura ("linia factura", "Descripció", "Base descompte", "Percentatge")
          VALUES ${placeholders.join(', ')}`;
        await pool.query(insertDescompteQuery, values);
      }
      if (mitjaTransportNou && mitjaTransportNou.length > 0) {
        mitja = mitjaTransportNou[0];
        // Intentamos actualizar la fila existente
        const mitjaTransportUpdateQuery = `
          UPDATE "${userSchema}".mitja_transport_nou
          SET "Data primera entrada servei" = $2, 
              "Distància fins entrega" = $3, 
              "Hores fins entrega" = $4
          WHERE "linia factura" = $1`;
        const values = [liniaRebuda, mitja.dataMitja, mitja.distancia, mitja.hores];
        const result = await pool.query(mitjaTransportUpdateQuery, values);
        // Si no se actualizó ninguna fila, significa que no existía, entonces hacemos un INSERT
        if (result.rowCount === 0) {
          const mitjaTransportInsertQuery = `
          INSERT INTO "${userSchema}".mitja_transport_nou 
          ("linia factura", "Data primera entrada servei", "Distància fins entrega", "Hores fins entrega")
          VALUES ($1, $2, $3, $4)`;
          await pool.query(mitjaTransportInsertQuery, values);
        }
      } else {
        // Si el objeto está vacío o no existe, eliminar el registro asociado
        await pool.query(`
          DELETE FROM "${userSchema}".mitja_transport_nou
          WHERE "linia factura" = $1`,
          [liniaRebuda]
        );
      }
      await pool.query('COMMIT');
      const resultat = await pool.query(`
        SELECT "Sèrie factura", "Número factura"
        FROM "${userSchema}".dades_linia_factura
        WHERE "id" = $1;
      `, [liniaRebuda]);
      const { "Sèrie factura": serie, "Número factura": numero } = resultat.rows[0];
      await updateEstatFactura(serie, numero, userSchema);
      res.status(200).json({ missatge: 'linia factura modificada correctamente' });
    } else { // Es un INSERT
      const columns = Object.keys(cambios).map(col => `"${col}"`).join(', ');
      const values = Object.values(cambios);
      const placeholders = values.map((_, index) => `$${index + 1}`).join(', ');
      const insertLiniaQuery = `
        INSERT INTO "${userSchema}".dades_linia_factura (${columns})
        VALUES (${placeholders})
        RETURNING "id"`;
      const result = await pool.query(insertLiniaQuery, values);
      if (result.rows.length === 0) {
        throw new Error("Error al insertar línea de factura");
      }
      const lineaId = result.rows[0].id;
      cambiosOpcionales["id"] = lineaId;
      const columnsOpcionals = Object.keys(cambiosOpcionales).map(col => `"${col}"`).join(', ');
      const valuesOpcionals = Object.values(cambiosOpcionales);
      const placeholdersOpcionals = valuesOpcionals.map((_, index) => `$${index + 1}`).join(', ');
      const insertLiniaQueryOpcional = `
          INSERT INTO "${userSchema}".dades_linia_factura_opcionals (${columnsOpcionals})
          VALUES (${placeholdersOpcionals})`;
      await pool.query(insertLiniaQueryOpcional, valuesOpcionals);
      if (impostosAfegits && impostosAfegits.length > 0) {
        const values = [];
        const placeholders = [];
        impostosAfegits.forEach((impost, index) => {
          const valorImpost = impost.impostTipus;
          const baseImposableImpost = impost.baseImposableCalc;
          const percImpost = impost.impostTipusImpositiu || null; // Si es '' o undefined, se convierte en null
          // Añadir los valores al array y generar los placeholders dinámicamente
          values.push(lineaId, valorImpost, baseImposableImpost, percImpost);
          // Calcular el desplazamiento de placeholders correctamente
          const startIndex = index * 4 + 1;
          placeholders.push(`($${startIndex}, $${startIndex + 1}, $${startIndex + 2}, $${startIndex + 3})`);
        });
        const insertImpostQuery = `
          INSERT INTO "${userSchema}".impost_linia_factura ("linia factura", "impost", "Base imposable", "Tipus impositiu")
          VALUES ${placeholders.join(', ')}`;
        await pool.query(insertImpostQuery, values);
      }
      if (descomptesAfegits && descomptesAfegits.length > 0) {
        const values = [];
        const placeholders = [];
        descomptesAfegits.forEach((descompte, index) => {
          const descompteDescripcio = descompte.descompteDescripcio || null;
          const baseImposableDescompte = parseFloat(descompte.baseImposableCalc);
          const percDescompte = parseFloat(descompte.descompteTipusDescompte) || null;
          // Añadir los valores al array y generar los placeholders dinámicamente
          values.push(lineaId, descompteDescripcio, baseImposableDescompte, percDescompte);
          // Calcular el desplazamiento de placeholders correctamente
          const startIndex = index * 4 + 1;
          placeholders.push(`($${startIndex}, $${startIndex + 1}, $${startIndex + 2}, $${startIndex + 3})`);
        });
        const insertDescompteQuery = `
          INSERT INTO "${userSchema}".descompte_linia_factura ("linia factura", "Descripció", "Base descompte", "Percentatge")
          VALUES ${placeholders.join(', ')}`;
        await pool.query(insertDescompteQuery, values);
      }
      if (mitjaTransportNou.length > 0) {
        mitja = mitjaTransportNou[0];
        const mitjaTransportQuery = `
          INSERT INTO "${userSchema}".mitja_transport_nou 
          ("linia factura", "Data primera entrada servei", "Distància fins entrega", "Hores fins entrega")
          VALUES ($1, $2, $3, $4)`;
        const values = [lineaId, mitja.dataMitja, mitja.distancia, mitja.hores];
        await pool.query(mitjaTransportQuery, values); // Ejecutar consulta con pg
      }
      await pool.query('COMMIT');
      const resultat = await pool.query(`
        SELECT "Sèrie factura", "Número factura"
        FROM "${userSchema}".dades_linia_factura
        WHERE "id" = $1;
      `, [lineaId]);
      const { "Sèrie factura": serie, "Número factura": numero } = resultat.rows[0];
      await updateEstatFactura(serie, numero, userSchema);
      res.status(200).json({ missatge: 'linia factura insertada correctamente' });
    }
  } catch (error) {
    if (transaccionIniciada) {
      await pool.query('ROLLBACK');
    }
    console.error('Error en /afegir_linia_factura:', error);
    winston.error('Error en /afegir_linia_factura:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_linia_factura', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    const { serie, numero } = req.query;
    if (!serie || !numero) {
      return res.status(400).json({ missatge: 'Sèrie o número de la factura no proporcionats' });
    }
    // Obtener nombres de columnas de ambas tablas
    const [columnes, columnesOpcionals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_linia_factura']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_linia_factura_opcionals'])
    ]);
    // Filtrar columnas innecesarias
    const camps = columnes.rows.map(row => row.column_name);
    const campsOpcionals = columnesOpcionals.rows
      .map(row => row.column_name)
      .filter(col => col !== "id");
    // Construcción de la lista de columnas con prefijo de tabla
    const columnsQuery = [
      ...camps.map(col => `"${userSchema}".dades_linia_factura."${col}"`),
      ...campsOpcionals.map(col => `"${userSchema}".dades_linia_factura_opcionals."${col}"`)
    ].join(', ');
    // Consulta con subconsultas para evitar duplicación de datos
    const dades = await pool.query(`
      SELECT 
        ${columnsQuery},
        COALESCE(impostos_json, '[]') AS impostos,
        COALESCE(descomptes_json, '[]') AS descomptes,
        COALESCE(mitja_transport_json, '[]') AS mitja_transport_nou
      FROM "${userSchema}".dades_linia_factura
      LEFT JOIN "${userSchema}".dades_linia_factura_opcionals 
        ON "${userSchema}".dades_linia_factura."id" = "${userSchema}".dades_linia_factura_opcionals."id"
      LEFT JOIN (
        SELECT 
          "linia factura",
          json_agg(
            json_build_object(
              'impost', "impost",
              'Base imposable', "Base imposable",
              'Tipus impositiu', "Tipus impositiu",
              'id', "id"
            )
          ) AS impostos_json
        FROM "${userSchema}".impost_linia_factura
        GROUP BY "linia factura"
      ) ilf ON "${userSchema}".dades_linia_factura."id" = ilf."linia factura"
      LEFT JOIN (
        SELECT 
          "linia factura",
          json_agg(
            json_build_object(
              'Descripció', "Descripció",
              'Base descompte', "Base descompte",
              'Percentatge', "Percentatge",
              'id', "id"
            )
          ) AS descomptes_json
        FROM "${userSchema}".descompte_linia_factura
        GROUP BY "linia factura"
      ) dlf ON "${userSchema}".dades_linia_factura."id" = dlf."linia factura"
      LEFT JOIN (
        SELECT 
          "linia factura",
          json_agg(
            json_build_object(
              'Data primera entrada servei', "Data primera entrada servei",
              'Distància fins entrega', "Distància fins entrega",
              'Hores fins entrega', "Hores fins entrega"
            )
          ) AS mitja_transport_json
        FROM "${userSchema}".mitja_transport_nou
        GROUP BY "linia factura"
      ) mtf ON "${userSchema}".dades_linia_factura."id" = mtf."linia factura"
      WHERE "${userSchema}".dades_linia_factura."Sèrie factura" = $1
      AND "${userSchema}".dades_linia_factura."Número factura" = $2;
    `, [serie, numero]);
    // Enviar datos en formato JSON
    res.json({
      camps: camps,
      camps_opcionals: campsOpcionals,
      valors: dades.rows,
    });
    console.log('Dades de línies de factura enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_linia_factura:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.delete('/linia_factura', authMiddleware, async (req, res) => {
  console.log('DELETE /linia_factura');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { idLiniaFactura } = req.body;
    console.log('-idLiniaFactura:', idLiniaFactura);
    if (idLiniaFactura) {
      // Query para la eliminación
      const deleteQuery = `DELETE FROM "${userSchema}".dades_linia_factura WHERE "id" = $1`;
      const resultat = await pool.query(`
        SELECT "Sèrie factura", "Número factura"
        FROM "${userSchema}".dades_linia_factura
        WHERE "id" = $1;
      `, [idLiniaFactura]);
      // Ejecutar la consulta con los valores actualizados
      await pool.query(deleteQuery, [idLiniaFactura]);
      const { "Sèrie factura": serie, "Número factura": numero } = resultat.rows[0];
      await updateEstatFactura(serie, numero, userSchema);
      res.status(200).json({ missatge: 'linia factura eliminada correctament' });
    } else {
      res.status(500).json({ missatge: 'Datos no válidos para la eliminación' });
    }
  } catch (error) {
    winston.error('Error en /linia_factura:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/impostos', authMiddleware, async (req, res) => {
  try {
    // Obtener todas las columnas de la tabla impostos.impostos
    const columnes = await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'impostos' AND table_name = 'impostos'
      ORDER BY ordinal_position;
    `);
    if (columnes.rowCount === 0) {
      return res.status(404).json({ missatge: 'No s\'han trobat columnes a la taula impostos' });
    }
    const camps = columnes.rows.map(row => row.column_name);
    const columnsQuery = camps.map(col => `"${col}"`).join(', '); // Escapar correctamente las columnas
    // Obtener los datos de la tabla impostos.impostos
    const dades = await pool.query(`SELECT ${columnsQuery} FROM impostos.impostos;`);
    res.json({
      camps_impostos: camps,
      valors_impostos: dades.rows.length > 0 ? dades.rows : 'No hi ha dades disponibles',
    });
    console.log('Dades dels impostos enviades correctament');
  } catch (error) {
    winston.error('Error en /impostos:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_plantilla', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas de ambas tablas
    const [columnes_dades_personals, columnesOpcionals_dades_personals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_personals']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_personals_opcionals'])
    ]);
    // Responder con los datos obtenidos
    res.json({
      camps_dades_personals: columnes_dades_personals.rows.map(row => row.column_name), // Nombres de columnas de dades_personals
      camps_opcionals_dades_personals: columnesOpcionals_dades_personals.rows.map(row => row.column_name), // Nombres de columnas de dades_personals_opcionals
    });
    console.log('Dades plantilla enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_plantilla:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

// Ruta para ejecutar el script Python
app.get('/run-script', authMiddleware, async (req, res) => {
  const [user, caducada] = await verifyAuth(req, res);
  if (user) {
    req.user = user;
    try {
      var valors_personals = [];
      var valors_opcionals_personals = [];
      var valors_clients = [];
      var valors_opcionals_clients = [];
      var camps_factura = [];
      var camps_opcionals_factura = [];
      var camps_linia_factura = [];
      var camps_opcionals_linia_factura = [];
      var camps_producte = [];
      var camps_opcionals_producte = [];
      var camps_impostos = [];
      var camps_descomptes = [];
      var camps_pagament_factura = [];
      var camps_circumstancies = [];
      var camps_pagaments = [];
      var camps_pagament = [];
      var email = "";
      var userSchema = "";
      try {
        email = req.user; // Extraer el email del token
        userSchema = encodeURIComponent(email);
        // Obtener los nombres de las columnas de ambas tablas
        const [columnes_personals, columnes_opcionals_personals, columnes_clients, columnes_opcionals_clients, columnes_factura, columnes_opcionals_factura, columnes_linia_factura, columnes_opcionals_linia_factura, columnes_producte, columnes_opcionals_producte, columnes_impostos, columnes_descomptes, columnes_pagament_factura, columnes_circumstancia, columnes_pagaments, columnes_pagament] = await Promise.all([
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_personals']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_personals_opcionals']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_clients']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_clients_opcionals']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_factures']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_factures_opcionals']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_linia_factura']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_linia_factura_opcionals']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_productes']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_productes_opcionals']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'impost_linia_factura']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'descompte_linia_factura']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_pagament_factura']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'circumstancies_factures']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'pagaments_anticipats']),
          pool.query(`
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = $1 AND table_name = $2;
          `, [userSchema, 'dades_pagament'])
        ]);
        valors_personals = columnes_personals.rows.map(row => row.column_name).filter(col => col !== "Tipus de persona" && col !== "Tipus de residència" && col !== "Codi de l'òrgan gestor" && col !== "Codi de la unitat tramitadora" && col !== "Codi de l'oficina comptable"); // Nombres de columnas de dades_personals
        valors_opcionals_personals = columnes_opcionals_personals.rows.map(row => row.column_name); // Nombres de columnas de dades_personals_opcionals
        valors_clients = columnes_clients.rows.map(row => row.column_name).filter(col => col !== "Tipus de persona" && col !== "Tipus de residència" && col !== "Codi de l'òrgan gestor" && col !== "Codi de la unitat tramitadora" && col !== "Codi de l'oficina comptable"); // Nombres de columnas de dades_personals; // Filtrar la columna conflictiva de opcionales; // Nombres de columnas de dades_clients
        valors_opcionals_clients = columnes_opcionals_clients.rows.map(row => row.column_name).filter(col => col !== "Número d'identificació fiscal"); // Nombres de columnas de dades_personals; // Filtrar la columna conflictiva de opcionales
        camps_factura = columnes_factura.rows.map(row => row.column_name).filter(col => col !== "Estat" && col !== "Client" && col !== "id" && col !== "Sèrie"); // Nombres de columnas de dades_factures
        camps_opcionals_factura = columnes_opcionals_factura.rows.map(row => row.column_name).filter(col => col !== "Sèrie" && col !== "Número"); // Nombres de columnas de dades_factures_opcionals
        camps_linia_factura = columnes_linia_factura.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "Codi producte" && col !== "id");
        camps_opcionals_linia_factura = columnes_opcionals_linia_factura.rows.map(row => row.column_name).filter(col => col !== "id");
        camps_producte = columnes_producte.rows.map(row => row.column_name).filter(col => col !== "Preu unitari"); // Nombres de columnas de dades_productes
        camps_opcionals_producte = columnes_opcionals_producte.rows.map(row => row.column_name).filter(col => col !== "Codi");
        camps_impostos = columnes_impostos.rows.map(row => row.column_name).filter(col => col !== "linia factura" && col !== "id"); // Nombres de columnas de impostos
        camps_descomptes = columnes_descomptes.rows.map(row => row.column_name).filter(col => col !== "linia factura" && col !== "id"); // Nombres de columnas de descomptes
        camps_pagament_factura = columnes_pagament_factura.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id" && col !== "Mitjà de pagament");
        camps_circumstancies = columnes_circumstancia.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id");
        camps_pagaments = columnes_pagaments.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id");
        camps_pagament = columnes_pagament.rows.map(row => row.column_name).filter(col => col !== "id");
        valors_personals = generarPlaceholders(valors_personals, 'Personal');
        valors_opcionals_personals = generarPlaceholders(valors_opcionals_personals, 'Personal_Opcional');
        valors_clients = generarPlaceholders(valors_clients, 'Client');
        valors_opcionals_clients = generarPlaceholders(valors_opcionals_clients, 'Client_Opcional');
        var valors_factura = generarPlaceholders(camps_factura, 'Factura');
        var valors_opcionals_factura = generarPlaceholders(camps_opcionals_factura, 'Factura_Opcional');
        var valors_linia_factura = generarPlaceholders(camps_linia_factura, 'Linia');
        var valors_opcionals_linia_factura = generarPlaceholders(camps_opcionals_linia_factura, 'Linia_Opcional');
        var valors_producte = generarPlaceholders(camps_producte, 'Producte');
        var valors_opcionals_producte = generarPlaceholders(camps_opcionals_producte, 'Producte_Opcional');
        var valors_impostos = generarPlaceholders(camps_impostos, 'Impost_Linia');
        var valors_descomptes = generarPlaceholders(camps_descomptes, 'Descompte_Linia');
        var valors_pagament_factura = generarPlaceholders(camps_pagament_factura, 'Pagament');
        var valors_circumstancies = generarPlaceholders(camps_circumstancies, 'Condició');
        var valors_pagaments = generarPlaceholders(camps_pagaments, 'Pagament_Anticipat');
        var valors_pagament = generarPlaceholders(camps_pagament, 'Pagament');
        /*
        console.log('Dades per a la plantilla:',
          valors_personals,
          valors_opcionals_personals,
          valors_clients,
          valors_opcionals_clients,
          camps_factura,
          valors_factura,
          camps_opcionals_factura,
          valors_opcionals_factura,
          camps_linia_factura,
          valors_linia_factura,
          camps_opcionals_linia_factura,
          valors_opcionals_linia_factura,
          camps_producte,
          valors_producte,
          camps_opcionals_producte,
          valors_opcionals_producte,
          camps_impostos,
          valors_impostos,
          camps_descomptes,
          valors_descomptes,
          camps_pagament_factura,
          valors_pagament_factura,
          camps_circumstancies,
          valors_circumstancies,
          camps_pagaments,
          valors_pagaments,
          camps_pagament,
          valors_pagament
        );
       */
      } catch (error) {
        winston.error('Error en obtenir les dades en /run-script:', error);
        res.status(500).json({ missatge: 'Error en el servidor' });
      }
      const allData = {
        valors_personals: valors_personals,
        valors_opcionals_personals: valors_opcionals_personals,
        valors_clients: valors_clients,
        valors_opcionals_clients: valors_opcionals_clients,
        camps_factura: camps_factura,
        valors_factura: valors_factura,
        camps_opcionals_factura: camps_opcionals_factura,
        valors_opcionals_factura: valors_opcionals_factura,
        camps_linia_factura: camps_linia_factura,
        valors_linia_factura: valors_linia_factura,
        camps_opcionals_linia_factura: camps_opcionals_linia_factura,
        valors_opcionals_linia_factura: valors_opcionals_linia_factura,
        camps_producte: camps_producte,
        valors_producte: valors_producte,
        camps_opcionals_producte: camps_opcionals_producte,
        valors_opcionals_producte: valors_opcionals_producte,
        camps_impostos: camps_impostos,
        valors_impostos: valors_impostos,
        camps_descomptes: camps_descomptes,
        valors_descomptes: valors_descomptes,
        camps_pagament_factura,
        valors_pagament_factura,
        camps_circumstancies,
        valors_circumstancies,
        camps_pagaments,
        valors_pagaments,
        camps_pagament,
        valors_pagament,
        user_path: `/srv/facturacio/data/${userSchema}`
      };
      //console.log('Script iniciat, Dades:', JSON.stringify(allData, null, 2));
      //console.log('Script iniciat, Dades:', allData);
      // Crear el proceso de Python y pasarle allData a través de stdin usando pipes
      const pythonProcess = spawn('python3', ['plantilla.py']);
      pythonProcess.stdin.write(JSON.stringify(allData));
      pythonProcess.stdin.end();
      let output = '';
      pythonProcess.stdout.on('data', (data) => {
        output += data.toString();
      });
      pythonProcess.stderr.on('data', (data) => {
        output += data.toString();
      });
      pythonProcess.on('close', (code) => {
        if (code !== 0) {
          winston.error('Error en ejecutar /run-script:');
          return res.status(500).json({ error: 'Error al ejecutar el script' });
        }
        res.json({
          message: 'Script ejecutado con éxito', output
        });
        console.log('Dades plantilla enviades correctament');
      });
    } catch (error) {
      winston.error('Error al ejecutar el script:', error);
      res.status(500).json({ error: 'Error en el servidor', details: error.message });
    }
  } else {
    console.log('No autenticado');
    if (caducada === true) {
      return res.status(408).json({ mensaje: 'Sessió caducada' });
    } else {
      return res.status(401).json({ mensaje: 'No autenticado' });
    }
  }
});

app.get('/plantilla_personal', authMiddleware, async (req, res) => {
  const email = req.user; // Extraer el email del token
  const userSchema = encodeURIComponent(email);
  try {
    const filePath = path.join('/srv/facturacio/data', userSchema, 'plantilla_personal.pdf');
    if (fs.existsSync(filePath)) {
      res.setHeader('Content-Type', 'application/pdf'); // Ajusta el tipo MIME si es necesario
      res.sendFile(filePath);
    } else {
      res.status(410).json({ message: 'Arxiu no trobat' });
    }
  } catch (error) {
    winston.error('Error en /plantilla_personal:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/plantilla_personal_descarrega', authMiddleware, async (req, res) => {
  const email = req.user; // Extraer el email del token
  const userSchema = encodeURIComponent(email);
  try {
    const filePath = path.join('/srv/facturacio/data', userSchema, 'plantilla_personal.odt');
    if (fs.existsSync(filePath)) {
      res.setHeader('Content-Type', 'application/vnd.oasis.opendocument.text'); // Tipo correcto para ODT
      res.setHeader('Content-Disposition', 'attachment; filename="plantilla_personal.odt"'); // Forzar descarga
      res.sendFile(filePath);
    } else {
      res.status(410).json({ message: 'Arxiu no trobat' });
    }
  } catch (error) {
    winston.error('Error en /plantilla_personal_descarrega:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.post("/pujar_plantilla", authMiddleware, upload.single("plantilla"), async (req, res) => {
  if (!req.file) {
    return res.status(409).json({ message: "No s'ha enviat cap fitxer o el format no és vàlid." });
  }
  const email = req.user; // Extraer email del token
  const userSchema = encodeURIComponent(email);
  const uploadDir = path.join("/srv/facturacio/data", userSchema);
  if (!fs.existsSync(uploadDir)) {
    return res.status(409).json({ message: "No s'ha trobat el directori de l'usuari." });
  }
  const filePath = path.join(uploadDir, "plantilla_personal_tmp.odt");
  try {
    fs.renameSync(req.file.path, filePath);
  } catch (error) {
    console.error("Error en la pujada:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
  //Recopilar dades obligatories i passarles a forma de tag
  try {
    var valors_personals = [];
    var valors_clients = [];
    var camps_factura = [];
    var camps_linia_factura = [];
    var camps_impostos = [];
    var camps_descomptes = [];
    var camps_producte = [];
    var camps_pagament_factura = [];
    var camps_circumstancies = [];
    var camps_pagaments = [];
    var camps_pagament = [];
    try {
      // Obtener los nombres de las columnas de ambas tablas
      const [columnes_personals, columnes_clients, columnes_factura, columnes_linia_factura, columnes_impostos, columnes_descomptes, columnes_productes, columnes_pagament_factura, columnes_circumstancia, columnes_pagaments, columnes_pagament] = await Promise.all([
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'dades_personals']),
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'dades_clients']),
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'dades_factures']),
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'dades_linia_factura']),
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'impost_linia_factura']),
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'descompte_linia_factura']),
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'dades_productes']),
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'dades_pagament_factura']),
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'circumstancies_factures']),
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'pagaments_anticipats']),
        pool.query(`
          SELECT column_name
          FROM information_schema.columns
          WHERE table_schema = $1 AND table_name = $2;
        `, [userSchema, 'dades_pagament'])
      ]);
      valors_personals = columnes_personals.rows.map(row => row.column_name).filter(col => col !== "Tipus de persona" && col !== "Tipus de residència"); // Nombres de columnas de dades_personals
      valors_clients = columnes_clients.rows.map(row => row.column_name).filter(col => col !== "Tipus de persona" && col !== "Tipus de residència" && col !== "Codi de l'òrgan gestor" && col !== "Codi de la unitat tramitadora" && col !== "Codi de l'oficina comptable"); // Nombres de columnas de dades_clients
      camps_factura = columnes_factura.rows.map(row => row.column_name).filter(col => col !== "Estat" && col !== "Client" && col !== "id" && col !== "Sèrie"); // Nombres de columnas de dades_factures
      camps_linia_factura = columnes_linia_factura.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "Codi producte" && col !== "id")
      camps_impostos = columnes_impostos.rows.map(row => row.column_name).filter(col => col !== "linia factura" && col !== "id"); // Nombres de columnas de impostos
      camps_descomptes = columnes_descomptes.rows.map(row => row.column_name).filter(col => col !== "linia factura" && col !== "id"); // Nombres de columnas de descomptes
      camps_producte = columnes_productes.rows.map(row => row.column_name).filter(col => col === "Unitats"); // Només ens quedem amb les unitats
      camps_pagament_factura = columnes_pagament_factura.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id" && col !== "Mitjà de pagament");
      camps_circumstancies = columnes_circumstancia.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id");
      camps_pagaments = columnes_pagaments.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id");
      camps_pagament = columnes_pagament.rows.map(row => row.column_name).filter(col => col !== "id");
      valors_personals = generarPlaceholders(valors_personals, 'Personal');
      valors_clients = generarPlaceholders(valors_clients, 'Client');
      var valors_factura = generarPlaceholders(camps_factura, 'Factura');
      var valors_linia_factura = generarPlaceholders(camps_linia_factura, 'Linia');
      var valors_impostos = generarPlaceholders(camps_impostos, 'Impost_Linia');
      var valors_descomptes = generarPlaceholders(camps_descomptes, 'Descompte_Linia');
      var valors_producte = generarPlaceholders(camps_producte, 'Producte');
      var valors_pagament_factura = generarPlaceholders(camps_pagament_factura, 'Pagament');
      var valors_circumstancies = generarPlaceholders(camps_circumstancies, 'Condició');
      var valors_pagaments = generarPlaceholders(camps_pagaments, 'Pagament_Anticipat');
      var valors_pagament = generarPlaceholders(camps_pagament, 'Pagament');
      if (valors_producte.length > 0) {
        valors_linia_factura.push(valors_producte[0]);
      }
    } catch (error) {
      winston.error('Error en obtenir les dades /pujar_plantilla:', error);
      res.status(500).json({ missatge: 'Error en el servidor' });
    }
    const allData = {
      valors_personals: valors_personals,
      valors_clients: valors_clients,
      valors_factura: valors_factura,
      valors_linia_factura: valors_linia_factura,
      valors_impostos: valors_impostos,
      valors_descomptes: valors_descomptes,
      valors_pagament_factura,
      valors_circumstancies,
      valors_pagaments,
      valors_pagament,
      user_path: `/srv/facturacio/data/${userSchema}`
    };
    const pythonProcess = spawn('python3', ['pujar_plantilla.py']);
    pythonProcess.stdin.write(JSON.stringify(allData));
    pythonProcess.stdin.end();
    let output = '';
    pythonProcess.stdout.on('data', (data) => {
      output += data.toString();
    });
    pythonProcess.stderr.on('data', (data) => {
      winston.error(`Error en STDERR: ${data.toString()}`);
      throw new Error(data.toString());
    });
    pythonProcess.on('close', (code) => {
      try {
        const result = JSON.parse(output);
        if (code !== 0) {
          winston.error('Error en pujar_plantilla: Faltan placeholders.');
          //console.log('---------------Error en pujar_plantilla: Faltan placeholders. Result:', result);
          //console.log('---------------', result.placeholders_faltantes);
          return res.status(400).json({
            error: 'Faltan placeholders en la plantilla.',
            placeholders_faltantes: result.placeholders_faltantes || []
          });
        }
        //Revisar si tinc odt i pdf
        const odtpath = `/srv/facturacio/data/${userSchema}/plantilla_personal_tmp.odt`;
        const pdfpath = `/srv/facturacio/data/${userSchema}/plantilla_personal_tmp.pdf`;
        if (fs.existsSync(odtpath) && fs.existsSync(pdfpath)) {
          fs.renameSync(odtpath, `/srv/facturacio/data/${userSchema}/plantilla_personal.odt`);
          fs.renameSync(pdfpath, `/srv/facturacio/data/${userSchema}/plantilla_personal.pdf`);
        }
        res.json({ message: 'Script ejecutado con éxito' });
      } catch (error) {
        winston.error('Error al parsear la salida del script:', error);
        return res.status(500).json({ error: 'Error al procesar la salida del script' });
      }
    });
  } catch (error) {
    winston.error('Error al ejecutar el script:', error);
    res.status(500).json({ error: 'Error en el servidor', details: error.message });
  }
  //res.json({ message: "Plantilla pujada correctament!" });
});

app.get('/factura_pdf', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    const { serie, numero } = req.query;
    if (!serie || !numero) {
      return res.status(400).json({ missatge: 'Sèrie o número de la factura no proporcionats' });
    }
    //Obtenir el id de la factura
    var idFactura = await pool.query(`
      SELECT "id"
      FROM "${userSchema}".dades_factures
      WHERE "Sèrie" = $1 AND "Número" = $2;
    `, [serie, numero]);
    if (idFactura.rowCount === 0) {
      return res.status(404).json({ missatge: 'Factura no trobada' });
    } else {
      idFactura = idFactura.rows[0].id;
      console.log('GENERAR PDF PLANTILLA: idFactura:', idFactura);
      var clientId = await pool.query(`
        SELECT "Client"
        FROM "${userSchema}".dades_factures
        WHERE "id" = $1;
      `, [idFactura]);
      if (clientId.rowCount === 0) {
        return res.status(404).json({ missatge: 'Client no trobat' });
      } else {
        clientId = clientId.rows[0].Client;
      }
      var serieId = await pool.query(`
        SELECT "Sèrie"
        FROM "${userSchema}".dades_factures
        WHERE "id" = $1;
      `, [idFactura]);
      if (serieId.rowCount === 0) {
        return res.status(404).json({ missatge: 'Sèrie no trobada' });
      } else {
        serieId = serieId.rows[0]['Sèrie'];
      }
      //Obtenir i consultar tots els placeholders i dades de la plantilla
      try {
        var placeholders_personals = [];
        var placeholders_opcionals_personals = [];
        var placeholders_clients = [];
        var placeholders_opcionals_clients = [];
        var placeholders_factura = [];
        var placeholders_opcionals_factura = [];
        var placeholders_lina_factura = [];
        var placeholders_opcionals_linia_factura = [];
        var placeholders_producte = [];
        var placeholders_opcionals_producte = [];
        var placeholders_descomptes = [];
        var placeholders_impostos = [];
        var placeholders_pagament_factura = [];
        var placeholders_circumstancies = [];
        var placeholders_pagaments = [];
        var placeholders_pagament = [];
        try {
          // Obtener los nombres de las columnas de ambas tablas
          //const [columnes_personals, columnes_opcionals_personals, columnes_clients, columnes_opcionals_clients, columnes_factura, columnes_opcionals_factura, columnes_linia_factura, columnes_opcionals_linia_factura, columnes_producte, columnes_opcionals_producte, columnes_impostos, columnes_descomptes] = await Promise.all([
          var [columnes_personals, columnes_opcionals_personals, columnes_clients, columnes_opcionals_clients, columnes_factura, columnes_opcionals_factura, columnes_linia_factura, columnes_opcionals_linia_factura, columnes_producte, columnes_opcionals_producte, columnes_descomptes, columnes_impostos, columnes_pagament_factura, columnes_circumstancia, columnes_pagaments, columnes_pagament] = await Promise.all([
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_personals']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_personals_opcionals']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_clients']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_clients_opcionals']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_factures']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_factures_opcionals']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_linia_factura']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_linia_factura_opcionals']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_productes']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_productes_opcionals']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'descompte_linia_factura']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'impost_linia_factura']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_pagament_factura']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'circumstancies_factures']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'pagaments_anticipats']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_pagament'])
          ]);
          columnes_personals = columnes_personals.rows.map(row => row.column_name); // Nombres de columnas de dades_personals
          columnes_opcionals_personals = columnes_opcionals_personals.rows.map(row => row.column_name);
          columnes_clients = columnes_clients.rows.map(row => row.column_name); // Nombres de columnas de dades_clients
          columnes_opcionals_clients = columnes_opcionals_clients.rows.map(row => row.column_name).filter(col => col !== "Número d'identificació fiscal"); // Filtrar la columna conflictiva de opcionales
          columnes_factura = columnes_factura.rows.map(row => row.column_name).filter(col => col !== "Estat" && col !== "Client" && col !== "id" && col !== "Sèrie"); // Nombres de columnas de dades_clients
          columnes_opcionals_factura = columnes_opcionals_factura.rows.map(row => row.column_name).filter(col => col !== "Sèrie" && col !== "Número"); // Filtrar la columna conflictiva de opcionales
          columnes_linia_factura = columnes_linia_factura.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "Codi producte" && col !== "id")
          columnes_opcionals_linia_factura = columnes_opcionals_linia_factura.rows.map(row => row.column_name).filter(col => col !== "id");
          columnes_producte = columnes_producte.rows.map(row => row.column_name).filter(col => col !== "Preu unitari"); // Nombres de columnas de dades_productes
          columnes_opcionals_producte = columnes_opcionals_producte.rows.map(row => row.column_name).filter(col => col !== "Codi");
          columnes_descomptes = columnes_descomptes.rows.map(row => row.column_name).filter(col => col !== "linia factura" && col !== "id"); // Nombres de columnas de descomptes
          columnes_impostos = columnes_impostos.rows.map(row => row.column_name).filter(col => col !== "linia factura" && col !== "id"); // Nombres de columnas de impostos
          columnes_pagament_factura = columnes_pagament_factura.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id");
          columnes_circumstancia = columnes_circumstancia.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id");
          columnes_pagaments = columnes_pagaments.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id");
          columnes_pagament = columnes_pagament.rows.map(row => row.column_name).filter(col => col !== "id"); // Nombres de columnas de dades_pagament
          var [dades_personals, dades_opcionals_personals, dades_clients, dades_opcionals_clients, dades_factura, dades_opcionals_factura, dades_linies_factura, dades_serie, dades_pagament_factura, dades_circumstancia, dades_pagaments] = await Promise.all([
            pool.query(`
              SELECT ${columnes_personals.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_personals;
            `),
            pool.query(`
              SELECT ${columnes_opcionals_personals.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_personals_opcionals;
            `),
            pool.query(`
              SELECT ${columnes_clients.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_clients
              WHERE "Número d'identificació fiscal" = $1;
              `, [clientId]),
            pool.query(`
              SELECT ${columnes_opcionals_clients.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_clients_opcionals
              WHERE "Número d'identificació fiscal" = $1;
              `, [clientId]),
            pool.query(`
              SELECT ${columnes_factura.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_factures
              WHERE "Sèrie" = $1 AND "Número" = $2;
            `, [serie, numero]),
            pool.query(`
              SELECT ${columnes_opcionals_factura.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_factures_opcionals
              WHERE "Sèrie" = $1 AND "Número" = $2;
            `, [serie, numero]),
            pool.query(`
              SELECT 
                ${columnes_linia_factura.map(col => `"${col}"`).join(', ')},
                COALESCE(opcionals_json, '[]') AS opcionals,
                COALESCE(impostos_json, '[]') AS impostos,
                COALESCE(descomptes_json, '[]') AS descomptes,
                COALESCE(mitja_transport_json, '[]') AS mitja_transport_nou,
                COALESCE(producte_json, '[]') AS producte
              FROM "${userSchema}".dades_linia_factura
              LEFT JOIN (
                SELECT 
                  "id",
                  json_agg(
                    json_build_object(
                      ${columnes_opcionals_linia_factura.map(col => `'${col}', "${col}"`).join(',\n        ')}
                    )
                  ) AS opcionals_json
                FROM "${userSchema}".dades_linia_factura_opcionals
                GROUP BY "id"
              ) opf ON "${userSchema}".dades_linia_factura."id" = opf."id"
              LEFT JOIN (
                SELECT 
                  "linia factura",
                  json_agg(
                    json_build_object(
                      'impost', "impost",
                      'Base imposable', "Base imposable",
                      'Tipus impositiu', "Tipus impositiu"
                    )
                  ) AS impostos_json
                FROM "${userSchema}".impost_linia_factura
                GROUP BY "linia factura"
              ) ilf ON "${userSchema}".dades_linia_factura."id" = ilf."linia factura"
              LEFT JOIN (
                SELECT 
                  "linia factura",
                  json_agg(
                    json_build_object(
                      'Descripció', "Descripció",
                      'Base descompte', "Base descompte",
                      'Percentatge', "Percentatge"
                    )
                  ) AS descomptes_json
                FROM "${userSchema}".descompte_linia_factura
                GROUP BY "linia factura"
              ) dlf ON "${userSchema}".dades_linia_factura."id" = dlf."linia factura"
              LEFT JOIN (
                SELECT 
                  "linia factura",
                  json_agg(
                    json_build_object(
                      'Data primera entrada servei', "Data primera entrada servei",
                      'Distància fins entrega', "Distància fins entrega",
                      'Hores fins entrega', "Hores fins entrega"
                    )
                  ) AS mitja_transport_json
                FROM "${userSchema}".mitja_transport_nou
                GROUP BY "linia factura"
              ) mtf ON "${userSchema}".dades_linia_factura."id" = mtf."linia factura"
              LEFT JOIN (
                SELECT 
                  dp."Codi",
                  json_agg(
                    json_build_object(
                      ${columnes_producte.map(col => `'${col}', dp."${col}"`).join(',\n        ')},
                      'opcions', COALESCE(dpo.opcions_json, '[]')
                    )
                  ) AS producte_json
                FROM "${userSchema}".dades_productes dp
                LEFT JOIN (
                  SELECT 
                    "Codi",
                    json_agg(
                      json_build_object(
                        ${columnes_opcionals_producte.map(col => `'${col}', "${col}"`).join(',\n          ')}
                      )
                    ) AS opcions_json
                  FROM "${userSchema}".dades_productes_opcionals
                  GROUP BY "Codi"
                ) dpo ON dp."Codi" = dpo."Codi"
                GROUP BY dp."Codi"
              ) plf ON "${userSchema}".dades_linia_factura."Codi producte" = plf."Codi"
              WHERE "${userSchema}".dades_linia_factura."Sèrie factura" = $1
              AND "${userSchema}".dades_linia_factura."Número factura" = $2;
            `, [serie, numero]),
            pool.query(`
              SELECT "Codi", "Prefix", "Sufix"
              FROM "${userSchema}".dades_series
              WHERE "Codi" = $1;
            `, [serieId]),
            pool.query(`
              SELECT ${columnes_pagament_factura.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_pagament_factura
              WHERE "Sèrie factura" = $1 AND "Número factura" = $2;
            `, [serie, numero]),
            pool.query(`
              SELECT ${columnes_circumstancia.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".circumstancies_factures
              WHERE "Sèrie factura" = $1 AND "Número factura" = $2;
            `, [serie, numero]),
            pool.query(`
              SELECT ${columnes_pagaments.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".pagaments_anticipats
              WHERE "Sèrie factura" = $1 AND "Número factura" = $2;
            `, [serie, numero])
          ]);
          var dades_pagament = await pool.query(`
            SELECT ${columnes_pagament.map(col => `"${col}"`).join(', ')}
            FROM "${userSchema}".dades_pagament
            WHERE "id" = $1 ;
          `, [dades_pagament_factura.rows[0]["Mitjà de pagament"]]);
          if (dades_personals?.rows?.length > 0) {
            dades_personals = Object.values(dades_personals.rows[0]);
          } else {
            dades_personals = [];
          }
          //Cas on no es troben les dades personals
          if (dades_personals.length === 0) {
            return res.status(405).json({ missatge: 'No s\'han trobat dades personals' });
          }
          if (dades_opcionals_personals?.rows?.length > 0) {
            dades_opcionals_personals = Object.values(dades_opcionals_personals.rows[0]);
          } else {
            dades_opcionals_personals = [];
          }
          if (dades_clients?.rows?.length > 0) {
            dades_clients = Object.values(dades_clients.rows[0]);
          } else {
            dades_clients = [];
          }
          if (dades_opcionals_clients?.rows?.length > 0) {
            dades_opcionals_clients = Object.values(dades_opcionals_clients.rows[0]);
          } else {
            dades_opcionals_clients = [];
          }
          if (dades_factura?.rows?.length > 0) {
            dades_factura = Object.values(dades_factura.rows[0]);
          } else {
            dades_factura = [];
          }
          if (dades_opcionals_factura?.rows?.length > 0) {
            dades_opcionals_factura = Object.values(dades_opcionals_factura.rows[0]);
          } else {
            dades_opcionals_factura = [];
          }
          if (dades_pagament_factura?.rows?.length > 0) {
            dades_pagament_factura = Object.values(dades_pagament_factura.rows[0]);
          } else {
            dades_pagament_factura = [];
          }
          dades_circumstancia = dades_circumstancia?.rows?.length > 0
            ? dades_circumstancia.rows.map(row => Object.values(row))
            : [];
          dades_pagaments = dades_pagaments?.rows?.length > 0
            ? dades_pagaments.rows.map(row => Object.values(row))
            : [];
          if (dades_pagament?.rows?.length > 0) {
            dades_pagament = Object.values(dades_pagament.rows[0]);
          } else {
            dades_pagament = [];
          }
          dades_serie = dades_serie.rows[0]
          placeholders_personals = generarPlaceholders(columnes_personals, 'Personal');
          placeholders_opcionals_personals = generarPlaceholders(columnes_opcionals_personals, 'Personal_Opcional');
          placeholders_clients = generarPlaceholders(columnes_clients, 'Client');
          placeholders_opcionals_clients = generarPlaceholders(columnes_opcionals_clients, 'Client_Opcional');
          placeholders_factura = generarPlaceholders(columnes_factura, 'Factura');
          placeholders_opcionals_factura = generarPlaceholders(columnes_opcionals_factura, 'Factura_Opcional');
          placeholders_lina_factura = generarPlaceholders(columnes_linia_factura, 'Linia');
          placeholders_opcionals_linia_factura = generarPlaceholders(columnes_opcionals_linia_factura, 'Linia_Opcional');
          placeholders_producte = generarPlaceholders(columnes_producte, 'Producte');
          placeholders_opcionals_producte = generarPlaceholders(columnes_opcionals_producte, 'Producte_Opcional');
          placeholders_descomptes = generarPlaceholders(columnes_descomptes, 'Descompte_Linia');
          placeholders_descomptes.push('#Total_Descompte_Linia');
          placeholders_impostos = generarPlaceholders(columnes_impostos, 'Impost_Linia');
          placeholders_impostos.push('#Total_Impost_Linia');
          placeholders_pagament_factura = generarPlaceholders(columnes_pagament_factura, 'Pagament');
          placeholders_circumstancies = generarPlaceholders(columnes_circumstancia, 'Condició');
          placeholders_pagaments = generarPlaceholders(columnes_pagaments, 'Pagament_Anticipat');
          placeholders_pagament = generarPlaceholders(columnes_pagament, 'Pagament');
          var placeholders_subtotal_linia_factura = ['#Subtotal_Linia']
          var placeholders_total_linia_factura = ['#Total_Linia']
          var dades_linia_factura = [];
          var dades_opcionals_linia_factura = [];
          var dades_impostos = [];
          var dades_descomptes = [];
          //var mitja_transport_nou = [];
          var subtotal_linia_factura = [];
          var total_linia_factura = [];
          var dades_producte = [];
          var dades_opcionals_producte = [];
          var mitja_afegit = false;
          // Buscar si alguna circumstància conté "Mitjà de transport"
          const hiHaMitja = dades_circumstancia.some(arr =>
            typeof arr[0] === 'string' && arr[0].includes('Mitjà de transport')
          );
          for (var i = 0; i < dades_linies_factura.rows.length; i++) {
            const linia_obj = dades_linies_factura.rows[i];
            // Filtrar solo les claus que no siguin impostos, descomptes ni mitja_transport_nou
            const linia_filtrada = Object.fromEntries(
              Object.entries(linia_obj).filter(([key]) =>
                !['opcionals', 'impostos', 'descomptes', 'mitja_transport_nou', 'producte'].includes(key)
              )
            );
            //Si hi ha mitja de trensport
            if (hiHaMitja && Array.isArray(linia_obj.mitja_transport_nou) && linia_obj.mitja_transport_nou.length > 0) {
              var data_mitja = null;
              var hores_mitja = null;
              var distancies_mitja = null;
              var nom_mitja = null;
              const mitja_transport = linia_obj.mitja_transport_nou[0];
              console.log('Mitjà de transport:', mitja_transport);
              data_mitja = mitja_transport['Data primera entrada servei'];
              if (data_mitja) {
                const [year, month, day] = data_mitja.split("-");
                data_mitja = `${day}/${month}/${year}`;
              }
              hores_mitja = mitja_transport['Hores fins entrega'];
              distancies_mitja = mitja_transport['Distància fins entrega'];
              // Si també hi ha producte
              if (Array.isArray(linia_obj.producte) && linia_obj.producte.length > 0) {
                const producte = linia_obj.producte[0];
                console.log('Producte:', producte);
                nom_mitja = producte['Descripció'];
              }
              var text_mitja_circumstancia = `Mitjà de transport ${nom_mitja ?? "-"}, amb data de la primera entrada en servei el ${data_mitja ?? "-"}, ${hores_mitja ?? "-"} hores d'ús i ${distancies_mitja ?? "-"} quilòmetres fins a l'entrega`;
              dades_circumstancia.push([text_mitja_circumstancia]);
              mitja_afegit = true;
            }
            //console.log('Linia filtrada:', linia_filtrada);
            //console.log('Producte:', linia_obj.producte);
            if (Array.isArray(linia_obj.producte) && linia_obj.producte.length > 0) {
              const producte = linia_obj.producte[0];
              // Separamos los campos
              const { opcions, ...obligatoris } = producte;
              // Añadimos solo los valores obligatorios
              dades_producte.push(Object.values(obligatoris));
              // Añadimos solo los valores de los opcionales (si hay)
              if (Array.isArray(opcions) && opcions.length > 0) {
                dades_opcionals_producte.push(Object.values(opcions[0])); // solo el primero
              } else {
                dades_opcionals_producte.push([]);
              }
            } else {
              dades_producte.push([]);
              dades_opcionals_producte.push([]);
            }
            var preu_total_linia = parseFloat(parseFloat(linia_obj['Quantitat']) * parseFloat(linia_obj['Preu unitari'])).toFixed(2);
            if (isNaN(preu_total_linia)) {
              preu_total_linia = 0;
            }
            subtotal_linia_factura.push([preu_total_linia]);
            const linia_vals = Object.values(linia_filtrada);
            const impostos = [];
            const descomptes = [];
            if (Array.isArray(linia_obj.descomptes)) {
              for (const descompte of linia_obj.descomptes) {
                //console.log('Descompte:', descompte);
                var total_descompte = 0;
                var percentatge = parseFloat(descompte['Percentatge']);
                var base_descompte = parseFloat(descompte['Base descompte']);
                if (!isNaN(percentatge)) {
                  if (!isNaN(base_descompte)) {
                    total_descompte = parseFloat((base_descompte) * (parseFloat(percentatge) / 100)).toFixed(2);
                  } else {
                    total_descompte = 0;
                  }
                } else {
                  if (!isNaN(base_descompte)) {
                    total_descompte = parseFloat(base_descompte).toFixed(2);
                  } else {
                    total_descompte = 0;
                  }
                }
                //console.log('Total descompte:', total_descompte);
                preu_total_linia = parseFloat(parseFloat(preu_total_linia) - parseFloat(total_descompte)).toFixed(2);
                descomptes.push([...Object.values(descompte), total_descompte]);
              }
            }
            if (Array.isArray(linia_obj.impostos)) {
              for (const impost of linia_obj.impostos) {
                //console.log('Impost:', impost);
                var total_impost = 0;
                var percentatge = parseFloat(impost['Tipus impositiu']);
                var base_imposable = parseFloat(impost['Base imposable']);
                if (!isNaN(percentatge)) {
                  if (!isNaN(base_imposable)) {
                    total_impost = parseFloat((base_imposable) * (parseFloat(percentatge) / 100)).toFixed(2);
                  } else {
                    total_impost = 0;
                  }
                } else {
                  if (!isNaN(base_imposable)) {
                    total_impost = parseFloat(base_imposable).toFixed(2);
                  } else {
                    total_impost = 0;
                  }
                }
                //console.log('Total impost:', total_impost);
                preu_total_linia = parseFloat(parseFloat(preu_total_linia) + parseFloat(total_impost)).toFixed(2);
                impostos.push([...Object.values(impost), total_impost]);
              }
            }
            total_linia_factura.push([preu_total_linia]);
            dades_linia_factura.push(linia_vals);
            if (Array.isArray(linia_obj.opcionals) && linia_obj.opcionals.length > 0) {
              dades_opcionals_linia_factura.push(Object.values(linia_obj.opcionals[0]));
            } else {
              dades_opcionals_linia_factura.push([]);
            }
            dades_impostos.push(impostos);
            dades_descomptes.push(descomptes);
          }
          if (mitja_afegit) {
            dades_circumstancia = dades_circumstancia.filter(arr =>
              !(Array.isArray(arr) && arr.length > 0 && arr[0] === 'Mitjà de transport')
            );
          }
          //console.log('Dades serie:', dades_serie);
          //obtener idice de dades_factura donde el valor es Número
          var numero_factura = "";
          var index_numero = columnes_factura.indexOf('Número');
          if (index_numero !== -1) {
            numero_factura = dades_serie['Codi'] + "-" + dades_serie['Prefix'] + dades_factura[index_numero] + dades_serie['Sufix'];
            dades_factura[index_numero] = numero_factura;
          }
          var index_data = columnes_factura.indexOf('Data');
          if (index_data !== -1 && dades_factura[index_data]) {
            const date = new Date(dades_factura[index_data]);
            const formattedDate = date.toLocaleDateString('ca-ES');
            dades_factura[index_data] = formattedDate;
          }
          var index_data_linia = columnes_linia_factura.indexOf('Data operació');
          if (index_data_linia !== -1) {
            for (let i = 0; i < dades_linia_factura.length && dades_linia_factura[i][index_data_linia]; i++) {
              const date = new Date(dades_linia_factura[i][index_data_linia]);
              const formattedDate = date.toLocaleDateString('ca-ES');
              dades_linia_factura[i][index_data_linia] = formattedDate;
            }
          }
          var index_quantitat_linia = columnes_linia_factura.indexOf('Quantitat');
          if (index_quantitat_linia !== -1) {
            for (let i = 0; i < dades_linia_factura.length; i++) {
              let valor = dades_linia_factura[i][index_quantitat_linia];
              if (valor) {
                dades_linia_factura[i][index_quantitat_linia] = parseFloat(valor).toString();
              }
            }
          }
          var index_data_pagaments = columnes_pagaments.indexOf('Data');
          if (index_data_pagaments !== -1) {
            for (let i = 0; i < dades_pagaments.length && dades_pagaments[i][index_data_pagaments]; i++) {
              const date = new Date(dades_pagaments[i][index_data_pagaments]);
              const formattedDate = date.toLocaleDateString('ca-ES');
              dades_pagaments[i][index_data_pagaments] = formattedDate;
            }
          }
          var index_data_pagament = columnes_pagament_factura.indexOf('Data termini');
          if (index_data_pagament !== -1 && dades_pagament_factura[index_data_pagament]) {
            const date = new Date(dades_pagament_factura[index_data_pagament]);
            const formattedDate = date.toLocaleDateString('ca-ES');
            dades_pagament_factura[index_data_pagament] = formattedDate;
          }
          console.log('Dades per a la plantilla:',
            "placeholders_personals:", placeholders_personals, `\n`,
            "valors_personals:", dades_personals, `\n`,
            "placeholders_opcionals_personals:", placeholders_opcionals_personals, `\n`,
            "valors_opcionals_personals:", dades_opcionals_personals, `\n`,
            "placeholders_clients:", placeholders_clients, `\n`,
            "valors_clients:", dades_clients, `\n`,
            "placeholders_opcionals_clients:", placeholders_opcionals_clients, `\n`,
            "valors_opcionals_clients:", dades_opcionals_clients, `\n`,
            "placeholders_factura:", placeholders_factura, `\n`,
            "valors_factura:", dades_factura, `\n`,
            "placeholders_opcionals_factura:", placeholders_opcionals_factura, `\n`,
            "valors_opcionals_factura:", dades_opcionals_factura, `\n`,
            "placeholders_linia_factura:", placeholders_lina_factura, `\n`,
            "valors_linia_factura:", dades_linia_factura, `\n`,
            "placeholders_opcionals_linia_factura:", placeholders_opcionals_linia_factura, `\n`,
            "valors_opcionals_linia_factura:", dades_opcionals_linia_factura, `\n`,
            "placeholders_subtotal_linia_factura:", placeholders_subtotal_linia_factura, `\n`,
            "valors_subtotal_linia_factura:", subtotal_linia_factura, `\n`,
            "placeholders_total_linia_factura:", placeholders_total_linia_factura, `\n`,
            "valors_total_linia_factura:", total_linia_factura, `\n`,
            "placeholders_producte:", placeholders_producte, `\n`,
            "valors_producte:", dades_producte, `\n`,
            "placeholders_opcionals_producte:", placeholders_opcionals_producte, `\n`,
            "valors_opcionals_producte:", dades_opcionals_producte, `\n`,
            "placeholders_descomptes:", placeholders_descomptes, `\n`,
            "valors_descomptes:", dades_descomptes, `\n`,
            "placeholders_impostos:", placeholders_impostos, `\n`,
            "valors_impostos:", dades_impostos, `\n`,
            "user_path:", `/srv/facturacio/data/${userSchema}`, `\n`,
            "numero_factura:", numero_factura, `\n`,
            "placeholders_circumstancies", placeholders_circumstancies, `\n`,
            "dades_circumstancia", dades_circumstancia, `\n`,
            "placeholders_pagaments", placeholders_pagaments, `\n`,
            "dades_pagaments", dades_pagaments, `\n`,
            "placeholders_pagament_factura", placeholders_pagament_factura, `\n`,
            "dades_pagament_factura", dades_pagament_factura, `\n`,
            "placeholders_pagament", placeholders_pagament, `\n`,
            "dades_pagament", dades_pagament, `\n`
          );
        } catch (error) {
          winston.error('Error en obtenir les dades en /factura_pdf:', error);
          return res.status(500).json({ missatge: 'Error en el servidor' });
        }
        const allData = {
          placeholders_personals: placeholders_personals,
          valors_personals: dades_personals,
          placeholders_opcionals_personals: placeholders_opcionals_personals,
          valors_opcionals_personals: dades_opcionals_personals,
          placeholders_clients: placeholders_clients,
          valors_clients: dades_clients,
          placeholders_opcionals_clients: placeholders_opcionals_clients,
          valors_opcionals_clients: dades_opcionals_clients,
          placeholders_factura: placeholders_factura,
          valors_factura: dades_factura,
          placeholders_opcionals_factura: placeholders_opcionals_factura,
          valors_opcionals_factura: dades_opcionals_factura,
          placeholders_linia_factura: placeholders_lina_factura,
          valors_linia_factura: dades_linia_factura,
          placeholders_opcionals_linia_factura: placeholders_opcionals_linia_factura,
          valors_opcionals_linia_factura: dades_opcionals_linia_factura,
          placeholders_subtotal_linia_factura: placeholders_subtotal_linia_factura,
          valors_subtotal_linia_factura: subtotal_linia_factura,
          placeholders_total_linia_factura: placeholders_total_linia_factura,
          valors_total_linia_factura: total_linia_factura,
          placeholders_producte: placeholders_producte,
          valors_producte: dades_producte,
          placeholders_opcionals_producte: placeholders_opcionals_producte,
          valors_opcionals_producte: dades_opcionals_producte,
          placeholders_descomptes: placeholders_descomptes,
          valors_descomptes: dades_descomptes,
          placeholders_impostos: placeholders_impostos,
          valors_impostos: dades_impostos,
          user_path: `/srv/facturacio/data/${userSchema}`,
          dest_path: `/srv/facturacio/data/${userSchema}/factures`,
          numero_factura: numero_factura,
          placeholders_circumstancies: placeholders_circumstancies,
          dades_circumstancia: dades_circumstancia,
          placeholders_pagaments: placeholders_pagaments,
          dades_pagaments: dades_pagaments,
          placeholders_pagament_factura: placeholders_pagament_factura,
          dades_pagament_factura: dades_pagament_factura,
          placeholders_pagament: placeholders_pagament,
          dades_pagament: dades_pagament,
        };
        //console.log('Dades per a la plantilla:', allData);
        const pythonProcess = spawn('python3', ['canvi.py']);
        pythonProcess.stdin.write(JSON.stringify(allData));
        pythonProcess.stdin.end();
        let output = '';
        pythonProcess.stdout.on('data', (data) => {
          output += data.toString();
        });
        pythonProcess.stderr.on('data', (data) => {
          winston.error(`Error en STDERR: ${data.toString()}`);
          throw new Error(data.toString());
        });
        pythonProcess.on('close', (code) => {
          try {
            if (code !== 0) {
              winston.error('Error en executar /factura_pdf');
              return res.status(400).json({
                error: 'Error al ejecutar el script',
              });
            }
            //Revisar si tinc odt i pdf
            const odtpath = `/srv/facturacio/data/${userSchema}/factures/${numero_factura}.odt`;
            const pdfpath = `/srv/facturacio/data/${userSchema}/factures/${numero_factura}.pdf`;
            if (fs.existsSync(odtpath) && fs.existsSync(pdfpath)) {
              console.log('Fitxers generats OK');
              res.setHeader('Content-Type', 'application/pdf'); // Ajusta el tipo MIME si es necesario
              return res.sendFile(pdfpath);
            } else { // Si no s'han generat correctament s'eliminen
              console.log('Fitxers no generats correctament:', odtpath, pdfpath);
              if (fs.existsSync(odtpath)) {
                fs.unlinkSync(odtpath);
              }
              if (fs.existsSync(pdfpath)) {
                fs.unlinkSync(pdfpath);
              }
              return res.status(500).json({ error: 'Error al generar els fitxers' });
            }
          } catch (error) {
            winston.error('Error al parsear la salida del script:', error);
            return res.status(500).json({ error: 'Error al procesar la salida del script' });
          }
        });
      } catch (error) {
        winston.error('Error al ejecutar el script:', error);
        return res.status(500).json({ error: 'Error en el servidor', details: error.message });
      }
    }
  } catch (error) {
    winston.error('Error en /factura_pdf:', error);
    return res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/mitjans_pagament', authMiddleware, async (req, res) => {
  try {
    const dades = await pool.query(`
      SELECT mitja_pagament
      FROM pagament.pagament;
    `);
    res.json({
      mitjans_pagament: dades.rows,
    });
    console.log('Dades de mitjans de pagament enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_pagament:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_pagament_totals', authMiddleware, async (req, res) => {
  try {
    const email = req.user; // Extraer el email del token
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener los nombres de las columnas
    const columnesQuery = await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = $1 AND table_name = $2;
    `, [userSchema, 'dades_pagament']);
    const columnes = columnesQuery.rows.map(row => `"${row.column_name}"`).join(', ');
    // Obtener los datos
    const dades = await pool.query(`
      SELECT ${columnes}
      FROM "${userSchema}".dades_pagament;
    `);
    res.json({
      camps: columnesQuery.rows.map(row => row.column_name),
      valors: dades.rows,
    });
    console.log('Dades de pagament enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_pagament:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.post('/afegir_dada_pagament', authMiddleware, async (req, res) => {
  console.log('POST /afegir_dada_pagament');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { cambios } = req.body;
    // Función para limpiar los valores de un objeto (eliminar espacios en blanco)
    const trimObjectValues = (obj) =>
      Object.fromEntries(
        Object.entries(obj).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value])
      );
    // Validar y limpiar datos
    if (cambios && typeof cambios === 'object' && Object.keys(cambios).length > 0) {
      cambios = trimObjectValues(cambios);
    } else {
      return res.status(500).json({ missatge: 'Datos no válidos para la inserción' });
    }
    console.log('- cambios:', cambios);
    // Crear lista de columnas y valores para dades_pagament
    const columns = Object.keys(cambios).map(col => `"${col}"`).join(', ');
    const values = Object.values(cambios);
    const placeholders = values.map((_, index) => `$${index + 1}`).join(', ');
    // Construir la cláusula WHERE para el SELECT dinámicamente
    const whereClause = Object.keys(cambios)
      .map((col, index) => `"${col}" = $${index + 1}`)
      .join(' AND ');
    const selectQuery = `SELECT id FROM "${userSchema}".dades_pagament WHERE ${whereClause}`;
    // Comprobar si ya existe un registro igual
    const existing = await pool.query(selectQuery, values);
    if (existing.rows.length > 0) {
      console.log('Ja existeix una dada de pagament amb els mateixos valors, retornant error 409');
      return res.status(409).json({ missatge: 'Ja existeix una dada de pagament amb els mateixos valors' });
    }
    // Queries de inserción
    const insertDadaPagamentQuery = `INSERT INTO "${userSchema}".dades_pagament (${columns}) VALUES (${placeholders}) RETURNING "id"`;
    // Ejecutar ambas consultas en una transacción
    await pool.query('BEGIN');
    const id_resultat = await pool.query(insertDadaPagamentQuery, values);
    const id = id_resultat.rows[0].id;
    console.log('Dada pagament insertada correctament, id:', id);
    await pool.query('COMMIT');
    res.status(200).json({
      missatge: 'Dada pagament insertada correctament',
      id: id
    });
  } catch (error) {
    await pool.query('ROLLBACK'); // Revertir cambios en caso de error
    console.error('Error en /afegir_dada_pagament:', error);
    winston.error('Error en /afegir_dada_pagament:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.delete('/eliminar_dades_pagament', authMiddleware, async (req, res) => {
  console.log('DELETE /eliminar_dades_pagament');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { idDadesPagament } = req.body;
    if (idDadesPagament && typeof idDadesPagament === 'string') {
      idDadesPagament = idDadesPagament.trim();
    }
    console.log('-idDadesPagament:', idDadesPagament);
    if (idDadesPagament && idDadesPagament !== "") {
      // Query para la eliminación
      const deleteQuery = `DELETE FROM "${userSchema}".dades_pagament WHERE "id" = $1`;
      // Ejecutar la consulta con los valores actualizados
      await pool.query(deleteQuery, [idDadesPagament]);
      res.status(200).json({ missatge: 'dades pagament eliminat correctament' });
    } else {
      res.status(500).json({ missatge: 'Datos no válidos para la eliminación' });
    }
  } catch (error) {
    winston.error('Error en /eliminar_dades_pagament:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.patch('/modificar_dades_pagament', authMiddleware, async (req, res) => {
  console.log('PATCH /modificar_dades_pagament');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    let { cambios, idDadesPagament } = req.body;
    const trimObjectValues = (obj) =>
      Object.fromEntries(
        Object.entries(obj).map(([key, value]) => [key, typeof value === 'string' ? value.trim() : value])
      );
    if (cambios && typeof cambios === 'object' && Object.keys(cambios).length > 0) {
      cambios = trimObjectValues(cambios);
    }
    if (idDadesPagament && typeof idDadesPagament === 'string') {
      idDadesPagament = idDadesPagament.trim();
    }
    console.log('-cambios:', cambios);
    console.log('-idDadesPagament:', idDadesPagament);
    if (idDadesPagament && idDadesPagament !== "") {
      const campos = Object.keys(cambios);
      const valores = Object.values(cambios);
      // Comprobar si ya existe una fila igual (excepto la que estamos actualizando)
      const whereClause = campos.map((col, i) => `"${col}" = $${i + 1}`).join(' AND ');
      const selectQuery = `SELECT id FROM "${userSchema}".dades_pagament WHERE ${whereClause} AND id <> $${campos.length + 1}`;
      const selectParams = [...valores, idDadesPagament];
      const existing = await pool.query(selectQuery, selectParams);
      if (existing.rows.length > 0) {
        console.log('Ja existeix una dada de pagament amb els mateixos valors.');
        return res.status(409).json({ missatge: 'Ja existeix una dada de pagament amb els mateixos valors' });
      }
      // Generar UPDATE dinámico
      const setClause = campos.map((col, i) => `"${col}" = $${i + 1}`).join(', ');
      const updateQuery = `
        UPDATE "${userSchema}".dades_pagament
        SET ${setClause}
        WHERE id = $${campos.length + 1}
      `;
      await pool.query(updateQuery, [...valores, idDadesPagament]);
      console.log('Dades de pagament modificades correctament');
      res.status(200).json({ missatge: 'Dades de pagament modificades correctament' });
    } else {
      console.log('Datos no válidos para la actualización');
      res.status(400).json({ missatge: 'Datos no válidos para la actualización' });
    }
  } catch (error) {
    console.log('Error en /modificar_dades_pagament:', error);
    winston.error('Error en /modificar_dades_pagament:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/circumstancies', authMiddleware, async (req, res) => {
  try {
    const dades = await pool.query(`
      SELECT descripció
      FROM circumstancies.circumstancies;
    `);
    res.json({
      circumstancies: dades.rows,
    });
    console.log('Circumstàncies enviades correctament');
  } catch (error) {
    winston.error('Error en /circumstancies:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.post('/afegir_dades_pagament_factura', authMiddleware, async (req, res) => {
  console.log('POST /afegir_dades_pagament_factura');
  try {
    const email = req.user; // Extraer el email del token
    const userSchema = encodeURIComponent(email);
    const { facturaSerie, facturaNumero, mitjaPagament, terminiPagament, circumstanciesFactura, pagamentsAnticipatsFactura, subtotal_factura, total_factura, circumstanciesEliminades, pagamentsEliminats } = req.body;
    console.log('serie:', facturaSerie, 'numero:', facturaNumero, 'mitjaPagament:', mitjaPagament, 'terminiPagament:', terminiPagament, 'circumstanciesFactura:', circumstanciesFactura, 'pagamentsAnticipatsFacturaInput:', pagamentsAnticipatsFactura, 'subtotal_factura', subtotal_factura, 'total_factura', total_factura, 'circumstanciesEliminades', circumstanciesEliminades, 'pagamentsEliminats', pagamentsEliminats);
    await pool.query('BEGIN');
    if (!facturaSerie || !facturaNumero) {
      return res.status(400).json({ missatge: 'Sèrie o número de la factura no proporcionats' });
    }
    if (subtotal_factura === null) {
      subtotal_factura = 0;
    }
    if (total_factura === null) {
      total_factura = 0;
    }
    const idDadesPagament = await pool.query(
      `SELECT id FROM "${userSchema}".dades_pagament_factura 
        WHERE "Sèrie factura" = $1 AND "Número factura" = $2`,
      [facturaSerie, facturaNumero]
    );
    if (idDadesPagament.rows.length > 0) {
      const id = idDadesPagament.rows[0].id;
      //console.log('Ja existeix una dada de pagament per a aquesta factura, actualitzant...');
      await pool.query(
        `UPDATE "${userSchema}".dades_pagament_factura
        SET "Mitjà de pagament" = $1, "Data termini" = $2, "Subtotal" = $3, "Total" = $4
        WHERE id = $5`,
        [mitjaPagament, terminiPagament, subtotal_factura, total_factura, id]
      );
    } else {
      //console.log('No existeix una dada de pagament per a aquesta factura, inserint...');
      await pool.query(
        `INSERT INTO "${userSchema}".dades_pagament_factura
        ("Sèrie factura", "Número factura", "Mitjà de pagament", "Data termini", "Subtotal", "Total")
        VALUES ($1, $2, $3, $4, $5, $6)`,
        [facturaSerie, facturaNumero, mitjaPagament, terminiPagament, subtotal_factura, total_factura]
      );
    }
    for (const idCircumstancia of circumstanciesEliminades) {
      await pool.query(
        `DELETE FROM "${userSchema}".circumstancies_factures
        WHERE id = $1`,
        [idCircumstancia]
      );
    }
    for (const circ of circumstanciesFactura) {
      const idCircumstancia = circ[0];
      const descripcioCircumstancia = circ[1];
      if (descripcioCircumstancia) {
        if (idCircumstancia) { //Es un update
          await pool.query(
            `UPDATE "${userSchema}".circumstancies_factures
          SET "Descripció" = $1
          WHERE id = $2`,
            [descripcioCircumstancia, idCircumstancia]
          );
        } else { //Es un insert
          await pool.query(
            `INSERT INTO "${userSchema}".circumstancies_factures
          ("Sèrie factura", "Número factura", "Descripció")
          VALUES ($1, $2, $3)`,
            [facturaSerie, facturaNumero, descripcioCircumstancia]
          );
        }
      }
    }
    for (const idpagament of pagamentsEliminats) {
      await pool.query(
        `DELETE FROM "${userSchema}".pagaments_anticipats
        WHERE id = $1`,
        [idpagament]
      );
    }
    for (const pag of pagamentsAnticipatsFactura) {
      const idpag = pag[0];
      const importPag = pag[1];
      const dataPag = pag[2];
      if (dataPag && importPag) {
        if (idpag) { //Es un update
          await pool.query(
            `UPDATE "${userSchema}".pagaments_anticipats
            SET "Data" = $1, "Import" = $2
            WHERE id = $3`,
            [dataPag, importPag, idpag]
          );
        } else { //Es un insert
          await pool.query(
            `INSERT INTO "${userSchema}".pagaments_anticipats
            ("Sèrie factura", "Número factura", "Data", "Import")
            VALUES ($1, $2, $3, $4)`,
            [facturaSerie, facturaNumero, dataPag, importPag]
          );
        }
      }
    }
    await pool.query('COMMIT');
    await updateEstatFactura(facturaSerie, facturaNumero, userSchema);
    res.status(200).json({ missatge: 'Dades de pagament insertades correctament' });
  } catch (error) {
    await pool.query('ROLLBACK'); // Revertir cambios en caso de error
    console.error('Error en /afegir_dades_pagament_factura:', error);
    winston.error('Error en /afegir_dades_pagament_factura:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_pagament_factura', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    const userSchema = encodeURIComponent(email);
    const { serie, numero } = req.query;
    if (!serie || !numero) {
      return res.status(400).json({ missatge: 'Sèrie o número de la factura no proporcionats' });
    }
    await pool.query('BEGIN');
    // Comprovar si hi ha mitjans de transport associats
    const mitjansTransFact = await pool.query(`
      SELECT COUNT(*) AS total
      FROM "${userSchema}".mitja_transport_nou mt
      JOIN "${userSchema}".dades_linia_factura lf ON mt."linia factura" = lf.id
      WHERE lf."Sèrie factura" = $1 AND lf."Número factura" = $2`,
      [serie, numero]
    );
    const ImpostosFact = await pool.query(`
      SELECT COUNT(*) AS total
      FROM "${userSchema}".impost_linia_factura imf
      JOIN "${userSchema}".dades_linia_factura lf ON imf."linia factura" = lf.id
      WHERE lf."Sèrie factura" = $1 AND lf."Número factura" = $2`,
      [serie, numero]
    );
    const pagFact = await pool.query(`
      SELECT "Data termini", "Mitjà de pagament"
      FROM "${userSchema}".dades_pagament_factura
      WHERE "Sèrie factura" = $1 AND "Número factura" = $2`,
      [serie, numero]
    );
    const circFact = await pool.query(`
      SELECT "Descripció", "id"
      FROM "${userSchema}".circumstancies_factures
      WHERE "Sèrie factura" = $1 AND "Número factura" = $2`,
      [serie, numero]
    );
    const circumstancies = circFact.rows.map(row => ({
      id: row.id,
      Descripció: row['Descripció']
    }));
    const countMitjans = parseInt(mitjansTransFact.rows[0].total, 10);
    const countImpostos = parseInt(ImpostosFact.rows[0].total, 10);
    const jaTéMitja = circumstancies.some(c => c.Descripció === 'Mitjà de transport');
    if (countMitjans > 0 && !jaTéMitja) {
      const insercio = await pool.query(`
        INSERT INTO "${userSchema}".circumstancies_factures
        ("Sèrie factura", "Número factura", "Descripció")
        VALUES ($1, $2, 'Mitjà de transport')
        RETURNING id`,
        [serie, numero]
      );
      circumstancies.push({
        id: insercio.rows[0].id,
        Descripció: 'Mitjà de transport'
      });
    }
    const jaTéImpost = circumstancies.some(c => c.Descripció === 'Operació exempta de l’Impost sobre el Valor Afegit');
    if (countImpostos === 0 && !jaTéImpost) {
      const insercio_impost = await pool.query(`
        INSERT INTO "${userSchema}".circumstancies_factures
        ("Sèrie factura", "Número factura", "Descripció")
        VALUES ($1, $2, 'Operació exempta de l’Impost sobre el Valor Afegit')
        RETURNING id`,
        [serie, numero]
      );
      circumstancies.push({
        id: insercio_impost.rows[0].id,
        Descripció: 'Operació exempta de l’Impost sobre el Valor Afegit'
      });
    }
    const pagAntFact = await pool.query(`
      SELECT "Data", "Import", "id"
      FROM "${userSchema}".pagaments_anticipats      
      WHERE "Sèrie factura" = $1 AND "Número factura" = $2`,
      [serie, numero]
    );
    await pool.query('COMMIT');
    res.json({
      pagFactDades: pagFact.rows,
      circFactDades: circumstancies,
      pagAntFactDades: pagAntFact.rows,
    });
    console.log('Dades de pagament enviades correctament');
  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Error en /dades_pagament_factura:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/unitats', authMiddleware, async (req, res) => {
  try {
    const dades = await pool.query(`
      SELECT unitat
      FROM unitats.unitats;
    `);
    res.json({
      unitats_productes: dades.rows,
    });
    console.log('unitats enviades correctament');
  } catch (error) {
    winston.error('Error en /unitats:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_client', authMiddleware, async (req, res) => {
  try {
    const [dades_persona, dades_residencia, dades_pais] = await Promise.all([
      pool.query(`SELECT persona FROM persona.persona;`),
      pool.query(`SELECT residencia FROM residencia.residencia;`),
      pool.query(`SELECT pais FROM pais.pais ORDER BY pais;`)
    ]);
    res.json({
      residencia_client: dades_residencia.rows,
      persona_client: dades_persona.rows,
      pais_client: dades_pais.rows
    });
    console.log('dades_client enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_client:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/factura_pdf_imprimir', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    const { serie, numero } = req.query;
    if (!serie || !numero) {
      return res.status(400).json({ missatge: 'Sèrie o número de la factura no proporcionats' });
    }
    var serie_dades = await pool.query(`
        SELECT "Prefix", "Sufix"
        FROM "${userSchema}".dades_series
        WHERE "Codi" = $1;
      `, [serie]);
    if (serie_dades.rowCount === 0) {
      return res.status(404).json({ missatge: 'Sèrie no trobada' });
    }
    var prefix = serie_dades.rows[0]['Prefix'];
    if (prefix === undefined || prefix === null) {
      prefix = '';
    }
    var sufix = serie_dades.rows[0]['Sufix'];
    if (sufix === undefined || sufix === null) {
      sufix = '';
    }
    var numero_factura = serie + "-" + prefix + numero + sufix;
    console.log('BUSCAR PDF PLANTILLA: numero_factura:', numero_factura);
    const filePath = path.join('/srv/facturacio/data', userSchema, 'factures', `${numero_factura}.pdf`);
    if (fs.existsSync(filePath)) {
      res.setHeader('Content-Type', 'application/pdf'); // Ajusta el tipo MIME si es necesario
      res.sendFile(filePath);
    } else {
      res.status(410).json({ message: 'Arxiu no trobat' });
    }
  } catch (error) {
    winston.error('Error en /factura_pdf_imprimir:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/factura_facturae_imprimir', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    const { serie, numero } = req.query;
    if (!serie || !numero) {
      return res.status(400).json({ missatge: 'Sèrie o número de la factura no proporcionats' });
    }
    var serie_dades = await pool.query(`
        SELECT "Prefix", "Sufix"
        FROM "${userSchema}".dades_series
        WHERE "Codi" = $1;
      `, [serie]);
    if (serie_dades.rowCount === 0) {
      return res.status(404).json({ missatge: 'Sèrie no trobada' });
    }
    var prefix = serie_dades.rows[0]['Prefix'];
    if (prefix === undefined || prefix === null) {
      prefix = '';
    }
    var sufix = serie_dades.rows[0]['Sufix'];
    if (sufix === undefined || sufix === null) {
      sufix = '';
    }
    var numero_factura = serie + "-" + prefix + numero + sufix;
    console.log('BUSCAR xml PLANTILLA: numero_factura:', numero_factura);
    var filePath = path.join('/srv/facturacio/data', userSchema, 'factures', `${numero_factura}.xsig`);
    if (fs.existsSync(filePath)) {
      res.setHeader('Content-Type', 'application/octet-stream'); // Ajusta el tipo MIME si es necesario
      return res.sendFile(filePath);
    } else {
      filePath = path.join('/srv/facturacio/data', userSchema, 'factures', `${numero_factura}.xml`);
      if (fs.existsSync(filePath)) {
        res.setHeader('Content-Type', 'application/xml'); // Ajusta el tipo MIME si es necesario
        return res.sendFile(filePath);
      } else {
        res.status(410).json({ message: 'Arxiu no trobat' });
      }
    }
  } catch (error) {
    winston.error('Error en /factura_facturae_imprimir:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/factura_facturae', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    const { serie, numero } = req.query;
    if (!serie || !numero) {
      return res.status(400).json({ missatge: 'Sèrie o número de la factura no proporcionats' });
    }
    //Obtenir el id de la factura
    var idFactura = await pool.query(`
      SELECT "id"
      FROM "${userSchema}".dades_factures
      WHERE "Sèrie" = $1 AND "Número" = $2;
    `, [serie, numero]);
    if (idFactura.rowCount === 0) {
      return res.status(404).json({ missatge: 'Factura no trobada' });
    } else {
      idFactura = idFactura.rows[0].id;
      console.log('GENERAR PDF PLANTILLA: idFactura:', idFactura);
      var clientId = await pool.query(`
        SELECT "Client"
        FROM "${userSchema}".dades_factures
        WHERE "id" = $1;
      `, [idFactura]);
      if (clientId.rowCount === 0) {
        return res.status(404).json({ missatge: 'Client no trobat' });
      } else {
        clientId = clientId.rows[0].Client;
      }
      var serieId = await pool.query(`
        SELECT "Sèrie"
        FROM "${userSchema}".dades_factures
        WHERE "id" = $1;
      `, [idFactura]);
      if (serieId.rowCount === 0) {
        return res.status(404).json({ missatge: 'Sèrie no trobada' });
      } else {
        serieId = serieId.rows[0]['Sèrie'];
      }
      //Obtenir i consultar tots els placeholders i dades de la plantilla
      try {
        var placeholders_personals = [];
        var placeholders_clients = [];
        var placeholders_factura = [];
        var placeholders_lina_factura = [];
        var placeholders_producte = [];
        var placeholders_descomptes = [];
        var placeholders_impostos = [];
        var placeholders_pagament_factura = [];
        var placeholders_circumstancies = [];
        var placeholders_pagaments = [];
        var placeholders_pagament = [];
        try {
          // Obtener los nombres de las columnas de ambas tablas
          //const [columnes_personals, columnes_clients, columnes_factura, columnes_linia_factura, columnes_producte, columnes_impostos, columnes_descomptes] = await Promise.all([
          var [columnes_personals, columnes_clients, columnes_factura, columnes_linia_factura, columnes_producte, columnes_descomptes, columnes_impostos, columnes_pagament_factura, columnes_circumstancia, columnes_pagaments, columnes_pagament] = await Promise.all([
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_personals']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_clients']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_factures']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_linia_factura']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_productes']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'descompte_linia_factura']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'impost_linia_factura']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_pagament_factura']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'circumstancies_factures']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'pagaments_anticipats']),
            pool.query(`
              SELECT column_name
              FROM information_schema.columns
              WHERE table_schema = $1 AND table_name = $2;
            `, [userSchema, 'dades_pagament'])
          ]);
          columnes_personals = columnes_personals.rows.map(row => row.column_name); // Nombres de columnas de dades_personals
          columnes_clients = columnes_clients.rows.map(row => row.column_name); // Nombres de columnas de dades_clients
          columnes_factura = columnes_factura.rows.map(row => row.column_name).filter(col => col !== "Estat" && col !== "Client" && col !== "id" && col !== "Sèrie"); // Nombres de columnas de dades_clients
          columnes_linia_factura = columnes_linia_factura.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "Codi producte" && col !== "id")
          columnes_producte = columnes_producte.rows.map(row => row.column_name).filter(col => col === "Unitats" || col === "Descripció"); // Nombres de columnas de dades_productes
          columnes_descomptes = columnes_descomptes.rows.map(row => row.column_name).filter(col => col !== "linia factura" && col !== "id"); // Nombres de columnas de descomptes
          columnes_impostos = columnes_impostos.rows.map(row => row.column_name).filter(col => col !== "linia factura" && col !== "id"); // Nombres de columnas de impostos
          columnes_pagament_factura = columnes_pagament_factura.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id");
          columnes_circumstancia = columnes_circumstancia.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id");
          columnes_pagaments = columnes_pagaments.rows.map(row => row.column_name).filter(col => col !== "Sèrie factura" && col !== "Número factura" && col !== "id");
          columnes_pagament = columnes_pagament.rows.map(row => row.column_name).filter(col => col !== "id"); // Nombres de columnas de dades_pagament
          var [dades_personals, dades_clients, dades_factura, dades_linies_factura, dades_serie, dades_pagament_factura, dades_circumstancia, dades_pagaments] = await Promise.all([
            pool.query(`
              SELECT ${columnes_personals.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_personals;
            `),
            pool.query(`
              SELECT ${columnes_clients.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_clients
              WHERE "Número d'identificació fiscal" = $1;
              `, [clientId]),
            pool.query(`
              SELECT ${columnes_factura.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_factures
              WHERE "Sèrie" = $1 AND "Número" = $2;
            `, [serie, numero]),
            pool.query(`
              SELECT 
                ${columnes_linia_factura.map(col => `"${col}"`).join(', ')},
                COALESCE(impostos_json, '[]') AS impostos,
                COALESCE(descomptes_json, '[]') AS descomptes,
                COALESCE(mitja_transport_json, '[]') AS mitja_transport_nou,
                COALESCE(producte_json, '[]') AS producte
              FROM "${userSchema}".dades_linia_factura
              LEFT JOIN (
                SELECT 
                  "linia factura",
                  json_agg(
                    json_build_object(
                      'impost', "impost",
                      'Base imposable', "Base imposable",
                      'Tipus impositiu', "Tipus impositiu"
                    )
                  ) AS impostos_json
                FROM "${userSchema}".impost_linia_factura
                GROUP BY "linia factura"
              ) ilf ON "${userSchema}".dades_linia_factura."id" = ilf."linia factura"
              LEFT JOIN (
                SELECT 
                  "linia factura",
                  json_agg(
                    json_build_object(
                      'Descripció', "Descripció",
                      'Base descompte', "Base descompte",
                      'Percentatge', "Percentatge"
                    )
                  ) AS descomptes_json
                FROM "${userSchema}".descompte_linia_factura
                GROUP BY "linia factura"
              ) dlf ON "${userSchema}".dades_linia_factura."id" = dlf."linia factura"
              LEFT JOIN (
                SELECT 
                  "linia factura",
                  json_agg(
                    json_build_object(
                      'Data primera entrada servei', "Data primera entrada servei",
                      'Distància fins entrega', "Distància fins entrega",
                      'Hores fins entrega', "Hores fins entrega"
                    )
                  ) AS mitja_transport_json
                FROM "${userSchema}".mitja_transport_nou
                GROUP BY "linia factura"
              ) mtf ON "${userSchema}".dades_linia_factura."id" = mtf."linia factura"
              LEFT JOIN (
                SELECT 
                  dp."Codi",
                  json_agg(
                    json_build_object(
                      ${columnes_producte.map(col => `'${col}', dp."${col}"`).join(',\n        ')}
                    )
                  ) AS producte_json
                FROM "${userSchema}".dades_productes dp
                GROUP BY dp."Codi"
              ) plf ON "${userSchema}".dades_linia_factura."Codi producte" = plf."Codi"              
              WHERE "${userSchema}".dades_linia_factura."Sèrie factura" = $1
              AND "${userSchema}".dades_linia_factura."Número factura" = $2;
            `, [serie, numero]),
            pool.query(`
              SELECT "Codi", "Prefix", "Sufix"
              FROM "${userSchema}".dades_series
              WHERE "Codi" = $1;
            `, [serieId]),
            pool.query(`
              SELECT ${columnes_pagament_factura.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".dades_pagament_factura
              WHERE "Sèrie factura" = $1 AND "Número factura" = $2;
            `, [serie, numero]),
            pool.query(`
              SELECT ${columnes_circumstancia.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".circumstancies_factures
              WHERE "Sèrie factura" = $1 AND "Número factura" = $2;
            `, [serie, numero]),
            pool.query(`
              SELECT ${columnes_pagaments.map(col => `"${col}"`).join(', ')}
              FROM "${userSchema}".pagaments_anticipats
              WHERE "Sèrie factura" = $1 AND "Número factura" = $2;
            `, [serie, numero])
          ]);
          var dades_pagament = await pool.query(`
            SELECT ${columnes_pagament.map(col => `"${col}"`).join(', ')}
            FROM "${userSchema}".dades_pagament
            WHERE "id" = $1 ;
          `, [dades_pagament_factura.rows[0]["Mitjà de pagament"]]);
          if (dades_personals?.rows?.length > 0) {
            dades_personals = Object.values(dades_personals.rows[0]);
          } else {
            dades_personals = [];
          }
          if (dades_clients?.rows?.length > 0) {
            dades_clients = Object.values(dades_clients.rows[0]);
          } else {
            dades_clients = [];
          }
          if (dades_factura?.rows?.length > 0) {
            dades_factura = Object.values(dades_factura.rows[0]);
          } else {
            dades_factura = [];
          }
          if (dades_pagament_factura?.rows?.length > 0) {
            dades_pagament_factura = Object.values(dades_pagament_factura.rows[0]);
          } else {
            dades_pagament_factura = [];
          }
          dades_circumstancia = dades_circumstancia?.rows?.length > 0
            ? dades_circumstancia.rows.map(row => Object.values(row))
            : [];
          dades_pagaments = dades_pagaments?.rows?.length > 0
            ? dades_pagaments.rows.map(row => Object.values(row))
            : [];
          if (dades_pagament?.rows?.length > 0) {
            dades_pagament = Object.values(dades_pagament.rows[0]);
          } else {
            dades_pagament = [];
          }
          dades_serie = dades_serie.rows[0]
          placeholders_personals = generarPlaceholders(columnes_personals, 'Personal');
          placeholders_clients = generarPlaceholders(columnes_clients, 'Client');
          placeholders_factura = generarPlaceholders(columnes_factura, 'Factura');
          placeholders_lina_factura = generarPlaceholders(columnes_linia_factura, 'Linia');
          placeholders_producte = generarPlaceholders(columnes_producte, 'Producte');
          placeholders_descomptes = generarPlaceholders(columnes_descomptes, 'Descompte_Linia');
          placeholders_descomptes.push('#Total_Descompte_Linia');
          placeholders_impostos = generarPlaceholders(columnes_impostos, 'Impost_Linia');
          placeholders_impostos.push('#Total_Impost_Linia');
          placeholders_pagament_factura = generarPlaceholders(columnes_pagament_factura, 'Pagament');
          placeholders_circumstancies = generarPlaceholders(columnes_circumstancia, 'Condició');
          placeholders_pagaments = generarPlaceholders(columnes_pagaments, 'Pagament_Anticipat');
          placeholders_pagament = generarPlaceholders(columnes_pagament, 'Pagament');
          var placeholders_subtotal_linia_factura = ['#Subtotal_Linia']
          var placeholders_total_linia_factura = ['#Total_Linia']
          var dades_linia_factura = [];
          var dades_impostos = [];
          var dades_descomptes = [];
          //var mitja_transport_nou = [];
          var subtotal_linia_factura = [];
          var total_linia_factura = [];
          var dades_producte = [];
          var mitja_afegit = false;
          // Buscar si alguna circumstància conté "Mitjà de transport"
          const hiHaMitja = dades_circumstancia.some(arr =>
            typeof arr[0] === 'string' && arr[0].includes('Mitjà de transport')
          );
          for (var i = 0; i < dades_linies_factura.rows.length; i++) {
            const linia_obj = dades_linies_factura.rows[i];
            // Filtrar solo les claus que no siguin impostos, descomptes ni mitja_transport_nou
            const linia_filtrada = Object.fromEntries(
              Object.entries(linia_obj).filter(([key]) =>
                !['impostos', 'descomptes', 'mitja_transport_nou', 'producte'].includes(key)
              )
            );
            //Si hi ha mitja de trensport
            if (hiHaMitja && Array.isArray(linia_obj.mitja_transport_nou) && linia_obj.mitja_transport_nou.length > 0) {
              var data_mitja = null;
              var hores_mitja = null;
              var distancies_mitja = null;
              var nom_mitja = null;
              const mitja_transport = linia_obj.mitja_transport_nou[0];
              console.log('Mitjà de transport:', mitja_transport);
              data_mitja = mitja_transport['Data primera entrada servei'];
              hores_mitja = mitja_transport['Hores fins entrega'];
              distancies_mitja = mitja_transport['Distància fins entrega'];
              // Si també hi ha producte
              if (Array.isArray(linia_obj.producte) && linia_obj.producte.length > 0) {
                const producte = linia_obj.producte[0];
                console.log('Producte:', producte);
                nom_mitja = producte['Descripció'];
              }
              var text_mitja_circumstancia = `Mitjà de transport ${nom_mitja ?? "-"}, amb data de la primera entrada en servei el ${data_mitja ?? "-"}, ${hores_mitja ?? "-"} hores d'ús i ${distancies_mitja ?? "-"} quilòmetres fins a l'entrega`;
              dades_circumstancia.push([text_mitja_circumstancia]);
              mitja_afegit = true;
            }
            //console.log('Linia filtrada:', linia_filtrada);
            //console.log('Producte:', linia_obj.producte);
            if (Array.isArray(linia_obj.producte) && linia_obj.producte.length > 0) {
              const producte = linia_obj.producte[0];
              // Separamos los campos
              const { opcions, ...obligatoris } = producte;
              // Añadimos solo los valores obligatorios
              dades_producte.push(Object.values(obligatoris));
            } else {
              dades_producte.push([]);
            }
            var preu_total_linia = parseFloat(parseFloat(linia_obj['Quantitat']) * parseFloat(linia_obj['Preu unitari'])).toFixed(2);
            if (isNaN(preu_total_linia)) {
              preu_total_linia = 0;
            }
            subtotal_linia_factura.push([preu_total_linia]);
            const linia_vals = Object.values(linia_filtrada);
            const impostos = [];
            const descomptes = [];
            if (Array.isArray(linia_obj.descomptes)) {
              for (const descompte of linia_obj.descomptes) {
                //console.log('Descompte:', descompte);
                var total_descompte = 0;
                var percentatge = parseFloat(descompte['Percentatge']);
                var base_descompte = parseFloat(descompte['Base descompte']);
                if (!isNaN(percentatge)) {
                  if (!isNaN(base_descompte)) {
                    total_descompte = parseFloat((base_descompte) * (parseFloat(percentatge) / 100)).toFixed(2);
                  } else {
                    total_descompte = 0;
                  }
                } else {
                  if (!isNaN(base_descompte)) {
                    total_descompte = parseFloat(base_descompte).toFixed(2);
                  } else {
                    total_descompte = 0;
                  }
                }
                //console.log('Total descompte:', total_descompte);
                preu_total_linia = parseFloat(parseFloat(preu_total_linia) - parseFloat(total_descompte)).toFixed(2);
                descomptes.push([...Object.values(descompte), total_descompte]);
              }
            }
            if (Array.isArray(linia_obj.impostos)) {
              for (const impost of linia_obj.impostos) {
                //console.log('Impost:', impost);
                var total_impost = 0;
                var percentatge = parseFloat(impost['Tipus impositiu']);
                var base_imposable = parseFloat(impost['Base imposable']);
                if (!isNaN(percentatge)) {
                  if (!isNaN(base_imposable)) {
                    total_impost = parseFloat((base_imposable) * (parseFloat(percentatge) / 100)).toFixed(2);
                  } else {
                    total_impost = 0;
                  }
                } else {
                  if (!isNaN(base_imposable)) {
                    total_impost = parseFloat(base_imposable).toFixed(2);
                  } else {
                    total_impost = 0;
                  }
                }
                //console.log('Total impost:', total_impost);
                preu_total_linia = parseFloat(parseFloat(preu_total_linia) + parseFloat(total_impost)).toFixed(2);
                impostos.push([...Object.values(impost), total_impost]);
              }
            }
            total_linia_factura.push([preu_total_linia]);
            dades_linia_factura.push(linia_vals);
            dades_impostos.push(impostos);
            dades_descomptes.push(descomptes);
          }
          if (mitja_afegit) {
            dades_circumstancia = dades_circumstancia.filter(arr =>
              !(Array.isArray(arr) && arr.length > 0 && arr[0] === 'Mitjà de transport')
            );
          }
          //console.log('Dades serie:', dades_serie);
          //obtener idice de dades_factura donde el valor es Número
          var numero_factura = "";
          var index_numero = columnes_factura.indexOf('Número');
          if (index_numero !== -1) {
            numero_factura = dades_serie['Prefix'] + dades_factura[index_numero] + dades_serie['Sufix'];
            dades_factura[index_numero] = numero_factura;
          }
          var index_data = columnes_factura.indexOf('Data');
          if (index_data !== -1 && dades_factura[index_data]) {
            const date = new Date(dades_factura[index_data]);
            const formattedDate = date.toLocaleDateString('ca-ES');
            dades_factura[index_data] = formattedDate;
          }
          var index_data_linia = columnes_linia_factura.indexOf('Data operació');
          if (index_data_linia !== -1) {
            for (let i = 0; i < dades_linia_factura.length && dades_linia_factura[i][index_data_linia]; i++) {
              const date = new Date(dades_linia_factura[i][index_data_linia]);
              const formattedDate = date.toLocaleDateString('ca-ES');
              dades_linia_factura[i][index_data_linia] = formattedDate;
            }
          }
          var index_quantitat_linia = columnes_linia_factura.indexOf('Quantitat');
          if (index_quantitat_linia !== -1) {
            for (let i = 0; i < dades_linia_factura.length; i++) {
              let valor = dades_linia_factura[i][index_quantitat_linia];
              if (valor) {
                dades_linia_factura[i][index_quantitat_linia] = parseFloat(valor).toString();
              }
            }
          }
          var index_data_pagaments = columnes_pagaments.indexOf('Data');
          if (index_data_pagaments !== -1) {
            for (let i = 0; i < dades_pagaments.length && dades_pagaments[i][index_data_pagaments]; i++) {
              const date = new Date(dades_pagaments[i][index_data_pagaments]);
              const formattedDate = date.toLocaleDateString('ca-ES');
              dades_pagaments[i][index_data_pagaments] = formattedDate;
            }
          }
          var index_data_pagament = columnes_pagament_factura.indexOf('Data termini');
          if (index_data_pagament !== -1 && dades_pagament_factura[index_data_pagament]) {
            const date = new Date(dades_pagament_factura[index_data_pagament]);
            const formattedDate = date.toLocaleDateString('ca-ES');
            dades_pagament_factura[index_data_pagament] = formattedDate;
          }
          console.log('Dades per a la plantilla:',
            "placeholders_personals:", placeholders_personals, `\n`,
            "valors_personals:", dades_personals, `\n`,
            "placeholders_clients:", placeholders_clients, `\n`,
            "valors_clients:", dades_clients, `\n`,
            "placeholders_factura:", placeholders_factura, `\n`,
            "valors_factura:", dades_factura, `\n`,
            "placeholders_linia_factura:", placeholders_lina_factura, `\n`,
            "valors_linia_factura:", dades_linia_factura, `\n`,
            "placeholders_subtotal_linia_factura:", placeholders_subtotal_linia_factura, `\n`,
            "valors_subtotal_linia_factura:", subtotal_linia_factura, `\n`,
            "placeholders_total_linia_factura:", placeholders_total_linia_factura, `\n`,
            "valors_total_linia_factura:", total_linia_factura, `\n`,
            "placeholders_producte:", placeholders_producte, `\n`,
            "valors_producte:", dades_producte, `\n`,
            "placeholders_descomptes:", placeholders_descomptes, `\n`,
            "valors_descomptes:", dades_descomptes, `\n`,
            "placeholders_impostos:", placeholders_impostos, `\n`,
            "valors_impostos:", dades_impostos, `\n`,
            "user_path:", `/srv/facturacio/data/${userSchema}`, `\n`,
            "numero_factura:", numero_factura, `\n`,
            "placeholders_circumstancies:", placeholders_circumstancies, `\n`,
            "dades_circumstancia:", dades_circumstancia, `\n`,
            "placeholders_pagaments:", placeholders_pagaments, `\n`,
            "dades_pagaments:", dades_pagaments, `\n`,
            "placeholders_pagament_factura:", placeholders_pagament_factura, `\n`,
            "dades_pagament_factura:", dades_pagament_factura, `\n`,
            "placeholders_pagament:", placeholders_pagament, `\n`,
            "dades_pagament:", dades_pagament, `\n`,
            "Serie:", serie, `\n`,
          );
        } catch (error) {
          winston.error('Error en obtenir les dades en /factura_facturae:', error);
          return res.status(500).json({ missatge: 'Error en el servidor' });
        }
        const allData = {
          placeholders_personals: placeholders_personals,
          valors_personals: dades_personals,
          placeholders_clients: placeholders_clients,
          valors_clients: dades_clients,
          placeholders_factura: placeholders_factura,
          valors_factura: dades_factura,
          placeholders_linia_factura: placeholders_lina_factura,
          valors_linia_factura: dades_linia_factura,
          placeholders_subtotal_linia_factura: placeholders_subtotal_linia_factura,
          valors_subtotal_linia_factura: subtotal_linia_factura,
          placeholders_total_linia_factura: placeholders_total_linia_factura,
          valors_total_linia_factura: total_linia_factura,
          placeholders_producte: placeholders_producte,
          valors_producte: dades_producte,
          placeholders_descomptes: placeholders_descomptes,
          valors_descomptes: dades_descomptes,
          placeholders_impostos: placeholders_impostos,
          valors_impostos: dades_impostos,
          user_path: `/srv/facturacio/data/${userSchema}`,
          dest_path: `/srv/facturacio/data/${userSchema}/factures`,
          numero_factura: numero_factura,
          placeholders_circumstancies: placeholders_circumstancies,
          dades_circumstancia: dades_circumstancia,
          placeholders_pagaments: placeholders_pagaments,
          dades_pagaments: dades_pagaments,
          placeholders_pagament_factura: placeholders_pagament_factura,
          dades_pagament_factura: dades_pagament_factura,
          placeholders_pagament: placeholders_pagament,
          dades_pagament: dades_pagament,
          serie: serie,
        };
        //console.log('Dades per a la plantilla:', allData);
        const pythonProcess = spawn('python3', ['facturae.py']);
        pythonProcess.stdin.write(JSON.stringify(allData));
        pythonProcess.stdin.end();
        let output = '';
        pythonProcess.stdout.on('data', (data) => {
          output += data.toString();
        });
        pythonProcess.stderr.on('data', (data) => {
          winston.error(`Error en STDERR: ${data.toString()}`);
          throw new Error(data.toString());
        });
        pythonProcess.on('close', (code) => {
          try {
            if (code !== 0) {
              winston.error('Error en executar /factura_facturae');
              return res.status(400).json({
                error: 'Error al ejecutar el script',
              });
            }
            else {
              //Revisar si tinc xml
              const xmlpath = `/srv/facturacio/data/${userSchema}/factures/${serie}-${numero_factura}.xml`;
              if (fs.existsSync(xmlpath)) {
                console.log('Fitxers generats OK');
                res.setHeader('Content-Type', 'application/xml'); // Ajusta el tipo MIME si es necesario
                return res.sendFile(xmlpath);
              } else { // Si no s'han generat correctament s'eliminen
                console.log('Fitxers no generats correctament:', xmlpath);
                if (fs.existsSync(xmlpath)) {
                  fs.unlinkSync(xmlpath);
                }
                return res.status(500).json({ error: 'Error al generar els fitxers' });
              }
            }
          } catch (error) {
            winston.error('Error al parsear la salida del script:', error);
            return res.status(500).json({ error: 'Error al procesar la salida del script' });
          }
        });
      } catch (error) {
        winston.error('Error al ejecutar el script:', error);
        return res.status(500).json({ error: 'Error en el servidor', details: error.message });
      }
    }
  } catch (error) {
    winston.error('Error en /factura_facturae:', error);
    return res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.post('/afegir_facturae_firmada', authMiddleware, upload.single('file'), async (req, res) => {
  console.log('POST /afegir_facturae_firmada');
  try {
    const email = req.user; // Email del usuario autenticado
    const userSchema = encodeURIComponent(email);
    const nom_factura_no_ext = req.body.nom_factura_no_ext;
    const facturaSerie = req.body.facturaSerie;
    const facturaNumero = req.body.facturaNumero;
    if (!req.file || !nom_factura_no_ext || !facturaSerie || !facturaNumero) {
      return res.status(400).json({ error: 'Falten dades necessàries' });
    }
    // Definir paths
    const dir = `/srv/facturacio/data/${userSchema}/factures`;
    const xsigPath = path.join(dir, `${nom_factura_no_ext}.xsig`);
    const xmlPath = path.join(dir, `${nom_factura_no_ext}.xml`);
    //console.log('Ruta fitxer .xsig:', xsigPath);
    //console.log('Ruta fitxer .xml:', xmlPath);
    // Guardar archivo .xsig (decodificando base64)
    fs.renameSync(req.file.path, xsigPath); // mover archivo
    // Eliminar archivo XML si existe
    if (fs.existsSync(xmlPath)) {
      fs.unlinkSync(xmlPath);
      //console.log('Fitxer XML existent eliminat:', xmlPath);
    }
    await pool.query(`
      UPDATE "${userSchema}".dades_factures
      SET "Estat" = 'Signada - Electrònica'
      WHERE "Sèrie" = $1 AND "Número" = $2;
    `, [facturaSerie, facturaNumero]);
    //console.log('Fitxer .xsig desat correctament:', xsigPath);
    return res.json({ message: 'Fitxer desat correctament' });
  } catch (error) {
    winston.error('Error en /afegir_facturae_firmada:', error);
    return res.status(500).json({ error: 'Error en el servidor' });
  }
});

app.post('/afegir_pdf_firmada', authMiddleware, upload.single('file'), async (req, res) => {
  console.log('POST /afegir_pdf_firmada');
  try {
    const email = req.user;
    const userSchema = encodeURIComponent(email);
    const nom_factura_no_ext = req.body.nom_factura_no_ext;
    const facturaSerie = req.body.facturaSerie;
    const facturaNumero = req.body.facturaNumero;
    if (!req.file || !nom_factura_no_ext || !facturaSerie || !facturaNumero) {
      return res.status(400).json({ error: 'Falten dades necessàries' });
    }
    const dir = `/srv/facturacio/data/${userSchema}/factures`;
    const pdfpath = path.join(dir, `${nom_factura_no_ext}.pdf`);
    const odtPath = path.join(dir, `${nom_factura_no_ext}.odt`);
    fs.renameSync(req.file.path, pdfpath); // mover archivo
    if (fs.existsSync(odtPath)) {
      fs.unlinkSync(odtPath);
      //console.log('Fitxer ODT existent eliminat:', odtPath);
    }
    await pool.query(`
      UPDATE "${userSchema}".dades_factures
      SET "Estat" = 'Signada - PDF'
      WHERE "Sèrie" = $1 AND "Número" = $2;
    `, [facturaSerie, facturaNumero]);
    return res.json({ message: 'Fitxer desat correctament' });
  } catch (error) {
    winston.error('Error en /afegir_pdf_firmada:', error);
    return res.status(500).json({ error: 'Error en el servidor' });
  }
});

app.get('/dades_factures_globals', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    // Obtener columnas de dades_factures y dades_factures_opcionals
    const [columnes, columnesOpcionals] = await Promise.all([
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_factures']),
      pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2;
      `, [userSchema, 'dades_factures_opcionals'])
    ]);
    const campsOpcionals = columnesOpcionals.rows
      .map(row => row.column_name)
      .filter(col => col !== "Sèrie" && col !== "Número");
    // Campos adicionales a añadir al final
    const campsPagament = ['Subtotal', 'Total', 'Data termini', 'Mitjà de pagament'];
    // Columnas para el SELECT
    const columnsQuery = [
      ...columnes.rows
        .filter(row => row.column_name !== "Client")
        .map(row => `"${userSchema}".dades_factures."${row.column_name}"`),
      `"${userSchema}".dades_clients."Nom i cognoms o raó social" AS "Client"`,
      ...campsOpcionals.map(col => `"${userSchema}".dades_factures_opcionals."${col}"`),
      `"${userSchema}".dades_series."Prefix"`,
      `"${userSchema}".dades_series."Sufix"`,
      `"${userSchema}".dades_pagament_factura."Subtotal"`,
      `"${userSchema}".dades_pagament_factura."Total"`,
      `"${userSchema}".dades_pagament_factura."Data termini"`,
      `"${userSchema}".dades_pagament."Mitjà de pagament"`
    ].join(', ');
    // Consulta SQL completa
    const dades = await pool.query(`
      SELECT ${columnsQuery}
      FROM "${userSchema}".dades_factures
      LEFT JOIN "${userSchema}".dades_factures_opcionals
        ON "${userSchema}".dades_factures."Sèrie" = "${userSchema}".dades_factures_opcionals."Sèrie"
        AND "${userSchema}".dades_factures."Número" = "${userSchema}".dades_factures_opcionals."Número"
      LEFT JOIN "${userSchema}".dades_series
        ON "${userSchema}".dades_factures."Sèrie" = "${userSchema}".dades_series."Codi"
      LEFT JOIN "${userSchema}".dades_clients
        ON "${userSchema}".dades_factures."Client" = "${userSchema}".dades_clients."Número d'identificació fiscal"
      LEFT JOIN "${userSchema}".dades_pagament_factura
        ON "${userSchema}".dades_factures."Sèrie" = "${userSchema}".dades_pagament_factura."Sèrie factura"
        AND "${userSchema}".dades_factures."Número" = "${userSchema}".dades_pagament_factura."Número factura"
      LEFT JOIN "${userSchema}".dades_pagament
        ON "${userSchema}".dades_pagament_factura."Mitjà de pagament" = "${userSchema}".dades_pagament."id"
    `);
    // Enviar los campos con los nuevos campos añadidos
    res.json({
      camps: columnes.rows.map(row => row.column_name),
      camps_opcionals: [...campsOpcionals, ...campsPagament],
      valors: dades.rows,
    });
    console.log('Dades de factures enviades correctament');
  } catch (error) {
    winston.error('Error en /dades_factures_globals:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

app.get('/dades_factures_grafic', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    console.log('Email:', email);
    const userSchema = encodeURIComponent(email);
    const dades = await pool.query(`
      SELECT 
        TO_CHAR(f."Data", 'DD/MM/YYYY') AS data,
        SUM(p."Total"::numeric) AS import_total
      FROM "${userSchema}".dades_factures f
      LEFT JOIN "${userSchema}".dades_pagament_factura p
        ON f."Sèrie" = p."Sèrie factura"
        AND f."Número" = p."Número factura"
      WHERE f."Estat" IN ('Signada - PDF', 'Signada - Electrònica', 'Enviada - PDF', 'Enviada - Electrònica')
      GROUP BY f."Data"::date
      ORDER BY f."Data"::date DESC
    `);
    // Enviar los campos con los nuevos campos añadidos
    res.json({
      valors: dades.rows,
    });
  } catch (error) {
    winston.error('Error en /dades_factures_grafic:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});






app.get('/factura_enviable', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    const userSchema = encodeURIComponent(email);
    const { serie, numero } = req.query;
    if (!serie || !numero) {
      return res.status(400).json({ missatge: 'Sèrie o número de la factura no proporcionats', enviada: false });
    }
    var enviada = false;
    const estat_factura_res = await pool.query(`
      SELECT "Estat"
      FROM "${userSchema}".dades_factures
      WHERE "Sèrie" = $1 AND "Número" = $2;
    `, [serie, numero]);
    const estat = estat_factura_res.rows[0]?.['Estat'];
    if (estat && (estat === 'Enviada - PDF' || estat === 'Enviada - Electrònica')) {
      enviada = true;
    }
    // Comprovem si la columna "Correu electrònic" existeix
    const columnesOpcionals = await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = $1 AND table_name = $2;
    `, [userSchema, 'dades_clients_opcionals']);
    const campsOpcionals = columnesOpcionals.rows.map(row => row.column_name);
    if (!campsOpcionals.includes("Correu electrònic")) {
      //console.log('La columna "Correu electrònic" no existeix a dades_clients_opcionals');
      return res.status(400).json({ missatge: `Si desitja enviar les factures per correu electrònic, ha d'afegir camp opcional Correu electrònic als clients.`, enviada: enviada });
    }
    // Consultem el correu electrònic del client relacionat amb la factura
    const correu_client = await pool.query(`
      SELECT "Correu electrònic"
      FROM "${userSchema}".dades_factures df
      LEFT JOIN "${userSchema}".dades_clients dc
        ON df."Client" = dc."Número d'identificació fiscal"
      LEFT JOIN "${userSchema}".dades_clients_opcionals dco
        ON dc."Número d'identificació fiscal" = dco."Número d'identificació fiscal"
      WHERE df."Sèrie" = $1 AND df."Número" = $2
      LIMIT 1;
    `, [serie, numero]);
    if (!correu_client.rows.length || !correu_client.rows[0]['Correu electrònic']) {
      //console.log('Correu electrònic no trobat per a la factura:', serie, numero);
      return res.status(406).json({ missatge: `Aquesta factura no es pot enviar perquè el client no disposa de correu electrònic.`, enviada: enviada });
    }
    const correu = correu_client.rows[0]['Correu electrònic'];
    // Comprovació de format del correu
    const regexCorreu = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!regexCorreu.test(correu)) {
      //console.log('Correu electrònic amb format invàlid:', correu);
      return res.status(406).json({ missatge: `Aquesta factura no es pot enviar perquè el correu electrònic del client no es vàlid.`, enviada: enviada });
    }
    return res.status(200).json({ missatge: 'Correu electrònic vàlid', enviada: enviada });
  } catch (error) {
    winston.error('Error en /factura_enviable:', error);
    res.status(500).json({ missatge: 'Error en el servidor', enviada: enviada });
  }
});








app.delete('/eliminar_factura', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    const userSchema = encodeURIComponent(email);
    const { serie, numero } = req.body;
    if (!serie || !numero) {
      return res.status(400).json({ missatge: 'Sèrie o número de la factura no proporcionats' });
    }

    await pool.query('BEGIN');
    // Eliminar la factura
    await pool.query(`
      DELETE FROM "${userSchema}".dades_factures
      WHERE "Sèrie" = $1 AND "Número" = $2;
    `, [serie, numero]);
    // Reordenar les factures "Esborrany" o "Preparada" posteriors
    await pool.query(`
      UPDATE "${userSchema}".dades_factures
      SET "Número" = "Número" - 1,
          "Data" = CURRENT_DATE
      WHERE "Sèrie" = $1
        AND "Número" > $2
        AND "Estat" IN ('Esborrany', 'Preparada');
    `, [serie, numero]);
    // Actualitzar el número actual de la sèrie
    const { rows } = await pool.query(`
      SELECT MAX("Número") AS maxim
      FROM "${userSchema}".dades_factures
      WHERE "Sèrie" = $1;
    `, [serie]);
    const maxim = rows[0].maxim || 0;
    await pool.query(`
      UPDATE "${userSchema}".dades_series
      SET "Número actual" = $2
      WHERE "Codi" = $1;
    `, [serie, maxim]);
          await pool.query('COMMIT');

    res.json({ missatge: 'Factura esborrada correctament' });
  } catch (error) {
        await pool.query('ROLLBACK');

    winston.error('Error en /eliminar_factura:', error);
    res.status(500).json({ missatge: 'Error en el servidor' });
  }
});













app.get('/enviar_factura', authMiddleware, async (req, res) => {
  try {
    const email = req.user;
    const userSchema = encodeURIComponent(email);
    const { serie, numero } = req.query;

    if (!serie || !numero) {
      return res.status(400).json({ missatge: 'Sèrie o número de la factura no proporcionats' });
    }
    const columnesOpcionals = await pool.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = $1 AND table_name = $2;
    `, [userSchema, 'dades_clients_opcionals']);
    const campsOpcionals = columnesOpcionals.rows.map(row => row.column_name);
    if (!campsOpcionals.includes("Correu electrònic")) {
      return res.status(400).json({ missatge: `Si desitja enviar les factures per correu electrònic, ha d'afegir camp opcional Correu electrònic als clients.` });
    }
    const correu_client = await pool.query(`
      SELECT "Correu electrònic", "Nom i cognoms o raó social", "Tipus de persona"
      FROM "${userSchema}".dades_factures df
      LEFT JOIN "${userSchema}".dades_clients dc
        ON df."Client" = dc."Número d'identificació fiscal"
      LEFT JOIN "${userSchema}".dades_clients_opcionals dco
        ON dc."Número d'identificació fiscal" = dco."Número d'identificació fiscal"
      WHERE df."Sèrie" = $1 AND df."Número" = $2
      LIMIT 1;
    `, [serie, numero]);
    if (!correu_client.rows.length || !correu_client.rows[0]['Correu electrònic']) {
      return res.status(400).json({ missatge: `Aquesta factura no es pot enviar perquè el client no disposa de correu electrònic.` });
    }
    const correu = correu_client.rows[0]['Correu electrònic'];
    const regexCorreu = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!regexCorreu.test(correu)) {
      return res.status(400).json({ missatge: `Aquesta factura no es pot enviar perquè el correu electrònic del client no es vàlid.`, correu });
    }
    const serie_dades = await pool.query(`
      SELECT "Prefix", "Sufix"
      FROM "${userSchema}".dades_series
      WHERE "Codi" = $1;
    `, [serie]);
    if (serie_dades.rowCount === 0) {
      return res.status(404).json({ missatge: 'Sèrie no trobada' });
    }
    const prefix = serie_dades.rows[0]['Prefix'] ?? '';
    const sufix = serie_dades.rows[0]['Sufix'] ?? '';
    const numero_factura = serie + "-" + prefix + numero + sufix;
    const estat_factura_res = await pool.query(`
      SELECT "Estat", "Data"
      FROM "${userSchema}".dades_factures
      WHERE "Sèrie" = $1 AND "Número" = $2;
    `, [serie, numero]);
    const estat = estat_factura_res.rows[0]?.['Estat'];
    var data_factura = estat_factura_res.rows[0]?.['Data'];
    if (data_factura) {
      const dataObj = new Date(data_factura);
      const dia = String(dataObj.getDate()).padStart(2, '0');
      const mes = String(dataObj.getMonth() + 1).padStart(2, '0'); // Els mesos van de 0 a 11
      const any = dataObj.getFullYear();
      data_factura = `${dia}/${mes}/${any}`;
    }
    let filePath = null;
    let estat_factura = null;
    if (estat === 'Signada - PDF' || estat === 'Enviada - PDF') {
      filePath = path.join('/srv/facturacio/data', userSchema, 'factures', `${numero_factura}.pdf`);
      estat_factura = 'Enviada - PDF';
    } else if (estat === 'Signada - Electrònica' || estat === 'Enviada - Electrònica') {
      filePath = path.join('/srv/facturacio/data', userSchema, 'factures', `${numero_factura}.xsig`);
      estat_factura = 'Enviada - Electrònica';
    } else {
      return res.status(410).json({ message: 'Estat de factura indefinit' });
    }
    if (!fs.existsSync(filePath)) {
      return res.status(410).json({ message: 'Arxiu no trobat' });
    }
    const dades_personals = await pool.query(`
      SELECT "Nom i cognoms o raó social", "Tipus de persona"
      FROM "${userSchema}".dades_personals;
    `);
    const fila = dades_personals.rows[0];
    let nomPersonal = fila['Nom i cognoms o raó social'] || '';
    const tipusPersonaRemitent = fila['Tipus de persona'] || '';
    // Tractament segons tipus de persona
    if (tipusPersonaRemitent === 'Física') {
      nomPersonal = nomPersonal.replace(/,/g, '');
    } else if (nomPersonal.includes(',')) {
      nomPersonal = `"${nomPersonal}"`; // Cometes dobles si hi ha comes
    }
    const ara = new Date();
    const hores = ara.getHours();
    let salutacio = 'Bon dia';
    if (hores >= 12 && hores < 20) salutacio = 'Bona tarda';
    else if (hores >= 20 || hores < 6) salutacio = 'Bona nit';
    let nom = correu_client.rows[0]['Nom i cognoms o raó social'] ?? '';
    const tipus_persona = correu_client.rows[0]['Tipus de persona'] ?? '';
    if (tipus_persona === 'Física') nom = nom.replace(/,/g, '');
    let cosMissatge = null;
    if (tipus_persona === 'Física') {
      cosMissatge =
        `${salutacio} ${nom},\n\n` +
        `Us adjuntem la vostra factura núm. ${numero_factura}, corresponent al ${data_factura}.\n\n` +
        `Gràcies per la vostra confiança.\n\n` +
        `Cordialment,\n` +
        `${nomPersonal}, mitjançant Facturació`;
    } else {
      cosMissatge =
        `${salutacio},\n\n` +
        `Els adjuntem la factura núm. ${numero_factura}, corresponent al ${data_factura}.\n\n` +
        `Gràcies per la vostra confiança.\n\n` +
        `Cordialment,\n` +
        `${nomPersonal}, mitjançant Facturació`;
    }
    const mailOptions = {
      from: `${nomPersonal} <facturacio.ddns.net@gmail.com>`,
      to: correu,
      subject: `Factura ${numero_factura} disponible`,
      text: cosMissatge,
      attachments: [
        {
          filename: path.basename(filePath),
          path: filePath
        }
      ]
    };
    transporter.sendMail(mailOptions, async (error, info) => {
      if (error) {
        console.error(error);
        return res.status(500).json({ missatge: 'Error al enviar el correu electrònic' });
      }
      if (estat_factura) {
        await pool.query(`
          UPDATE "${userSchema}".dades_factures
          SET "Estat" = $1
          WHERE "Sèrie" = $2 AND "Número" = $3;
        `, [estat_factura, serie, numero]);
      }
      // Creem nova instància per a la còpia
      const mailOptionsCopia = {
        from: `Facturació <facturacio.ddns.net@gmail.com>`,
        to: email, // email de l'usuari remitent
        subject: `Còpia enviament factura ${numero_factura}`,
        text: `Aquest missatge és una còpia de l'enviament de la factura ${numero_factura} a ${correu}.\n\n` +
          `Missatge original:\n\n${cosMissatge}`,
        attachments: [
          {
            filename: path.basename(filePath),
            path: filePath
          }
        ]
      };
      transporter.sendMail(mailOptionsCopia, (error, info) => {
        if (error) {
          console.error('Error enviant còpia al remitent:', error);
        } else {
          console.log('Còpia enviada al remitent:', info.response);
        }
      });
      //console.log('--------Email enviat: ' + info.response);
      return res.status(200).json({ missatge: 'Correu electrònic vàlid', correu });
    });
  } catch (error) {
    winston.error('Error en /enviar_factura:', error);
    return res.status(500).json({ missatge: 'Error en el servidor' });
  }
});

//Com que es tràfic intern creat pe les urls falss de navigateto cal comprovar si l'usuari està autenticat
app.get('*', async (req, res) => {
  //Primer mirem si esta autenticat:
  console.log('Ruta teoricamente autenticada:', req.url);
  const [user, caducada] = await verifyAuth(req, res);
  if (user) {
    console.log('Servint log_in.html A REDIRIGIR SI VERIFICAT');
    const filePathLogIn = '/srv/facturacio/public/log_in.html';
    const filePathDashboard = '/srv/facturacio/private/dashboard.html';
    if (fs.existsSync(filePathLogIn) && fs.existsSync(filePathDashboard)) {
      try {
        // Leer el archivo base (log_in.html)
        let logInHTML = fs.readFileSync(filePathLogIn, 'utf-8');
        // Injectar CSS en el `<head>`
        logInHTML = logInHTML.replace('</head>', `<link rel="stylesheet" href="/private/dashboard.css"></head>`);
        // Leer el contenido del dashboard
        const dashboardHTML = fs.readFileSync(filePathDashboard, 'utf-8');
        // Reemplazar el contenido del `<body>` del archivo base con el dashboard
        logInHTML = logInHTML.replace(
          `<!-- username -->`,
          `<div id="username">${user}</div>`
        );
        logInHTML = logInHTML.replace(
          /<!-- START_CONTAINER_CONTENT -->[\s\S]*?<!-- END_CONTAINER_CONTENT -->/,
          `<!-- START_CONTAINER_CONTENT -->${dashboardHTML}<!-- END_CONTAINER_CONTENT -->`
        );
        res.send(logInHTML);
      } catch (error) {
        winston.error('Error al procesar los archivos HTML:', error);
        res.status(500).send('Error interno del servidor');
      }
    } else {
      winston.error('Error: No se encontraron los archivos HTML requeridos.');
      res.status(404).send('Fitxers no trobats');
    }
  } else {
    console.log('Servint log_in.html A REDIRIGIR NO VERIFICAT');
    const filePath = '/srv/facturacio/public/log_in.html'
    if (fs.existsSync(filePath)) { // Comprovem si el fitxer existeix abans de servir-lo
      let logInHTML = fs.readFileSync(filePath, 'utf-8');
      //res.sendFile(filePath);
      res.send(logInHTML);
    } else {
      winston.error('Error servint log_in.html, no existeix a la ruta especificada.');
      res.status(404).send('Log_in no trobat');
    }
  }
});

https.createServer(options, app).listen(port, () => { // Servidor HTTPS
  console.log(`Servidor HTTPS funcionant en el port ${port}`);
});

http.createServer((req, res) => { // Redirigim tot el tràfic HTTP cap a HTTPS
  if (req.headers['x-forwarded-proto'] !== 'https') {
    res.writeHead(301, { Location: 'https://' + req.headers.host + req.url });
  }
  res.end();
}).listen(80);