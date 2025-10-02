const express = require('express');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const admin = require('firebase-admin');  // para FCM
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Configuración de MySQL
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'tu_contraseña_mysql',
  database: 'nombre_base_de_datos'
};

// Configuración de nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'tu_email@gmail.com',
    pass: 'tu_contraseña'
  }
});

// Inicialización de Firebase Admin con credenciales
const serviceAccount = require('./firebase-service-account.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// Función para enviar push real con FCM
async function sendPush(token, title, body, data = {}) {
  const message = {
    token: token,
    notification: {
      title,
      body
    },
    data: data
  };
  try {
    const resp = await admin.messaging().send(message);
    console.log('Push enviado:', resp);
    return resp;
  } catch (err) {
    console.error('Error enviando push:', err);
    throw err;
  }
}

// Función para enviar email con nodemailer
function sendEmail(to, subject, text) {
  return transporter.sendMail({
    from: 'tu_email@gmail.com',
    to,
    subject,
    text
  });
}

// Función para enviar SMS real (ejemplo con Twilio — debes instalar y configurar)
const twilio = require('twilio')('TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN');
async function sendSMSReal(phone, message) {
  try {
    const resp = await twilio.messages.create({
      body: message,
      from: 'TU_NUMERO_TWILIO', 
      to: phone
    });
    console.log('SMS enviado:', resp.sid);
    return resp;
  } catch (err) {
    console.error('Error SMS:', err);
    throw err;
  }
}

// Registrar notificación en DB
async function registrarNotificacion(connection, id_usuario, tipo, mensaje, canal) {
  const sql = `
    INSERT INTO Notificacion (id_usuario, tipo, mensaje, canal, leida)
      VALUES (?, ?, ?, ?, FALSE)
  `;
  await connection.execute(sql, [id_usuario, tipo, mensaje, canal]);
}

// Middleware de autenticación real con JWT
async function authMiddleware(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) {
    return res.status(401).json({ error: 'No token' });
  }
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, 'TU_SECRETO_JWT');
    // payload debe contener id_usuario y rol
    req.user = {
      id_usuario: payload.id_usuario,
      rol: payload.rol
    };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// Verificar permiso según rol
function checkRolePermission(rol, permisoRequerido) {
  // Puedes tener una función que lea los permisos del rol de la DB o del JWT
  // Ejemplo muy simple:
  const permisosPorRol = {
    'Coordinador': ['marcar_asistencia', 'ver_todo', 'notificar'],
    'Docente': ['marcar_asistencia', 'ver_sus_cursos'],
    'Cocina': ['ver_asistencia'],
    'Directivo': ['ver_todo', 'alertas']
    // etc.
  };
  const perms = permisosPorRol[rol] || [];
  return perms.includes(permisoRequerido);
}

// Endpoint para marcar lista con notificaciones reales
app.post('/marcar-lista', authMiddleware, async (req, res) => {
  const { curso_id, asistencias } = req.body;
  const usuarioQueMarca = req.user.id_usuario;
  const rol = req.user.rol;

  // Verificar permiso
  if (!checkRolePermission(rol, 'marcar_asistencia')) {
    return res.status(403).json({ error: 'No tienes permiso para marcar asistencia' });
  }

  let connection;
  try {
    connection = await mysql.createConnection(dbConfig);
    await connection.beginTransaction();

    // Validación: si intentan editar fechas pasadas más de 7 días (solo coordinadores pueden más atrás)
    const limiteDiasEdicion = 7;

    for (let a of asistencias) {
      const { id_alumno, estado, justificacion, fecha } = a;
      // Si fecha no es hoy, verificar permiso y límite
      if (fecha && fecha !== new Date().toISOString().slice(0, 10)) {
        const fechaObj = new Date(fecha);
        const hoy = new Date();
        const diffMs = hoy - fechaObj;
        const diffDias = diffMs / (1000 * 60 * 60 * 24);
        if (rol !== 'Coordinador' && diffDias > limiteDiasEdicion) {
          throw new Error(`No permitido editar asistencia de hace más de ${limiteDiasEdicion} días`);
        }
      }
      // Igual que antes: insertar o actualizar
      const [rows] = await connection.execute(
        `SELECT id_asistencia FROM Asistencia WHERE id_alumno = ? AND fecha = ?`,
        [id_alumno, fecha || new Date().toISOString().slice(0,10)]
      );
      if (rows.length > 0) {
        const id_asistencia = rows[0].id_asistencia;
        const [oldRows] = await connection.execute(
          `SELECT estado FROM Asistencia WHERE id_asistencia = ?`,
          [id_asistencia]
        );
        const estadoAnterior = oldRows[0].estado;

        await connection.execute(
          `UPDATE Asistencia
           SET estado = ?, justificacion = ?
           WHERE id_asistencia = ?`,
          [estado, justificacion, id_asistencia]
        );

        await connection.execute(
          `INSERT INTO Asistencia_Log
            (id_asistencia, usuario_modificador, estado_anterior, estado_nuevo, comentario_modificacion)
           VALUES (?, ?, ?, ?, ?)`,
          [id_asistencia, usuarioQueMarca, estadoAnterior, estado, null]
        );
      } else {
        await connection.execute(
          `INSERT INTO Asistencia
            (fecha, estado, justificacion, id_alumno, marcada_por)
           VALUES (?, ?, ?, ?, ?)`,
          [fecha || new Date().toISOString().slice(0,10), estado, justificacion, id_alumno, usuarioQueMarca]
        );
      }
    }

    // Recuperar detalles para notificaciones (presentes, ausentes)
    const [presentesRows] = await connection.execute(
      `SELECT u.id_usuario, u.nombre, u.apellido, u.token_push
       FROM Asistencia a
        JOIN Alumno al ON a.id_alumno = al.id_alumno
        JOIN Usuario u ON al.id_alumno = u.id_usuario
       WHERE a.fecha = ? AND a.estado = 'Presente' AND al.id_curso = ?`,
      [new Date().toISOString().slice(0,10), curso_id]
    );
    const [ausentesRows] = await connection.execute(
      `SELECT u.id_usuario, u.nombre, u.apellido, u.token_push
       FROM Asistencia a
        JOIN Alumno al ON a.id_alumno = al.id_alumno
        JOIN Usuario u ON al.id_alumno = u.id_usuario
       WHERE a.fecha = ? AND a.estado = 'Ausente' AND al.id_curso = ?`,
      [new Date().toISOString().slice(0,10), curso_id]
    );

    // Datos del docente que marca
    const [docenteRows] = await connection.execute(
      `SELECT email, token_push FROM Usuario WHERE id_usuario = ?`,
      [usuarioQueMarca]
    );
    const docenteInfo = docenteRows[0];

    // Usuarios de cocina
    const [cocinaRows] = await connection.execute(
      `SELECT u.id_usuario, u.email, u.token_push
       FROM Usuario u
       JOIN Rol r ON u.id_rol = r.id_rol
       WHERE r.nombre = 'Cocina'`
    );

    // Envío de notificaciones
    // A cocina: presentes
    if (presentesRows.length > 0) {
      const nombres = presentesRows.map(r => r.nombre + ' ' + r.apellido).join(', ');
      const mensaje = `Alumnos presentes hoy: ${nombres}`;
      for (let c of cocinaRows) {
        if (c.token_push) {
          await sendPush(c.token_push, 'Asistencia – Presentes', mensaje);
          await registrarNotificacion(connection, c.id_usuario, 'presentes', mensaje, 'push');
        }
        if (c.email) {
          await sendEmail(c.email, 'Alumnos presentes', mensaje);
          await registrarNotificacion(connection, c.id_usuario, 'presentes', mensaje, 'email');
        }
      }
    }

    // Al docente: ausentes
    if (ausentesRows.length > 0 && docenteInfo) {
      const nombresAus = ausentesRows.map(r => r.nombre + ' ' + r.apellido).join(', ');
      const mensaje = `Alumnos ausentes hoy: ${nombresAus}`;
      if (docenteInfo.token_push) {
        await sendPush(docenteInfo.token_push, 'Asistencia – Ausentes', mensaje);
        await registrarNotificacion(connection, usuarioQueMarca, 'ausentes', mensaje, 'push');
      }
      if (docenteInfo.email) {
        await sendEmail(docenteInfo.email, 'Alumnos ausentes', mensaje);
        await registrarNotificacion(connection, usuarioQueMarca, 'ausentes', mensaje, 'email');
      }
    }

    // Ausencia masiva
    const UMBRAL = 10;
    if (ausentesRows.length > UMBRAL) {
      const mensaje = `Alerta: ausencia masiva (${ausentesRows.length}) en curso ${curso_id}`;
      const [directivos] = await connection.execute(
        `SELECT u.id_usuario, u.email, u.token_push FROM Usuario u JOIN Rol r ON u.id_rol = r.id_rol WHERE r.nombre = 'Directivo'`
      );
      for (let d of directivos) {
        if (d.token_push) {
          await sendPush(d.token_push, 'Alerta Ausencia Masiva', mensaje);
          await registrarNotificacion(connection, d.id_usuario, 'alerta_ausencia_masiva', mensaje, 'push');
        }
        if (d.email) {
          await sendEmail(d.email, 'Alerta de ausencia masiva', mensaje);
          await registrarNotificacion(connection, d.id_usuario, 'alerta_ausencia_masiva', mensaje, 'email');
        }
        // Si tienes teléfono:
        // if (d.telefono) { await sendSMSReal(d.telefono, mensaje); await registrarNotificacion(connection, d.id_usuario, 'alerta_ausencia_masiva', mensaje, 'sms'); }
      }
    }

    await connection.commit();
    await connection.end();

    return res.json({ success: true, message: 'Asistencia procesada con notificaciones reales' });
  }
  catch (err) {
    if (connection) await connection.rollback();
    console.error('Error en /marcar-lista:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Ruta de alerta de sesión sospechosa real
app.post('/alerta-sesion-sospechosa', authMiddleware, async (req, res) => {
  const { userId, location } = req.body;
  const rol = req.user.rol;
  // Podrías requerir que solo ciertos roles puedan disparar esta alerta

  try {
    const connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute(
      `SELECT email, token_push FROM Usuario WHERE id_usuario = ?`,
      [userId]
    );
    if (rows.length === 0) {
      await connection.end();
      return res.status(404).json({ error: 'Usuario no existe' });
    }
    const usr = rows[0];
    const mensaje = `Se detectó un inicio de sesión desde: ${location}`;

    if (usr.token_push) {
      await sendPush(usr.token_push, 'Alerta de seguridad', mensaje);
      await registrarNotificacion(connection, userId, 'alerta_sesion', mensaje, 'push');
    }
    if (usr.email) {
      await sendEmail(usr.email, 'Alerta de seguridad', mensaje);
      await registrarNotificacion(connection, userId, 'alerta_sesion', mensaje, 'email');
    }

    await connection.end();
    return res.json({ success: true, message: 'Alerta enviada' });
  } catch (err) {
    console.error('Error /alerta-sesion-sospechosa:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(3000, () => {
  console.log('Servidor corriendo en puerto 3000');
});
