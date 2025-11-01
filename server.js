const express = require('express');
const { createClient } = require('@libsql/client');
const session = require('express-session');
const { createServer } = require('http');
const { Server } = require('socket.io');
require('dotenv').config();

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer);
const port = 3000;

// Configuración de la base de datos Turso
const client = createClient({
    url: process.env.TURSO_URL,
    authToken: process.env.TURSO_AUTH_TOKEN,
});

// Middleware para procesar JSON (debe ir antes de las rutas)
app.use(express.json());

// Configuración de la sesión
const sessionMiddleware = session({
    secret: 'tu_secreto_aqui', // CAMBIAR en producción por una clave segura
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Cambia a true si usas HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 horas
    }
});

app.use(sessionMiddleware);

// Compartir sesión con Socket.IO
io.use((socket, next) => {
    sessionMiddleware(socket.request, {}, next);
});

// Middleware de autenticación
const requireAuth = (req, res, next) => {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.status(401).json({ authenticated: false });
    }
};

// Inicializar la base de datos
async function initDatabase() {
    try {
        await client.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                telefono TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        await client.execute(`
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        `);
        
        console.log('Base de datos inicializada correctamente');
    } catch (error) {
        console.error('Error al inicializar la base de datos:', error);
    }
}

// ============ RUTAS DE API ============

// Verificar autenticación
app.get('/api/check-auth', async (req, res) => {
    if (req.session && req.session.userId) {
        try {
            const result = await client.execute({
                sql: 'SELECT id, username FROM users WHERE id = ?',
                args: [req.session.userId]
            });
            
            if (result.rows.length > 0) {
                res.json({
                    authenticated: true,
                    userId: result.rows[0].id,
                    username: result.rows[0].username
                });
                return;
            }
        } catch (error) {
            console.error('Error al verificar usuario:', error);
        }
    }
    res.json({ authenticated: false });
});

// Login de usuarios
app.post('/api/login', async (req, res) => {
    const { username, telefono } = req.body;
    
    try {
        const result = await client.execute({
            sql: 'SELECT id FROM users WHERE username = ? AND telefono = ?',
            args: [username, telefono]
        });
        
        if (result.rows.length > 0) {
            // Establecer la sesión del usuario
            req.session.userId = result.rows[0].id;
            
            res.json({ 
                success: true, 
                message: 'Login exitoso',
                redirect: '/chat'
            });
        } else {
            res.status(401).json({ 
                success: false, 
                message: 'Usuario o teléfono incorrectos' 
            });
        }
    } catch (error) {
        console.error('Error al hacer login:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al intentar hacer login' 
        });
    }
});

// Registrar usuarios
app.post('/api/registro', async (req, res) => {
    const { username, telefono } = req.body;
    
    // Validación de datos
    if (!username || !telefono) {
        return res.status(400).json({ 
            success: false, 
            message: 'Username y teléfono son requeridos' 
        });
    }

    if (username.length < 3) {
        return res.status(400).json({ 
            success: false, 
            message: 'El username debe tener al menos 3 caracteres' 
        });
    }
    
    try {
        const result = await client.execute({
            sql: 'INSERT INTO users (username, telefono) VALUES (?, ?) RETURNING id',
            args: [username, telefono]
        });
        
        // Establecer la sesión del usuario
        req.session.userId = result.rows[0].id;
        
        res.json({ 
            success: true, 
            message: 'Usuario registrado correctamente',
            redirect: '/chat'
        });
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        
        // Verificar si es un error de username duplicado
        if (error.message && error.message.includes('UNIQUE')) {
            return res.status(409).json({ 
                success: false, 
                message: 'El username ya está en uso' 
            });
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Error al registrar usuario' 
        });
    }
});

// Buscar usuarios
app.get('/api/search-users', requireAuth, async (req, res) => {
    const searchTerm = req.query.search || '';
    
    try {
        const result = await client.execute({
            sql: `SELECT id, username FROM users 
                  WHERE username LIKE ? 
                  AND id != ? 
                  ORDER BY username 
                  LIMIT 10`,
            args: [`%${searchTerm}%`, req.session.userId]
        });
        
        res.json({ 
            success: true, 
            users: result.rows 
        });
    } catch (error) {
        console.error('Error al buscar usuarios:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al buscar usuarios' 
        });
    }
});

// Obtener historial de mensajes
app.get('/api/messages/:userId', requireAuth, async (req, res) => {
    const otherUserId = req.params.userId;
    const currentUserId = req.session.userId;
    
    try {
        const result = await client.execute({
            sql: `SELECT m.*, u.username as sender_username 
                  FROM messages m
                  JOIN users u ON m.sender_id = u.id
                  WHERE (m.sender_id = ? AND m.receiver_id = ?)
                     OR (m.sender_id = ? AND m.receiver_id = ?)
                  ORDER BY m.created_at ASC
                  LIMIT 100`,
            args: [currentUserId, otherUserId, otherUserId, currentUserId]
        });
        
        res.json({ 
            success: true, 
            messages: result.rows 
        });
    } catch (error) {
        console.error('Error al obtener mensajes:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al obtener mensajes' 
        });
    }
});

// Cerrar sesión
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error al cerrar sesión:', err);
            return res.status(500).json({ 
                success: false, 
                message: 'Error al cerrar sesión' 
            });
        }
        res.json({ success: true });
    });
});

// ============ SOCKET.IO ============

// Almacenar usuarios conectados: userId -> socketId
const connectedUsers = new Map();

io.on('connection', (socket) => {
    const session = socket.request.session;
    
    if (!session || !session.userId) {
        socket.disconnect();
        return;
    }
    
    const userId = session.userId;
    connectedUsers.set(userId, socket.id);
    
    console.log(`Usuario ${userId} conectado con socket ${socket.id}`);
    
    // Manejar envío de mensajes
    socket.on('send_message', async (data) => {
        const { receiverId, message } = data;
        
        try {
            // Guardar mensaje en la base de datos
            const result = await client.execute({
                sql: 'INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?) RETURNING id, created_at',
                args: [userId, receiverId, message]
            });
            
            // Obtener el username del sender
            const userResult = await client.execute({
                sql: 'SELECT username FROM users WHERE id = ?',
                args: [userId]
            });
            
            const messageData = {
                id: result.rows[0].id,
                sender_id: userId,
                receiver_id: receiverId,
                message: message,
                created_at: result.rows[0].created_at,
                sender_username: userResult.rows[0].username
            };
            
            // Enviar mensaje al remitente (confirmación)
            socket.emit('receive_message', messageData);
            
            // Enviar mensaje al receptor si está conectado
            const receiverSocketId = connectedUsers.get(receiverId);
            if (receiverSocketId) {
                io.to(receiverSocketId).emit('receive_message', messageData);
            }
            
        } catch (error) {
            console.error('Error al enviar mensaje:', error);
            socket.emit('message_error', { error: 'Error al enviar mensaje' });
        }
    });
    
    // Manejar desconexión
    socket.on('disconnect', () => {
        connectedUsers.delete(userId);
        console.log(`Usuario ${userId} desconectado`);
    });
});

// ============ RUTAS DE PÁGINAS ============

// pagina principal
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// Ruta para la página de login
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/public/registro/login.html');
});

// Ruta para la página de registro
app.get('/registro', (req, res) => {
    res.sendFile(__dirname + '/public/registro/registro.html');
});

// Ruta para la página de chat (protegida)
app.get('/chat', requireAuth, (req, res) => {
    res.sendFile(__dirname + '/public/chat/index.html');
});

// Servir archivos estáticos (debe ir al final de las rutas específicas)
app.use(express.static('public'));

// Ruta raíz
app.get('/', (req, res) => {
    res.redirect('/registro');
});

// Manejo de errores 404
app.use((req, res) => {
    res.status(404).json({ 
        success: false, 
        message: 'Ruta no encontrada' 
    });
});

// ============ INICIAR SERVIDOR ============

initDatabase().then(() => {
    httpServer.listen(port, () => {
        console.log(`Servidor corriendo en http://localhost:${port}`);
    });
}).catch(err => {
    console.error('Error al iniciar el servidor:', err);
    process.exit(1);
});