// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

console.log("LMS server starting... 🚀");  

const app = express();
app.use(cors());
app.use(express.json());  // parse JSON body

// === CONFIG ===
const JWT_SECRET = "your_jwt_secret_here_change_it";
const VIDEO_DIR = path.join(__dirname, 'videos');  // directory where video files are saved

// create video dir if not exists
if (!fs.existsSync(VIDEO_DIR)) {
  fs.mkdirSync(VIDEO_DIR);
}

// MySQL connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'lms',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// === Middleware: auth ===
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: "Missing token" });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: "Invalid token" });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;  // user = { id, username, role }
    next();
  });
}


// === Routes ===

// --- 1. Register ---
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, role } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "username and password required" });
    }
    // optional: enforce who can register as sub_admin etc.
    const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length > 0) {
      return res.status(400).json({ message: "Username taken" });
    }
    const password_hash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
      [username, password_hash, role || 'student']
    );
    return res.json({ message: "Registered OK" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

console.log("register")

// --- 2. Login ---
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    // create token
    const token = jwt.sign({
      id: user.id,
      username: user.username,
      role: user.role
    }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
});

// --- 3. Get courses list ---
app.get('/api/courses', authenticateToken, async (req, res) => {
  try {
    const { role, id: userId } = req.user;
    let sql = 'SELECT id, title, description FROM courses';
    let params = [];
    if (role === 'sub_admin') {
      // sub_admin sees only his own
      sql += ' WHERE created_by = ?';
      params.push(userId);
    }
    // main_admin sees all, students see all visible (or you might filter further)
    const [rows] = await pool.execute(sql, params);
    return res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- 4. Create a new course (upload video) ---
app.post('/api/courses', authenticateToken, async (req, res) => {
  // For simplicity, assume body contains: title, description, video_base64 (or file path) etc.
  // In real, you'd use multipart/form-data + multer to upload video file.
  try {
    const { title, description, videoFilename } = req.body;
    if (!title || !videoFilename) {
      return res.status(400).json({ message: "title and videoFilename required" });
    }
    const { id: userId, role } = req.user;
    // Only main_admin or sub_admin can create
    if (!['main_admin', 'sub_admin'].includes(role)) {
      return res.status(403).json({ message: "Not allowed" });
    }
    // Save video file externally (you will need to implement upload and save)
    // For now we assume video is placed in videos/ folder with name videoFilename
    const srcPath = path.join('videos', videoFilename);
    const [result] = await pool.execute(
      'INSERT INTO courses (title, description, src, created_by) VALUES (?, ?, ?, ?)',
      [title, description, srcPath, userId]
    );
    return res.json({ id: result.insertId, title, description });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- 5. Update existing course ---
app.put('/api/courses/:id', authenticateToken, async (req, res) => {
  try {
    const courseId = req.params.id;
    const { title, description, videoFilename } = req.body;
    const { id: userId, role } = req.user;

    // Fetch the course first
    const [rows] = await pool.execute('SELECT * FROM courses WHERE id = ?', [courseId]);
    if (rows.length === 0) {
      return res.status(404).json({ message: "Course not found" });
    }
    const course = rows[0];
    // Authorization: if sub_admin, can only edit his own
    if (role === 'sub_admin' && course.created_by !== userId) {
      return res.status(403).json({ message: "Cannot edit another's course" });
    }

    // Build update
    const updates = [];
    const params = [];
    if (title) { updates.push('title = ?'); params.push(title); }
    if (description) { updates.push('description = ?'); params.push(description); }
    if (videoFilename) {
      const srcPath = path.join('videos', videoFilename);
      updates.push('src = ?');
      params.push(srcPath);
    }
    if (updates.length === 0) {
      return res.status(400).json({ message: "Nothing to update" });
    }
    params.push(courseId);
    const sql = 'UPDATE courses SET ' + updates.join(', ') + ' WHERE id = ?';
    await pool.execute(sql, params);
    return res.json({ message: "Updated" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// --- 6. Stream the video file ---
app.get('/api/video/:courseId', authenticateToken, async (req, res) => {
  try {
    const courseId = req.params.courseId;
    const [rows] = await pool.execute('SELECT * FROM courses WHERE id = ?', [courseId]);
    if (rows.length === 0) {
      return res.status(404).json({ message: "Course not found" });
    }
    const course = rows[0];
    const videoPath = path.join(__dirname, course.src);
    // Check if file exists
    if (!fs.existsSync(videoPath)) {
      return res.status(404).json({ message: "Video file not found" });
    }

    const stat = fs.statSync(videoPath);
    const fileSize = stat.size;
    const range = req.headers.range;
    if (range) {
      // Partial request (video streaming)
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunkSize = (end - start) + 1;
      const file = fs.createReadStream(videoPath, { start, end });
      res.writeHead(206, {
        "Content-Range": `bytes ${start}-${end}/${fileSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": chunkSize,
        "Content-Type": "video/mp4"
      });
      file.pipe(res);
    } else {
      // Full request
      res.writeHead(200, {
        "Content-Length": fileSize,
        "Content-Type": "video/mp4"
      });
      fs.createReadStream(videoPath).pipe(res);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
