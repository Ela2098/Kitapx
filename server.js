const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "degistir-beni";

const db = new Database("kitapx.db");
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS books (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  genre TEXT DEFAULT '',
  description TEXT DEFAULT '',
  chapter TEXT DEFAULT '',
  published INTEGER DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
)`);

app.use(express.json({limit:"2mb"}));
app.use(express.urlencoded({extended:true}));
app.use(session({
  secret: process.env.SESSION_SECRET || "kitapx-session-secret-degistir",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly:true, sameSite:"lax", secure: process.env.NODE_ENV === "production", maxAge: 1000*60*60*8 }
}));
app.use(express.static(path.join(__dirname,"public")));

function requireAdmin(req,res,next){
  if(!req.session.admin) return res.status(401).json({error:"Yetkisiz erişim"});
  next();
}

app.post("/api/login",(req,res)=>{
  const password = String(req.body.password || "");
  if(!bcrypt.compareSync(password, bcrypt.hashSync(ADMIN_PASSWORD, 10)))
    return res.status(401).json({error:"Şifre yanlış"});
  req.session.admin = true;
  res.json({ok:true});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({admin:!!req.session.admin}));

app.get("/api/books",(req,res)=>{
  const books=db.prepare("SELECT id,title,genre,description,chapter,created_at FROM books WHERE published=1 ORDER BY id DESC").all();
  res.json(books);
});
app.get("/api/admin/books",requireAdmin,(req,res)=>{
  res.json(db.prepare("SELECT * FROM books ORDER BY id DESC").all());
});
app.post("/api/admin/books",requireAdmin,(req,res)=>{
  const {title,genre,description,chapter}=req.body;
  if(!title || !description || !chapter) return res.status(400).json({error:"Kitap adı, açıklama ve bölüm zorunlu."});
  const info=db.prepare("INSERT INTO books(title,genre,description,chapter,published) VALUES(?,?,?,?,1)")
    .run(String(title),String(genre||""),String(description),String(chapter));
  res.json({ok:true,id:info.lastInsertRowid});
});
app.put("/api/admin/books/:id",requireAdmin,(req,res)=>{
  const {title,genre,description,chapter,published}=req.body;
  db.prepare("UPDATE books SET title=?,genre=?,description=?,chapter=?,published=? WHERE id=?")
    .run(String(title),String(genre||""),String(description||""),String(chapter||""),published?1:0,Number(req.params.id));
  res.json({ok:true});
});
app.delete("/api/admin/books/:id",requireAdmin,(req,res)=>{
  db.prepare("DELETE FROM books WHERE id=?").run(Number(req.params.id));
  res.json({ok:true});
});

app.listen(PORT,()=>console.log(`Kitapx çalışıyor: http://localhost:${PORT}`));