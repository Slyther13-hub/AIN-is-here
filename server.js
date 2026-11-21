const express = require('express');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json({ limit: '2mb' }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024 } });

const required = ['B2_KEY_ID','B2_APPLICATION_KEY','B2_BUCKET','B2_ENDPOINT','B2_PUBLIC_BASE_URL'];
for (const key of required) if (!process.env[key]) console.warn(`Missing environment variable: ${key}`);

const s3 = new S3Client({
  region: process.env.B2_REGION || 'us-east-005',
  endpoint: process.env.B2_ENDPOINT,
  credentials: { accessKeyId: process.env.B2_KEY_ID || '', secretAccessKey: process.env.B2_APPLICATION_KEY || '' },
  forcePathStyle: true
});
const bucket = process.env.B2_BUCKET;
const emailKey = email => crypto.createHash('sha256').update(String(email).trim().toLowerCase()).digest('hex');
const userKey = (role,email) => `users/${role}/${emailKey(email)}.json`;
async function readObject(key) {
  const out = await s3.send(new GetObjectCommand({Bucket:bucket,Key:key}));
  return JSON.parse(await out.Body.transformToString());
}
async function writeObject(key,data) {
  await s3.send(new PutObjectCommand({Bucket:bucket,Key:key,Body:JSON.stringify(data),ContentType:'application/json',CacheControl:'no-store'}));
}
function publicUser(u) {
  const { passwordHash, ...safe } = u;
  return safe;
}
app.get('/api/health', (_req,res) => res.json({ok:true,service:'AIN Backblaze API',testMode:process.env.AIN_TEST_MODE==='true'}));

app.post('/api/auth/signup', async (req,res) => {
  try {
    const {role,name,email,password,field,phone,experience,description,photo} = req.body || {};
    if (!['worker','customer'].includes(role)) return res.status(400).json({error:'Choose a valid account type.'});
    if (!name || !email || !password || String(password).length < 8 || !field)
      return res.status(400).json({error:'Name, email, field and a password of at least 8 characters are required.'});
    const normalized = String(email).trim().toLowerCase();
    const key = userKey(role,normalized);
    try { await readObject(key); return res.status(409).json({error:`A ${role} account already exists with this email. Please log in.`}); }
    catch (e) { if (e.name !== 'NoSuchKey' && e.$metadata?.httpStatusCode !== 404) throw e; }
    const user = {
      id: `${role}_${emailKey(normalized)}`, role, name:String(name).trim(), email:normalized,
      field:String(field), phone:String(phone||''), experience:String(experience||''),
      description:String(description||''), photo:String(photo||''), subscribed:false,
      passwordHash:await bcrypt.hash(String(password),12),
      createdAt:new Date().toISOString()
    };
    await writeObject(key,user);
    res.status(201).json({user:publicUser(user)});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not save your account to Backblaze. Check the server Backblaze settings.'}); }
});

app.post('/api/auth/login', async (req,res) => {
  try {
    const {role,email,password} = req.body || {};
    if (!['worker','customer'].includes(role) || !email || !password) return res.status(400).json({error:'Enter account type, email and password.'});
    let user;
    try { user = await readObject(userKey(role,email)); }
    catch(e) { if(e.name==='NoSuchKey'||e.$metadata?.httpStatusCode===404) return res.status(401).json({error:`No ${role} account found for that email.`}); throw e; }
    if (!await bcrypt.compare(String(password),user.passwordHash)) return res.status(401).json({error:'Incorrect password.'});
    res.json({user:publicUser(user)});
  } catch(e) { console.error(e); res.status(500).json({error:'Login could not be completed. Please try again.'}); }
});

app.post('/api/subscription', async (req,res) => {
  try {
    const {role,email,active} = req.body || {};
    if (!['worker','customer'].includes(role) || !email) return res.status(400).json({error:'Invalid account.'});
    const key=userKey(role,email), user=await readObject(key);
    user.subscribed=!!active; user.updatedAt=new Date().toISOString();
    await writeObject(key,user);
    res.json({user:publicUser(user)});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not update subscription in Backblaze.'}); }
});

app.post('/api/upload', upload.single('file'), async (req,res) => {
  try {
    if (!req.file) return res.status(400).json({error:'Select an image to upload.'});
    if (!req.file.mimetype.startsWith('image/')) return res.status(400).json({error:'Only image files are allowed.'});
    const ext = (req.file.originalname.match(/\.(png|jpe?g|webp|gif)$/i)||[])[0] || '.img';
    const key=`uploads/${crypto.randomUUID()}${ext.toLowerCase()}`;
    await s3.send(new PutObjectCommand({Bucket:bucket,Key:key,Body:req.file.buffer,ContentType:req.file.mimetype}));
    res.json({key,url:`${process.env.B2_PUBLIC_BASE_URL.replace(/\/$/,'')}/${key}`});
  } catch(e) { console.error(e); res.status(500).json({error:'Image upload to Backblaze failed.'}); }
});

app.get('/api/workers', async (req,res) => {
  try {
    const field=String(req.query.field||'');
    const listed=await s3.send(new ListObjectsV2Command({Bucket:bucket,Prefix:'users/worker/'}));
    const workers=[];
    for (const obj of (listed.Contents||[])) {
      try { const u=await readObject(obj.Key); if((process.env.AIN_TEST_MODE==='true' || u.subscribed) && u.field===field) workers.push(publicUser(u)); }
      catch(e) { console.warn('Skipping unreadable worker record',obj.Key); }
    }
    res.json({workers});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not retrieve workers from Backblaze.'}); }
});
app.get('/api/workers/:id', async (req,res) => {
  try {
    const listed=await s3.send(new ListObjectsV2Command({Bucket:bucket,Prefix:'users/worker/'}));
    for(const obj of (listed.Contents||[])) {
      const u=await readObject(obj.Key);
      if(u.id===req.params.id && (process.env.AIN_TEST_MODE==='true' || u.subscribed)) return res.json({worker:publicUser(u)});
    }
    res.status(404).json({error:'Worker profile not found.'});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not load worker profile.'}); }
});

// Serve the AIN single-page app from the same Render service.
app.use(express.static(path.join(__dirname,'public')));
app.get('/{*splat}', (req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
const port=process.env.PORT||10000;
app.listen(port,()=>console.log(`AIN API listening on ${port}`));
