const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const User = require('./models/user');
const Chat = require('./models/chat');
const path = require('path');
const app = express();
const server = require('http').createServer(app);
const io = require('socket.io')(server);
const multer = require('multer');
const fs = require('fs');
require('dotenv').config();
const { decrypt } = require('./utils/crypto');

// ----------- DATABASE CONNECTION -----------
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log("MongoDB Atlas connected successfully!"))
  .catch((err) => console.error("MongoDB connection error:", err));

// ----------- MIDDLEWARE -----------
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Added for handling JSON requests
app.use(express.static(path.join(__dirname, 'public')));
app.use('/media', express.static(path.join(__dirname, 'public', 'media')));
app.set('view engine', 'ejs');

// ----------- SESSION STORE -----------
app.use(session({
    secret: 'mini-whatsapp-secret',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        ttl: 14 * 24 * 60 * 60
    }),
    cookie: { maxAge: 14 * 24 * 60 * 60 * 1000 }
}));

// ----------- MULTER SETTINGS -----------
const avatarStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = path.join(__dirname, 'public', 'avatars');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const avatarUpload = multer({ storage: avatarStorage });

const mediaStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = path.join(__dirname, 'public', 'media');
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const mediaUpload = multer({ storage: mediaStorage });

// ----------- ROUTES -----------
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard'); 
    res.render('login');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.userId = user._id;
        res.redirect('/dashboard');
    } else {
        res.send('Invalid credentials');
    }
});

app.get('/signup', (req, res) => 
    res.render('signup', { errors: {}, username: '', email: '', profession: '', location: '' })
);

app.post('/signup', avatarUpload.single('avatar'), async (req, res) => {
    const { username, email, password, profession, location } = req.body;
    let errors = {};

    const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
    if (!emailRegex.test(email)) errors.email = "Invalid email format.";
    if (!username || username.length < 3) errors.username = "Username must be at least 3 characters.";
    const passwordRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*()_+[\]{};':"\\|,.<>/?]).{6,}$/;
    if (!passwordRegex.test(password)) errors.password = "Password must be at least 6 characters and include one uppercase letter and one special character.";
    if (await User.findOne({ username })) errors.username = "Username already taken. Choose another.";
    if (await User.findOne({ email })) errors.email = "Email already registered.";
    
    if (Object.keys(errors).length > 0) 
        return res.render('signup', { errors, username, email, profession, location });

    const hashedPassword = await bcrypt.hash(password, 10);
    const avatarPath = req.file ? req.file.filename : null;
    const newUser = new User({ username, email, password: hashedPassword, profession, location, avatar: avatarPath });
    await newUser.save();
    res.redirect('/login');
});

app.get('/dashboard', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');

    const users = await User.find({ _id: { $ne: req.session.userId } });
    const currentUser = await User.findById(req.session.userId);

    const decryptedUsers = users.map(u => u.getDecrypted());
    const decryptedCurrentUser = currentUser.getDecrypted();

    res.render('dashboard', { users: decryptedUsers, currentUser: decryptedCurrentUser });
});

app.post('/startchat', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    const receiverId = req.body.to;
    if (!await User.findById(receiverId)) return res.send("User not found");
    res.redirect(`/chat/${receiverId}`);
});

app.get('/chat/:id', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    const otherUser = await User.findById(req.params.id);
    const currentUser = await User.findById(req.session.userId);
    if (!otherUser || !currentUser) return res.send("User not found!");
    
    const rawChats = await Chat.find({ 
        $or: [{ from: currentUser._id, to: otherUser._id }, { from: otherUser._id, to: currentUser._id }],
        // Filter out messages that are deleted for this user
        $and: [
            { deletedForEveryone: { $ne: true } },
            { deletedFor: { $ne: currentUser._id } }
        ]
    }).sort({ created_at: 1 });

    const chats = rawChats.map(chat => chat.getDecrypted());

    res.render('chat', { otherUser, currentUser, chats });
});

app.post('/chat/:id', mediaUpload.single('media'), async (req, res) => {
    try {
        console.log("REQ FILE:", req.file);
        console.log("REQ BODY:", req.body);

        const from = req.session.userId;
        const to = req.params.id;
        const msg = req.body.msg || '';
        const media = req.file ? `/media/${req.file.filename}` : null;

        console.log("MEDIA URL SAVED:", media);

        const newChat = await Chat.create({ from, to, msg, media, status: 'sent' });

        const decryptedChat = newChat.getDecrypted();

        // Send decrypted message to frontend
        io.to([from, to].sort().join('_')).emit('chat message', decryptedChat);

        res.json(decryptedChat);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to send message" });
    }
});

// ----------- UPDATED DELETE/EDIT ROUTES -----------

// Delete message route - FIXED VERSION
app.delete('/message/:messageId', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
        
        const { messageId } = req.params;
        const { deleteType } = req.body; // 'forMe' or 'forEveryone'
        const currentUserId = req.session.userId;
        
        const message = await Chat.findById(messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });
        
        // Check if user is the sender
        if (message.from.toString() !== currentUserId) {
            return res.status(403).json({ error: 'You can only delete your own messages' });
        }
        
        const roomId = [message.from, message.to].sort().join('_');
        
        if (deleteType === 'forEveryone') {
            // Mark message as deleted for everyone
            message.deletedForEveryone = true;
            await message.save();
            
            // Notify all users in the room
            io.to(roomId).emit('message deleted', { messageId, deleteType: 'forEveryone' });
        } else {
            // Mark as deleted for current user only
            if (!message.deletedFor.includes(currentUserId)) {
                message.deletedFor.push(currentUserId);
                await message.save();
            }
            
            // Only notify the current user (since it's only deleted for them)
            io.to(currentUserId).emit('message deleted', { messageId, deleteType: 'forMe' });
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('Delete message error:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// Edit message route - ENHANCED VERSION
app.put('/message/:messageId', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
        
        const { messageId } = req.params;
        const { newMessage } = req.body;
        const currentUserId = req.session.userId;
        
        const message = await Chat.findById(messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });
        
        // Check if user is the sender
        if (message.from.toString() !== currentUserId) {
            return res.status(403).json({ error: 'You can only edit your own messages' });
        }
        
        // Check if message is deleted
        if (message.deletedForEveryone || message.deletedFor.includes(currentUserId)) {
            return res.status(400).json({ error: 'Cannot edit deleted message' });
        }
        
        // Check if message is not too old (optional: 15 minutes limit)
        const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
        if (message.created_at < fifteenMinutesAgo) {
            return res.status(400).json({ error: 'Message too old to edit (15 minute limit)' });
        }
        
        // Check if it's a media-only message
        if (!message.msg && message.media) {
            return res.status(400).json({ error: 'Cannot edit media-only messages' });
        }
        
        // Update the message
        message.msg = newMessage;
        message.edited = true;
        message.editedAt = new Date();
        await message.save();
        
        const decryptedMessage = message.getDecrypted();
        
        // Notify all users in the room
        const roomId = [message.from, message.to].sort().join('_');
        io.to(roomId).emit('message edited', decryptedMessage);
        
        res.json({ success: true, message: decryptedMessage });
    } catch (error) {
        console.error('Edit message error:', error);
        res.status(500).json({ error: 'Failed to edit message' });
    }
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// ----------- SOCKET.IO -------------
io.on('connection', (socket) => {
    console.log('A user connected');

    socket.on('userOnline', async (userId) => {
        socket.userId = userId;
        socket.join(userId); // Join a room with their own ID for individual notifications
        await User.findByIdAndUpdate(userId, { online: true });
        io.emit('userStatus', { userId, online: true });
    });

    socket.on('joinRoom', (roomId) => socket.join(roomId));

    socket.on('message delivered', async ({ messageId }) => {
        try { await Chat.findByIdAndUpdate(messageId, { status: 'delivered' }); } 
        catch (err) { console.error('Error updating message status:', err); }
    });

    socket.on('messages seen', async (data) => {
        try {
            await Chat.updateMany({ from: data.to, to: data.from, status: { $ne: 'seen' } }, { $set: { status: 'seen' } });
            const roomId = [data.to, data.from].sort().join('_');
            io.to(roomId).emit('messages seen', { from: data.to, to: data.from });
        } catch (err) { console.error('Error updating seen messages:', err); }
    });

    socket.on('disconnect', async () => {
        if (socket.userId) {
            await User.findByIdAndUpdate(socket.userId, { online: false });
            io.emit('userStatus', { userId: socket.userId, online: false });
        }
        console.log('A user disconnected');
    });
});

const os = require('os');
const networkInterfaces = os.networkInterfaces();
let localIp;
for (let iface of Object.values(networkInterfaces)) {
    for (let i of iface) {
        if (i.family === 'IPv4' && !i.internal) { localIp = i.address; break; }
    }
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));