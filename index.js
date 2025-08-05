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
const Group = require('./models/group');
const GroupChat = require('./models/groupChat');
const Call = require('./models/call');

// ----------- DATABASE CONNECTION -----------
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log("MongoDB Atlas connected successfully!"))
  .catch((err) => console.error("MongoDB connection error:", err));

// ----------- MIDDLEWARE -----------
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/media', express.static(path.join(__dirname, 'public', 'media')));
app.set('view engine', 'ejs');

// ----------- SESSION STORE -----------
app.use(session({
    secret: process.env.SESSION_SECRET || 'mini-whatsapp-secret',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        ttl: 14 * 24 * 60 * 60
    }),
    cookie: { 
        maxAge: 14 * 24 * 60 * 60 * 1000,
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true
    }
}));

// ----------- FILE UPLOAD CONFIGURATION -----------
const configureUpload = (subfolder) => {
    return multer({
        storage: multer.diskStorage({
            destination: (req, file, cb) => {
                const dir = path.join(__dirname, 'public', subfolder);
                if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
                cb(null, dir);
            },
            filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
        }),
        limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
        fileFilter: (req, file, cb) => {
            const filetypes = /jpeg|jpg|png|gif|mp4|mpeg|pdf/;
            const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
            const mimetype = filetypes.test(file.mimetype);
            if (extname && mimetype) {
                return cb(null, true);
            }
            cb(new Error('Error: File upload only supports the following filetypes - ' + filetypes));
        }
    });
};

const avatarUpload = configureUpload('avatars');
const mediaUpload = configureUpload('media');
const groupIconUpload = configureUpload('group_icons');

// ----------- AUTH ROUTES -----------
app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard'); 
    res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.render('login', { error: 'Invalid credentials' });
        }

        req.session.regenerate(() => {
            req.session.userId = user._id;
            res.redirect('/dashboard');
        });
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', { error: 'An error occurred during login' });
    }
});

app.get('/signup', (req, res) => 
    res.render('signup', { errors: {}, username: '', email: '', profession: '', location: '' })
);

app.post('/signup', avatarUpload.single('avatar'), async (req, res) => {
    try {
        const { username, email, password, profession, location } = req.body;
        let errors = {};

        // Validation
        const emailRegex = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
        if (!emailRegex.test(email)) errors.email = "Invalid email format.";
        if (!username || username.length < 3) errors.username = "Username must be at least 3 characters.";
        const passwordRegex = /^(?=.*[A-Z])(?=.*[!@#$%^&*()_+[\]{};':"\\|,.<>/?]).{6,}$/;
        if (!passwordRegex.test(password)) errors.password = "Password must be at least 6 characters and include one uppercase letter and one special character.";
        if (await User.findOne({ username })) errors.username = "Username already taken. Choose another.";
        if (await User.findOne({ email })) errors.email = "Email already registered.";
        
        if (Object.keys(errors).length > 0) {
            return res.render('signup', { errors, username, email, profession, location });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const avatarPath = req.file ? `/avatars/${req.file.filename}` : null;
        
        const newUser = new User({ 
            username, 
            email, 
            password: hashedPassword, 
            profession, 
            location, 
            avatar: avatarPath 
        });
        
        await newUser.save();
        res.redirect('/login');
    } catch (error) {
        console.error('Signup error:', error);
        res.render('signup', { 
            errors: { general: 'An error occurred during registration' },
            username: req.body.username,
            email: req.body.email,
            profession: req.body.profession,
            location: req.body.location
        });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// ----------- DASHBOARD & CHAT ROUTES -----------
app.get('/dashboard', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');

    try {
        const users = await User.find({ _id: { $ne: req.session.userId } });
        const currentUser = await User.findById(req.session.userId);
        const groups = await Group.find({ members: req.session.userId });

        res.render('dashboard', { 
            users: users.map(u => u.getDecrypted()), 
            currentUser: currentUser.getDecrypted(),
            groups
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).send('Error loading dashboard');
    }
});

app.post('/startchat', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    
    try {
        const receiverId = req.body.to;
        if (!await User.findById(receiverId)) return res.status(404).send("User not found");
        res.redirect(`/chat/${receiverId}`);
    } catch (error) {
        console.error('Start chat error:', error);
        res.status(500).send('Error starting chat');
    }
});

app.get('/chat/:id', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    
    try {
        const otherUser = await User.findById(req.params.id);
        const currentUser = await User.findById(req.session.userId);
        
        if (!otherUser || !currentUser) return res.status(404).send("User not found!");
        
        const rawChats = await Chat.find({ 
            $or: [{ from: currentUser._id, to: otherUser._id }, { from: otherUser._id, to: currentUser._id }],
            $and: [
                { deletedForEveryone: { $ne: true } },
                { deletedFor: { $ne: currentUser._id } }
            ]
        }).sort({ created_at: 1 });

        res.render('chat', { 
            otherUser: otherUser.getDecrypted(), 
            currentUser: currentUser.getDecrypted(), 
            chats: rawChats.map(chat => chat.getDecrypted()) 
        });
    } catch (error) {
        console.error('Chat error:', error);
        res.status(500).send('Error loading chat');
    }
});

app.post('/chat/:id', mediaUpload.single('media'), async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

        const from = req.session.userId;
        const to = req.params.id;
        const msg = req.body.msg || '';
        const media = req.file ? `/media/${req.file.filename}` : null;

        const newChat = await Chat.create({ from, to, msg, media, status: 'sent' });
        const decryptedChat = newChat.getDecrypted();

        io.to([from, to].sort().join('_')).emit('chat message', decryptedChat);
        res.json(decryptedChat);
    } catch (error) {
        console.error('Send message error:', error);
        res.status(500).json({ error: "Failed to send message" });
    }
});

// ----------- MESSAGE MANAGEMENT ROUTES -----------
app.delete('/message/:messageId', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
        
        const { messageId } = req.params;
        const { deleteType } = req.body;
        const currentUserId = req.session.userId;
        
        const message = await Chat.findById(messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });
        
        if (message.from.toString() !== currentUserId) {
            return res.status(403).json({ error: 'You can only delete your own messages' });
        }
        
        const roomId = [message.from, message.to].sort().join('_');
        
        if (deleteType === 'forEveryone') {
            message.deletedForEveryone = true;
            await message.save();
            io.to(roomId).emit('message deleted', { messageId, deleteType: 'forEveryone' });
        } else {
            if (!message.deletedFor.includes(currentUserId)) {
                message.deletedFor.push(currentUserId);
                await message.save();
            }
            io.to(currentUserId).emit('message deleted', { messageId, deleteType: 'forMe' });
        }
        
        res.json({ success: true });
    } catch (error) {
        console.error('Delete message error:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

app.put('/message/:messageId', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
        
        const { messageId } = req.params;
        const { newMessage } = req.body;
        const currentUserId = req.session.userId;
        
        const message = await Chat.findById(messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });
        
        if (message.from.toString() !== currentUserId) {
            return res.status(403).json({ error: 'You can only edit your own messages' });
        }
        
        if (message.deletedForEveryone || message.deletedFor.includes(currentUserId)) {
            return res.status(400).json({ error: 'Cannot edit deleted message' });
        }
        
        const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
        if (message.created_at < fifteenMinutesAgo) {
            return res.status(400).json({ error: 'Message too old to edit (15 minute limit)' });
        }
        
        if (!message.msg && message.media) {
            return res.status(400).json({ error: 'Cannot edit media-only messages' });
        }
        
        message.msg = newMessage;
        message.edited = true;
        message.editedAt = new Date();
        await message.save();
        
        const decryptedMessage = message.getDecrypted();
        const roomId = [message.from, message.to].sort().join('_');
        io.to(roomId).emit('message edited', decryptedMessage);
        
        res.json({ success: true, message: decryptedMessage });
    } catch (error) {
        console.error('Edit message error:', error);
        res.status(500).json({ error: 'Failed to edit message' });
    }
});

// ----------- GROUP ROUTES -----------
app.get('/groups', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    
    try {
        const groups = await Group.find({ members: req.session.userId })
            .populate('admin')
            .populate('members');
            
        res.render('groups_list', { 
            groups, 
            currentUser: await User.findById(req.session.userId) 
        });
    } catch (error) {
        console.error('Groups list error:', error);
        res.status(500).send('Error loading groups');
    }
});

app.get('/groups/create', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    
    try {
        const users = await User.find({ _id: { $ne: req.session.userId } });
        res.render('group_create', { 
            users, 
            currentUser: await User.findById(req.session.userId) 
        });
    } catch (error) {
        console.error('Group create page error:', error);
        res.status(500).send('Error loading group creation page');
    }
});

app.post('/groups/create', groupIconUpload.single('icon'), async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    
    try {
        const { name, members } = req.body;
        const icon = req.file ? `/group_icons/${req.file.filename}` : null;
        const memberArray = Array.isArray(members) ? members : [members];
        
        const group = await Group.create({
            name,
            icon,
            admin: req.session.userId,
            members: [req.session.userId, ...memberArray]
        });
        
        res.redirect(`/groups/${group._id}`);
    } catch (error) {
        console.error('Group creation error:', error);
        res.status(500).send('Error creating group');
    }
});

app.get('/groups/:id', async (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    
    try {
        const group = await Group.findById(req.params.id)
            .populate('members')
            .populate('admin');
            
        if (!group.members.some(m => m._id.equals(req.session.userId))) {
            return res.status(403).send('Not authorized');
        }

        const chats = await GroupChat.find({ group: group._id })
            .populate('from')
            .sort({ created_at: 1 });
            
        res.render('group_chat', { 
            group, 
            chats, 
            currentUser: await User.findById(req.session.userId) 
        });
    } catch (error) {
        console.error('Group chat error:', error);
        res.status(500).send('Error loading group chat');
    }
});

app.post('/groupchat/:id', mediaUpload.single('media'), async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

        const from = req.session.userId;
        const msg = req.body.msg || '';
        const media = req.file ? `/media/${req.file.filename}` : null;

        const newChat = await GroupChat.create({ 
            group: req.params.id, 
            from, 
            msg, 
            media 
        });
        
        const populatedChat = await newChat.populate('from');
        io.to(`group_${req.params.id}`).emit('group message', populatedChat);
        res.json(populatedChat);
    } catch (error) {
        console.error('Group message error:', error);
        res.status(500).json({ error: 'Failed to send group message' });
    }
});

app.post('/groups/:id/add', async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group.admin.equals(req.session.userId)) {
            return res.status(403).send('Not authorized');
        }
        
        group.members.push(req.body.userId);
        await group.save();
        res.redirect(`/groups/${req.params.id}`);
    } catch (error) {
        console.error('Add member error:', error);
        res.status(500).send('Error adding member');
    }
});

app.post('/groups/:id/remove', async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group.admin.equals(req.session.userId)) {
            return res.status(403).send('Not authorized');
        }
        
        group.members = group.members.filter(m => m.toString() !== req.body.userId);
        await group.save();
        res.redirect(`/groups/${req.params.id}`);
    } catch (error) {
        console.error('Remove member error:', error);
        res.status(500).send('Error removing member');
    }
});

app.post('/groups/:id/update', groupIconUpload.single('icon'), async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group.admin.equals(req.session.userId)) {
            return res.status(403).send('Not authorized');
        }
        
        if (req.body.name) group.name = req.body.name;
        if (req.file) group.icon = `/group_icons/${req.file.filename}`;
        
        await group.save();
        res.redirect(`/groups/${req.params.id}`);
    } catch (error) {
        console.error('Group update error:', error);
        res.status(500).send('Error updating group');
    }
});

// ----------- CALL ROUTES -----------
app.post('/call/initiate', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const { receiverId, type } = req.body;
        
        if (!receiverId || !type || !['audio', 'video'].includes(type)) {
            return res.status(400).json({ error: 'Invalid call parameters' });
        }
        
        const receiver = await User.findById(receiverId);
        if (!receiver) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (!receiver.online) {
            return res.status(400).json({ error: 'User is offline' });
        }
        
        const existingCall = await Call.findOne({
            $or: [
                { caller: req.session.userId, receiver: receiverId },
                { caller: receiverId, receiver: req.session.userId }
            ],
            status: { $in: ['ringing', 'accepted'] }
        });
        
        if (existingCall) {
            return res.status(400).json({ error: 'Call already in progress' });
        }
        
        const call = new Call({
            caller: req.session.userId,
            receiver: receiverId,
            type,
            status: 'ringing'
        });
        
        await call.save();
        const caller = await User.findById(req.session.userId);
        
        io.to(receiverId).emit('incoming-call', {
            callId: call._id,
            caller: {
                id: caller._id,
                username: caller.username,
                avatar: caller.avatar
            },
            type
        });
        
        setTimeout(async () => {
            const callCheck = await Call.findById(call._id);
            if (callCheck && callCheck.status === 'ringing') {
                callCheck.status = 'missed';
                callCheck.endTime = new Date();
                await callCheck.save();
                
                io.to(req.session.userId).emit('call-timeout', { callId: call._id });
                io.to(receiverId).emit('call-missed', { callId: call._id });
            }
        }, 30000);
        
        res.json({ success: true, callId: call._id });
    } catch (error) {
        console.error('Call initiation error:', error);
        res.status(500).json({ error: 'Failed to initiate call' });
    }
});

app.post('/call/:callId/respond', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const { callId } = req.params;
        const { action } = req.body;
        
        if (!['accept', 'decline'].includes(action)) {
            return res.status(400).json({ error: 'Invalid action' });
        }
        
        const call = await Call.findById(callId).populate('caller receiver');
        if (!call) {
            return res.status(404).json({ error: 'Call not found' });
        }
        
        if (call.receiver._id.toString() !== req.session.userId) {
            return res.status(403).json({ error: 'Not authorized to respond to this call' });
        }
        
        if (call.status !== 'ringing') {
            return res.status(400).json({ error: 'Call is no longer available' });
        }
        
        if (action === 'accept') {
            call.status = 'accepted';
            await call.save();
            
            io.to(call.caller._id.toString()).emit('call-accepted', {
                callId: call._id,
                receiver: {
                    id: call.receiver._id,
                    username: call.receiver.username,
                    avatar: call.receiver.avatar
                }
            });
            
            res.json({ success: true, message: 'Call accepted' });
        } else {
            call.status = 'declined';
            call.endTime = new Date();
            await call.save();
            
            io.to(call.caller._id.toString()).emit('call-declined', {
                callId: call._id
            });
            
            res.json({ success: true, message: 'Call declined' });
        }
    } catch (error) {
        console.error('Call response error:', error);
        res.status(500).json({ error: 'Failed to respond to call' });
    }
});

app.post('/call/:callId/end', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const { callId } = req.params;
        const call = await Call.findById(callId);
        if (!call) {
            return res.status(404).json({ error: 'Call not found' });
        }
        
        const isParticipant = call.caller.toString() === req.session.userId || 
                            call.receiver.toString() === req.session.userId;
        
        if (!isParticipant) {
            return res.status(403).json({ error: 'Not authorized to end this call' });
        }
        
        call.status = 'ended';
        call.endTime = new Date();
        await call.save();
        
        const otherParticipantId = call.caller.toString() === req.session.userId 
            ? call.receiver.toString() 
            : call.caller.toString();
            
        io.to(otherParticipantId).emit('call-ended', {
            callId: call._id
        });
        
        res.json({ success: true, message: 'Call ended' });
    } catch (error) {
        console.error('End call error:', error);
        res.status(500).json({ error: 'Failed to end call' });
    }
});

app.post('/call/:callId/cancel', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const { callId } = req.params;
        const call = await Call.findById(callId);
        if (!call) {
            return res.status(404).json({ error: 'Call not found' });
        }
        
        if (call.caller.toString() !== req.session.userId) {
            return res.status(403).json({ error: 'Only caller can cancel the call' });
        }
        
        if (!['ringing'].includes(call.status)) {
            return res.status(400).json({ error: 'Call cannot be cancelled in current state' });
        }
        
        call.status = 'cancelled';
        call.endTime = new Date();
        await call.save();
        
        io.to(call.receiver.toString()).emit('call-cancelled', {
            callId: call._id
        });
        
        res.json({ success: true, message: 'Call cancelled' });
    } catch (error) {
        console.error('Cancel call error:', error);
        res.status(500).json({ error: 'Failed to cancel call' });
    }
});

app.get('/calls/history', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip = (page - 1) * limit;
        
        const calls = await Call.find({
            $or: [
                { caller: req.session.userId },
                { receiver: req.session.userId }
            ]
        })
        .populate('caller receiver', 'username avatar')
        .sort({ created_at: -1 })
        .skip(skip)
        .limit(limit);
        
        const callsWithInfo = calls.map(call => {
            const callObj = call.toObject();
            const isIncoming = call.receiver._id.toString() === req.session.userId;
            const otherUser = isIncoming ? call.caller : call.receiver;
            
            return {
                ...callObj,
                isIncoming,
                otherUser,
                formattedDuration: call.formattedDuration
            };
        });
        
        res.json(callsWithInfo);
    } catch (error) {
        console.error('Call history error:', error);
        res.status(500).json({ error: 'Failed to fetch call history' });
    }
});

app.get('/calls/active', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        
        const activeCalls = await Call.find({
            $or: [
                { caller: req.session.userId },
                { receiver: req.session.userId }
            ],
            status: { $in: ['ringing', 'accepted'] }
        })
        .populate('caller receiver', 'username avatar');
        
        res.json(activeCalls);
    } catch (error) {
        console.error('Active calls error:', error);
        res.status(500).json({ error: 'Failed to fetch active calls' });
    }
});

// ----------- SOCKET.IO HANDLING -----------
io.on('connection', (socket) => {
    console.log('A user connected');

    socket.on('userOnline', async (userId) => {
        try {
            socket.userId = userId;
            socket.join(userId);
            await User.findByIdAndUpdate(userId, { online: true, lastSeen: null });
            io.emit('userStatus', { userId, online: true });
        } catch (error) {
            console.error('User online error:', error);
        }
    });

    socket.on('joinRoom', (roomId) => socket.join(roomId));
    socket.on('joinGroup', (groupId) => socket.join(`group_${groupId}`));

    socket.on('message delivered', async ({ messageId }) => {
        try {
            await Chat.findByIdAndUpdate(messageId, { status: 'delivered' });
        } catch (err) {
            console.error('Message delivered error:', err);
        }
    });

    socket.on('messages seen', async (data) => {
        try {
            await Chat.updateMany(
                { from: data.to, to: data.from, status: { $ne: 'seen' } }, 
                { $set: { status: 'seen' } }
            );
            const roomId = [data.to, data.from].sort().join('_');
            io.to(roomId).emit('messages seen', { from: data.to, to: data.from });
        } catch (err) {
            console.error('Messages seen error:', err);
        }
    });

    // WebRTC signaling
    socket.on('call-offer', (data) => {
        socket.to(data.to).emit('call-offer', {
            offer: data.offer,
            from: data.from,
            callId: data.callId
        });
    });

    socket.on('call-answer', (data) => {
        socket.to(data.to).emit('call-answer', {
            answer: data.answer,
            from: data.from,
            callId: data.callId
        });
    });

    socket.on('ice-candidate', (data) => {
        socket.to(data.to).emit('ice-candidate', {
            candidate: data.candidate,
            from: data.from,
            callId: data.callId
        });
    });

    socket.on('disconnect', async () => {
        if (socket.userId) {
            try {
                // End any active calls
                const activeCalls = await Call.find({
                    $or: [
                        { caller: socket.userId },
                        { receiver: socket.userId }
                    ],
                    status: { $in: ['ringing', 'accepted'] }
                });
                
                for (let call of activeCalls) {
                    call.status = 'ended';
                    call.endTime = new Date();
                    await call.save();
                    
                    const otherUserId = call.caller.toString() === socket.userId 
                        ? call.receiver.toString() 
                        : call.caller.toString();
                        
                    io.to(otherUserId).emit('call-ended', {
                        callId: call._id,
                        reason: 'User disconnected'
                    });
                }
                
                // Update user status
                await User.findByIdAndUpdate(socket.userId, { 
                    online: false,
                    lastSeen: new Date() 
                });
                
                io.emit('userStatus', { 
                    userId: socket.userId, 
                    online: false,
                    lastSeen: new Date()
                });
            } catch (error) {
                console.error('Disconnect error:', error);
            }
        }
        console.log('A user disconnected');
    });
});

// ----------- SERVER STARTUP -----------
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));