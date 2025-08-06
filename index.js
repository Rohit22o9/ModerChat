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
// Configure multer for different file types
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        let uploadPath = 'public/';

        if (file.fieldname === 'avatar') {
            uploadPath += 'avatars/';
        } else if (file.fieldname === 'icon') {
            uploadPath += 'group_icons/';
        } else {
            uploadPath += 'media/';
        }

        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit for videos
    fileFilter: (req, file, cb) => {
        // Allow images, documents, audio, and videos
        const allowedTypes = /jpeg|jpg|png|gif|webp|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|mp3|wav|ogg|webm|m4a|mp4|avi|mov|wmv|flv|mkv/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Unsupported file type'));
        }
    }
});

const mediaUpload = upload.single('media');
const avatarUpload = upload.single('avatar');
const iconUpload = upload.single('icon');

// ----------- AUTHROUTES -----------
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
        const originalName = req.file ? req.file.originalname : null;

        const newChat = await Chat.create({ from, to, msg, media, originalName, status: 'sent' });
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

// ----------- API ROUTES -----------
app.get('/api/users/available-for-group/:groupId', async (req, res) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const group = await Group.findById(req.params.groupId);
        if (!group) {
            return res.status(404).json({ error: 'Group not found' });
        }

        // Check if user is admin
        if (!group.admin.equals(req.session.userId)) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        // Get users who are not already members
        const users = await User.find({ 
            _id: { 
                $nin: group.members,
                $ne: req.session.userId
            } 
        }).select('username _id');

        res.json(users.map(user => ({ _id: user._id, username: user.username })));
    } catch (error) {
        console.error('Available users error:', error);
        res.status(500).json({ error: 'Error fetching users' });
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

        const chats = await GroupChat.find({ 
            group: group._id,
            $and: [
                { deletedForEveryone: { $ne: true } },
                { deletedFor: { $ne: req.session.userId } }
            ]
        })
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

app.post('/groupchat/:groupId', mediaUpload.single('media'), async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

        const { groupId } = req.params;
        const userId = req.session.userId;
        const msg = req.body.msg || '';
        const media = req.file ? `/media/${req.file.filename}` : null;
        const originalName = req.file ? req.file.originalname : null;
        const replyTo = req.body.replyTo || null;

        const group = await Group.findById(groupId);
        if (!group || !group.members.includes(userId)) {
            return res.status(403).json({ error: 'Not a group member' });
        }

        const newMessage = await GroupChat.create({
            group: groupId,
            from: userId,
            msg,
            media,
            originalName,
            replyTo
        });

        const populatedMessage = await GroupChat.findById(newMessage._id)
            .populate('from', 'username avatar')
            .populate('replyTo');

        io.to(`group_${groupId}`).emit('group message', populatedMessage);
        res.json({ success: true, message: populatedMessage });
    } catch (error) {
        console.error('Send group message error:', error);
        res.status(500).json({ error: 'Failed to send group message' });
    }
});

app.post('/groups/:id/add', async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group) {
            return res.status(404).json({ error: 'Group not found' });
        }

        if (!group.admin.equals(req.session.userId)) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        const { userId } = req.body;

        // Check if user exists
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if user is already a member
        if (group.members.includes(userId)) {
            return res.status(400).json({ error: 'User is already a member' });
        }

        group.members.push(userId);
        await group.save();

        // Notify the new member via socket
        io.to(userId).emit('added-to-group', {
            groupId: group._id,
            groupName: group.name,
            addedBy: req.session.userId
        });

        res.json({ success: true, message: 'Member added successfully' });
    } catch (error) {
        console.error('Add member error:', error);
        res.status(500).json({ error: 'Error adding member' });
    }
});

app.post('/groups/:id/remove', async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group) {
            return res.status(404).json({ error: 'Group not found' });
        }

        if (!group.admin.equals(req.session.userId)) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        const { userId } = req.body;

        // Check if user is a member
        if (!group.members.includes(userId)) {
            return res.status(400).json({ error: 'User is not a member' });
        }

        // Cannot remove admin
        if (group.admin.toString() === userId) {
            return res.status(400).json({ error: 'Cannot remove admin' });
        }

        group.members = group.members.filter(m => m.toString() !== userId);
        await group.save();

        // Notify the removed member via socket
        io.to(userId).emit('removed-from-group', {
            groupId: group._id,
            groupName: group.name,
            removedBy: req.session.userId
        });

        res.json({ success: true, message: 'Member removed successfully' });
    } catch (error) {
        console.error('Remove member error:', error);
        res.status(500).json({ error: 'Error removing member' });
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

app.post('/groups/:id/exit', async (req, res) => {
    try {
        const group = await Group.findById(req.params.id);
        if (!group) {
            return res.status(404).json({ error: 'Group not found' });
        }

        // Check if user is a member
        if (!group.members.includes(req.session.userId)) {
            return res.status(400).json({ error: 'You are not a member of this group' });
        }

        // Admin cannot exit (must transfer ownership first)
        if (group.admin.toString() === req.session.userId) {
            return res.status(400).json({ error: 'Admin cannot exit group. Transfer ownership first or delete the group.' });
        }

        // Remove user from group
        group.members = group.members.filter(m => m.toString() !== req.session.userId);
        await group.save();

        // Notify other members via socket
        const currentUser = await User.findById(req.session.userId);
        io.to(`group_${group._id}`).emit('member-left-group', {
            groupId: group._id,
            user: {
                id: currentUser._id,
                username: currentUser.username
            }
        });

        res.json({ success: true, message: 'Successfully exited group' });
    } catch (error) {
        console.error('Exit group error:', error);
        res.status(500).json({ error: 'Error exiting group' });
    }
});

// ----------- GROUP MESSAGE MANAGEMENT ROUTES -----------
app.delete('/groupmessage/:messageId', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

        const { messageId } = req.params;
        const { deleteType } = req.body;
        const currentUserId = req.session.userId;

        const message = await GroupChat.findById(messageId).populate('group');
        if (!message) return res.status(404).json({ error: 'Message not found' });

        // Check if user is a member of the group
        if (!message.group.members.includes(currentUserId)) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        if (message.from.toString() !== currentUserId) {
            return res.status(403).json({ error: 'You can only delete your own messages' });
        }

        if (deleteType === 'forEveryone') {
            message.deletedForEveryone = true;
            await message.save();
            io.to(`group_${message.group._id}`).emit('group message deleted', { messageId, deleteType: 'forEveryone' });
        } else {
            if (!message.deletedFor.includes(currentUserId)) {
                message.deletedFor.push(currentUserId);
                await message.save();
            }
            io.to(currentUserId).emit('group message deleted', { messageId, deleteType: 'forMe' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Delete group message error:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

app.put('/groupmessage/:messageId', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

        const { messageId } = req.params;
        const { newMessage } = req.body;
        const currentUserId = req.session.userId;

        const message = await GroupChat.findById(messageId).populate('group').populate('from');
        if (!message) return res.status(404).json({ error: 'Message not found' });

        // Check if user is a member of the group
        if (!message.group.members.includes(currentUserId)) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        if (message.from._id.toString() !== currentUserId) {
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

        const updatedMessage = await GroupChat.findById(messageId).populate('from');
        io.to(`group_${message.group._id}`).emit('group message edited', updatedMessage);

        res.json({ success: true, message: updatedMessage });
    } catch (error) {
        console.error('Edit group message error:', error);
        res.status(500).json({ error: 'Failed to edit message' });
    }
});

// ----------- REACTION ROUTES -----------
app.post('/message/:messageId/react', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

        const { messageId } = req.params;
        const { emoji } = req.body;
        const userId = req.session.userId;

        const message = await Chat.findById(messageId);
        if (!message) return res.status(404).json({ error: 'Message not found' });

        // Check if user is part of the conversation
        if (message.from.toString() !== userId && message.to.toString() !== userId) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        let reactionIndex = message.reactions.findIndex(r => r.emoji === emoji);

        if (reactionIndex === -1) {
            // Add new reaction
            message.reactions.push({ emoji, users: [userId] });
        } else {
            // Toggle existing reaction
            const userIndex = message.reactions[reactionIndex].users.indexOf(userId);
            if (userIndex === -1) {
                message.reactions[reactionIndex].users.push(userId);
            } else {
                message.reactions[reactionIndex].users.splice(userIndex, 1);
                // Remove reaction if no users left
                if (message.reactions[reactionIndex].users.length === 0) {
                    message.reactions.splice(reactionIndex, 1);
                }
            }
        }

        await message.save();

        const roomId = [message.from, message.to].sort().join('_');
        io.to(roomId).emit('message reaction', {
            messageId,
            reactions: message.reactions
        });

        res.json({ success: true, reactions: message.reactions });
    } catch (error) {
        console.error('React to message error:', error);
        res.status(500).json({ error: 'Failed to react to message' });
    }
});

app.post('/groupmessage/:messageId/react', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

        const { messageId } = req.params;
        const { emoji } = req.body;
        const userId = req.session.userId;

        const message = await GroupChat.findById(messageId).populate('group');
        if (!message) return res.status(404).json({ error: 'Message not found' });

        // Check if user is a member of the group
        if (!message.group.members.includes(userId)) {
            return res.status(403).json({ error: 'Not a group member' });
        }

        let reactionIndex = message.reactions.findIndex(r => r.emoji === emoji);

        if (reactionIndex === -1) {
            message.reactions.push({ emoji, users: [userId] });
        } else {
            const userIndex = message.reactions[reactionIndex].users.indexOf(userId);
            if (userIndex === -1) {
                message.reactions[reactionIndex].users.push(userId);
            } else {
                message.reactions[reactionIndex].users.splice(userIndex, 1);
                if (message.reactions[reactionIndex].users.length === 0) {
                    message.reactions.splice(reactionIndex, 1);
                }
            }
        }

        await message.save();

        io.to(`group_${message.group._id}`).emit('group message reaction', {
            messageId,
            reactions: message.reactions
        });

        res.json({ success: true, reactions: message.reactions });
    } catch (error) {
        console.error('React to group message error:', error);
        res.status(500).json({ error: 'Failed to react to message' });
    }
});

// ----------- POLL ROUTES -----------
app.post('/groupchat/:groupId/poll', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

        const { groupId } = req.params;
        const { question, options, allowMultiple, duration } = req.body;
        const userId = req.session.userId;

        const group = await Group.findById(groupId);
        if (!group || !group.members.includes(userId)) {
            return res.status(403).json({ error: 'Not a group member' });
        }

        const expiresAt = duration ? new Date(Date.now() + duration * 60 * 60 * 1000) : null;

        const pollMessage = await GroupChat.create({
            group: groupId,
            from: userId,
            poll: {
                question,
                options: options.map(opt => ({ text: opt, votes: [] })),
                allowMultiple: allowMultiple || false,
                expiresAt
            }
        });

        const populatedPoll = await GroupChat.findById(pollMessage._id).populate('from', 'username avatar');

        io.to(`group_${groupId}`).emit('group message', populatedPoll);
        res.json({ success: true, poll: populatedPoll });
    } catch (error) {
        console.error('Create poll error:', error);
        res.status(500).json({ error: 'Failed to create poll' });
    }
});

app.post('/groupmessage/:messageId/vote', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

        const { messageId } = req.params;
        const { optionIndex } = req.body;
        const userId = req.session.userId;

        const message = await GroupChat.findById(messageId).populate('group');
        if (!message || !message.poll) return res.status(404).json({ error: 'Poll not found' });

        if (!message.group.members.includes(userId)) {
            return res.status(403).json({ error: 'Not a group member' });
        }

        // Check if poll has expired
        if (message.poll.expiresAt && new Date() > message.poll.expiresAt) {
            return res.status(400).json({ error: 'Poll has expired' });
        }

        const option = message.poll.options[optionIndex];
        if (!option) return res.status(400).json({ error: 'Invalid option' });

        // Handle voting logic
        if (!message.poll.allowMultiple) {
            // Remove user from all options first if single choice
            message.poll.options.forEach(opt => {
                const userIndex = opt.votes.indexOf(userId);
                if (userIndex !== -1) opt.votes.splice(userIndex, 1);
            });
        }

        // Toggle vote for selected option
        const userIndex = option.votes.indexOf(userId);
        if (userIndex === -1) {
            option.votes.push(userId);
        } else {
            option.votes.splice(userIndex, 1);
        }

        await message.save();

        io.to(`group_${message.group._id}`).emit('poll update', {
            messageId,
            poll: message.poll
        });

        res.json({ success: true, poll: message.poll });
    } catch (error) {
        console.error('Vote on poll error:', error);
        res.status(500).json({ error: 'Failed to vote on poll' });
    }
});

// ----------- THEME PREFERENCE ROUTE -----------
app.post('/user/theme', async (req, res) => {
    try {
        if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });

        const { theme } = req.body;
        if (!['light', 'dark', 'auto'].includes(theme)) {
            return res.status(400).json({ error: 'Invalid theme' });
        }

        await User.findByIdAndUpdate(req.session.userId, { theme });
        res.json({ success: true });
    } catch (error) {
        console.error('Update theme error:', error);
        res.status(500).json({ error: 'Failed to update theme' });
    }
});

// ----------- CALL ROUTES -----------
app.post('/call/initiate/group', async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { groupId, type } = req.body;

        if (!groupId || !type || !['audio', 'video'].includes(type)) {
            return res.status(400).json({ error: 'Invalid call parameters' });
        }

        const group = await Group.findById(groupId).populate('members');
        if (!group) {
            return res.status(404).json({ error: 'Group not found' });
        }

        if (!group.members.some(m => m._id.equals(req.session.userId))) {
            return res.status(403).json({ error: 'Not authorized' });
        }

        const caller = await User.findById(req.session.userId);
        const onlineMembers = group.members.filter(m => m.online && !m._id.equals(req.session.userId));

        if (onlineMembers.length === 0) {
            return res.status(400).json({ error: 'No online members to call' });
        }

        // Create call record for the group
        const call = new Call({
            caller: req.session.userId,
            receiver: null, // No specific receiver for group calls
            groupId: groupId,
            type,
            status: 'ringing'
        });

        await call.save();

        // Notify all online group members except the caller
        onlineMembers.forEach(member => {
            io.to(member._id.toString()).emit('incoming-group-call', {
                callId: call._id,
                groupId: groupId,
                groupName: group.name,
                caller: {
                    id: caller._id,
                    username: caller.username,
                    avatar: caller.avatar
                },
                type
            });
        });

        // Auto-end call after 30 seconds if no one joins
        setTimeout(async () => {
            const callCheck = await Call.findById(call._id);
            if (callCheck && callCheck.status === 'ringing') {
                callCheck.status = 'missed';
                callCheck.endTime = new Date();
                await callCheck.save();

                io.to(`group_${groupId}`).emit('group-call-timeout', { callId: call._id });
            }
        }, 30000);

        res.json({ success: true, callId: call._id });
    } catch (error) {
        console.error('Group call initiation error:', error);
        res.status(500).json({ error: 'Failed to initiate group call' });
    }
});

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

        // Handle group calls
        if (call.groupId) {
            const group = await Group.findById(call.groupId).populate('members');
            if (!group.members.some(m => m._id.equals(req.session.userId))) {
                return res.status(403).json({ error: 'Not authorized to respond to this group call' });
            }

            if (call.status !== 'ringing') {
                return res.status(400).json({ error: 'Call is no longer available' });
            }

            if (action === 'accept') {
                call.status = 'accepted';
                if (!call.participants) call.participants = [];
                if (!call.participants.includes(req.session.userId)) {
                    call.participants.push(req.session.userId);
                }
                await call.save();

                const user = await User.findById(req.session.userId);
                io.to(`group_${call.groupId}`).emit('group-call-joined', {
                    callId: call._id,
                    user: {
                        id: user._id,
                        username: user.username,
                        avatar: user.avatar
                    }
                });

                res.json({ success: true, message: 'Joined group call' });
            } else {
                res.json({ success: true, message: 'Declined group call' });
            }
            return;
        }

        // Handle personal calls
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

        // Handle group calls
        if (call.groupId) {
            const group = await Group.findById(call.groupId).populate('members');
            const isParticipant = call.caller.toString() === req.session.userId || 
                                (call.participants && call.participants.includes(req.session.userId));

            if (!isParticipant) {
                return res.status(403).json({ error: 'Not authorized to end this call' });
            }

            // If caller ends the call, end it for everyone
            if (call.caller.toString() === req.session.userId) {
                call.status = 'ended';
                call.endTime = new Date();
                await call.save();

                io.to(`group_${call.groupId}`).emit('group-call-ended', {
                    callId: call._id,
                    reason: 'Ended by caller'
                });
            } else {
                // Remove participant from call
                if (call.participants) {
                    call.participants = call.participants.filter(p => p.toString() !== req.session.userId);
                    await call.save();
                }

                const user = await User.findById(req.session.userId);
                io.to(`group_${call.groupId}`).emit('group-call-left', {
                    callId: call._id,
                    user: {
                        id: user._id,
                        username: user.username
                    }
                });
            }

            res.json({ success: true, message: 'Left group call' });
            return;
        }

        // Handle personal calls
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

    // Typing status events
    socket.on('typing start', (data) => {
        const roomId = [data.from, data.to].sort().join('_');
        socket.to(roomId).emit('user typing', { 
            userId: data.from, 
            username: data.username,
            isTyping: true 
        });
    });

    socket.on('typing stop', (data) => {
        const roomId = [data.from, data.to].sort().join('_');
        socket.to(roomId).emit('user typing', { 
            userId: data.from, 
            username: data.username,
            isTyping: false 
        });
    });

    // Group typing events
    socket.on('group typing start', (data) => {
        socket.to(`group_${data.groupId}`).emit('group user typing', { 
            userId: data.from, 
            username: data.username,
            isTyping: true 
        });
    });

    socket.on('group typing stop', (data) => {
        socket.to(`group_${data.groupId}`).emit('group user typing', { 
            userId: data.from, 
            username: data.username,
            isTyping: false 
        });
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

    // Group call WebRTC signaling
    socket.on('group-call-offer', (data) => {
        socket.to(`group_${data.groupId}`).emit('group-call-offer', {
            offer: data.offer,
            from: data.from,
            callId: data.callId,
            groupId: data.groupId
        });
    });

    socket.on('group-call-answer', (data) => {
        socket.to(`group_${data.groupId}`).emit('group-call-answer', {
            answer: data.answer,
            from: data.from,
            callId: data.callId,
            groupId: data.groupId
        });
    });

    socket.on('group-ice-candidate', (data) => {
        socket.to(`group_${data.groupId}`).emit('group-ice-candidate', {
            candidate: data.candidate,
            from: data.from,
            callId: data.callId,
            groupId: data.groupId
        });
    });

    // Group management events
    socket.on('group-member-added', (data) => {
        socket.to(`group_${data.groupId}`).emit('member-added-to-group', data);
    });

    socket.on('group-member-removed', (data) => {
        socket.to(`group_${data.groupId}`).emit('member-removed-from-group', data);
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