const mongoose = require("mongoose");
const { encrypt, decrypt } = require("../utils/crypto");

const chatSchema = new mongoose.Schema({
    from: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    to: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    msg: { type: String, required: false },
    media: String,
    status: { type: String, enum: ['sent', 'delivered', 'seen'], default: 'sent' },
    created_at: { type: Date, default: Date.now },
    // New fields for delete and edit functionality
    deletedFor: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // Array of user IDs who deleted this message for themselves
    deletedForEveryone: { type: Boolean, default: false }, // True if message is deleted for everyone
    edited: { type: Boolean, default: false },
    editedAt: { type: Date }
});

chatSchema.pre('save', function (next) {
    if (this.isModified('msg') && this.msg) {
        this.msg = encrypt(this.msg);
    }
    next();
});

chatSchema.methods.getDecrypted = function () {
    const obj = this.toObject();
    obj.msg = this.msg ? decrypt(this.msg) : '';
    return obj;
};

// Method to check if message is deleted for a specific user
chatSchema.methods.isDeletedForUser = function(userId) {
    return this.deletedForEveryone || this.deletedFor.includes(userId);
};

const Chat = mongoose.model("Chat", chatSchema);
module.exports = Chat;