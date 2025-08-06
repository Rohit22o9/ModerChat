const mongoose = require("mongoose");

const groupChatSchema = new mongoose.Schema({
    group: { type: mongoose.Schema.Types.ObjectId, ref: "Group", required: true },
    from: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    msg: { type: String, default: '' },
    media: { type: String, default: null },
    originalName: { type: String, default: null },
    created_at: { type: Date, default: Date.now },
    // New fields for delete and edit functionality
    deletedFor: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }], // Array of user IDs who deleted this message for themselves
    deletedForEveryone: { type: Boolean, default: false }, // True if message is deleted for everyone
    edited: { type: Boolean, default: false },
    editedAt: { type: Date },
    // Reactions field
    reactions: [{
        emoji: { type: String, required: true },
        users: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }]
    }],
    // Reply functionality
    replyTo: { type: mongoose.Schema.Types.ObjectId, ref: "GroupChat", default: null },
    // Polls for group chats
    poll: {
        question: String,
        options: [{
            text: String,
            votes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }]
        }],
        allowMultiple: { type: Boolean, default: false },
        expiresAt: Date
    }
});

// Method to check if message is deleted for a specific user
groupChatSchema.methods.isDeletedForUser = function(userId) {
    return this.deletedForEveryone || this.deletedFor.includes(userId);
};

module.exports = mongoose.model("GroupChat", groupChatSchema);