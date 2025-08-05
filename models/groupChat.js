const mongoose = require("mongoose");

const groupChatSchema = new mongoose.Schema({
    group: { type: mongoose.Schema.Types.ObjectId, ref: "Group", required: true },
    from: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    msg: { type: String },
    media: { type: String },
    created_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model("GroupChat", groupChatSchema);
