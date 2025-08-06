const mongoose = require("mongoose");

const groupSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, default: '' },
    admin: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    icon: { type: String, default: null },
    created_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Group", groupSchema);