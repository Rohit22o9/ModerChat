const mongoose = require("mongoose");

const groupSchema = new mongoose.Schema({
    name: { type: String, required: true },
    icon: { type: String, default: null },
    admin: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Group", groupSchema);
