const mongoose = require("mongoose");
const { encrypt, decrypt } = require("../utils/crypto");

const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,  // Should be hashed separately
    profession: { type: String, default: "" },
    location: { type: String, default: "" },
    avatar: String,
    online: { type: Boolean, default: false },
    theme: { type: String, enum: ['light', 'dark', 'auto'], default: 'auto' }
});

// Encrypt fields before saving
userSchema.pre('save', function (next) {
    if (this.isModified('email') && this.email) {
        this.email = encrypt(this.email);
    }
    if (this.isModified('profession') && this.profession) {
        this.profession = encrypt(this.profession);
    }
    if (this.isModified('location') && this.location) {
        this.location = encrypt(this.location);
    }
    next();
});

// Decrypt before returning data
userSchema.methods.getDecrypted = function () {
    const obj = this.toObject();
    obj.email = this.email ? decrypt(this.email) : '';
    obj.profession = this.profession ? decrypt(this.profession) : '';
    obj.location = this.location ? decrypt(this.location) : '';
    return obj;
};

const User = mongoose.model("User", userSchema);
module.exports = User;