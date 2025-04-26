const mongoose = require('mongoose');

// Check if the model already exists to prevent OverwriteModelError
const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    profilePhoto: { type: String, default: '/images/profile.png' },
    coverPhoto: { type: String, default: '/images/cover_image.png' }
}));

module.exports = User;