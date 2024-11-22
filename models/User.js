const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profileImageUrl: { type: String }, // URL or filename of profile image
  isVerified: { type: Boolean, default: false },
});

module.exports = mongoose.model('User', userSchema);
