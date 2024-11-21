
const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  mediaUrl: { type: String }, // URL of the attached media
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model('Post', postSchema);

