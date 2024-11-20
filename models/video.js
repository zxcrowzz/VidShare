const mongoose = require('mongoose');

const videoSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User', // Assuming you have a User model
    
  },
  title: {
    type: String,
    required: true,
  },
  videoUrl: {
    type: String,
    required: true, // Make sure videoUrl is required
  },
});

module.exports = mongoose.model('Video', videoSchema);
