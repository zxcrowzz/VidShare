const mongoose = require('mongoose');

const pendingUserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true },
    password: { type: String, required: true },
    confirmationCode: { type: String, required: true, index: true }, // Confirmation code instead of token
    createdAt: { type: Date, default: Date.now, expires: 3600 } // Expires in 1 hour
});

// Optionally, you can explicitly create an index for confirmationCode:
pendingUserSchema.index({ confirmationCode: 1 }); // This creates an index on the confirmationCode field

module.exports = mongoose.model('PendingUser', pendingUserSchema);
