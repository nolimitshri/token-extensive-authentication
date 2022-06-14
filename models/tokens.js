const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true
  },
  userId: {
    type: String,
    requried: true
  },
  uniqueToken: {
    type: String,
    required: true
  },
  expiresAt: {
    type: Date
  }
});

const Token = mongoose.model('Token', tokenSchema);

module.exports = Token;
