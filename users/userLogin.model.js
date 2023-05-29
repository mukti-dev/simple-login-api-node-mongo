const mongoose = require('mongoose');
const { Types: { ObjectId } } = require('mongoose')
const Schema = mongoose.Schema;

const schema = new Schema({
    user: { type: ObjectId, ref: 'User', required: true },
    ip: { type: String, required: true },
    createdDate: { type: Date, default: Date.now }
});

schema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('UserLogins', schema);