const autopopulate = require("mongoose-autopopulate");

const mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    Types = mongoose.Types;

const schema = new Schema({
    token: {
        type: String,
        required: true
    },
    uid: {
        type: Types.ObjectId,
        required: true
    },
    expiresDate: Date,
    createdByIp: String,
    revoked: Date,
    revokedByIp: String,
    replacedByToken: String,
    privacy: [{
        type: String,
        required: true
    }],
    updatedAt: {
        type: Date,
        default: Date.now()
    },
    createdAt: {
        type: Date,
        default: Date.now()
    }
});

schema.virtual('isExpired').get(function() {
    return new Date(Date.now()) >= this.expiresDate;
});

schema.virtual('isActive').get(function() {
    return !this.revoked && !this.isExpired;
});

schema.set('toJSON', {
    virtuals: true,
    versionKey: false,
    transform: function(doc, ret) {}
});

schema.plugin(autopopulate);

module.exports = mongoose.model('RefreshToken', schema);