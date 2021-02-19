const autopopulate = require("mongoose-autopopulate");

const mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    Types = mongoose.Types;

const schema = new Schema({
    value: {
        type: String,
        required: true
    },
    uid: {
        type: Types.ObjectId,
        required: true
    },
    actor: {
        type: Types.ObjectId,
        required: true
    },
    verifyToken: {
        token: String,
        expires: Date
    },
    verifiedDate: Date,
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

schema.virtual('isPrivate').get(function() {
    return this.privacy.some(x => x === 'private');
});

schema.virtual('isPublic').get(function() {
    return !this.privacy.some(x => x === 'private');
});

schema.virtual('isConfirmed').get(function() {
    return (this.verifiedDate !== undefined);
});

schema.virtual('isVerified').get(function() {
    return (this.verifiedDate !== undefined) && (this.verifiedDate !== null);
});

schema.virtual('isPrimary').get(function() {
    return this.privacy.some(x => x === 'primary');
});

schema.set('toJSON', {
    virtuals: true,
    versionKey: false,
    transform: function(doc, ret) {
        delete ret.verifiedDate;
        delete ret.verifyToken;
    }
});

schema.plugin(autopopulate);

module.exports = mongoose.model('Password', schema);