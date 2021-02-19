const autopopulate = require("mongoose-autopopulate");

const mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    Types = mongoose.Types;

const schema = new Schema({
    location: {
        type: [Number, Number],
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

schema.virtual('isPublic').get(function() {
    return !this.privacy.some(x => x === 'private');
});

schema.virtual('isPrivate').get(function() {
    return this.privacy.some(x => x === 'private');
});

schema.virtual('isConfirmed').get(function() {
    return true;
});

schema.virtual('isPin').get(function() {
    return this.privacy.some(x => x === 'pin');
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

module.exports = mongoose.model('Post', schema);