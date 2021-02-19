const autopopulate = require("mongoose-autopopulate");

const mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    Types = mongoose.Types;

const schema = new Schema({
    verifyToken: {
        token: String,
        expires: Date
    },
    verifiedDate: Date,
    privacy: [{
        type: String,
        required: true
    }],
    performances: [{
        type: String,
        required: true
    }],
    acceptTerms: [{
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

schema.virtual('isVerified').get(function() {
    return !!(this.verified || this.passwordReset);
});

schema.virtual('isPrivate').get(function() {
    return this.privacy.some(x => x === 'private');
});

schema.virtual('isPublic').get(function() {
    return !this.privacy.some(x => x === 'private');
});

schema.virtual('isConfirmed').get(function() {
    return this.privacy.some(x => x === 'confirmed');
});

schema.virtual('isVerified').get(function() {
    return this.privacy.some(x => x === 'verified');
});

schema.virtual('role').get(function() {
    return this.privacy.some(x => x === 'admin') ? 'admin' : 'user';
});



schema.virtual('canCreate').get(function() {
    return this.privacy.some(x => x === 'create');
});

schema.virtual('canEdit').get(function() {
    return this.privacy.some(x => x === 'edit');
});

schema.virtual('canVerify').get(function() {
    return this.privacy.some(x => x === 'verify');
});

schema.virtual('canGet').get(function() {
    return this.privacy.some(x => x === 'get');
});

schema.virtual('canRemove').get(function() {
    return this.privacy.some(x => x === 'remove');
});

schema.virtual('canPermote').get(function() {
    return this.privacy.some(x => x === 'permote');
});

schema.virtual('canGetToken').get(function() {
    return this.privacy.some(x => x === 'get-token');
});



schema.virtual('canCreateAsRoot').get(function() {
    return this.privacy.some(x => x === 'create-as-root');
});

schema.virtual('canEditAsRoot').get(function() {
    return this.privacy.some(x => x === 'edit-as-root');
});

schema.virtual('canVerifyAsRoot').get(function() {
    return this.privacy.some(x => x === 'verify-as-root');
});

schema.virtual('canGetAsRoot').get(function() {
    return this.privacy.some(x => x === 'get-as-root');
});

schema.virtual('canRemoveAsRoot').get(function() {
    return this.privacy.some(x => x === 'remove-as-root');
});

schema.virtual('canPermoteAsRoot').get(function() {
    return this.privacy.some(x => x === 'permote-as-root');
});

schema.virtual('canGetTokenAsRoot').get(function() {
    return this.privacy.some(x => x === 'get-token-as-root');
});




schema.virtual('canPublicCreate').get(function() {
    return this.privacy.some(x => x === 'public-create');
});

schema.virtual('canPublicEdit').get(function() {
    return this.privacy.some(x => x === 'public-edit');
});

schema.virtual('canPublicVerify').get(function() {
    return this.privacy.some(x => x === 'public-verify');
});

schema.virtual('canPublicGet').get(function() {
    return this.privacy.some(x => x === 'public-get');
});

schema.virtual('canPublicRemove').get(function() {
    return this.privacy.some(x => x === 'public-remove');
});

schema.virtual('canPublicPermote').get(function() {
    return this.privacy.some(x => x === 'public-permote');
});

schema.virtual('canPublicGetToken').get(function() {
    return this.privacy.some(x => x === 'public-get-token');
});

schema.virtual('email', {
    ref: 'Email',
    foreignField: 'uid',
    localField: '_id',
    justOne: true,
    autopopulate: true,
    options: {
        verifiedDate: { $ne: undefined },
        sort: { updatedAt: -1 },
        limit: 1
    }
});

schema.virtual('mobile', {
    ref: 'Mobile',
    foreignField: 'uid',
    localField: '_id',
    justOne: true,
    autopopulate: true,
    options: {
        verifiedDate: { $ne: undefined },
        sort: { updatedAt: -1 },
        limit: 1
    }
});

schema.virtual('emails', {
    ref: 'Email',
    foreignField: 'uid',
    localField: '_id',
    justOne: false,
    autopopulate: true,
    options: {
        verifiedDate: { $ne: undefined },
        sort: { updatedAt: -1 },
        limit: 1
    }
});

schema.virtual('mobiles', {
    ref: 'Mobile',
    foreignField: 'uid',
    localField: '_id',
    justOne: false,
    autopopulate: true,
    options: {
        verifiedDate: { $ne: undefined },
        sort: { updatedAt: -1 },
        limit: 1
    }
});

schema.virtual('token', {
    ref: 'RefreshToken',
    foreignField: 'uid',
    localField: '_id',
    justOne: true,
    autopopulate: true,
    options: {
        verifiedDate: { $ne: undefined },
        sort: { updatedAt: -1 },
        limit: 1
    }
});

schema.virtual('tokens', {
    ref: 'RefreshToken',
    foreignField: 'uid',
    localField: '_id',
    justOne: false,
    autopopulate: true,
    options: {
        verifiedDate: { $ne: undefined },
        sort: { updatedAt: -1 },
        limit: 1
    }
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

module.exports = mongoose.model('User', schema);