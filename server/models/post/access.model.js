const autopopulate = require("mongoose-autopopulate");

const mongoose = require('mongoose'),
    Schema = mongoose.Schema,
    Types = mongoose.Types;

const schema = new Schema({
    relations: [{
        type: Types.ObjectId,
        required: true
    }],
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

schema.virtual('isConfirmed').get(function() {
    return this.privacy.some(x => x === 'confirm');
});

schema.virtual('isPin').get(function() {
    return this.privacy.some(x => x === 'pin');
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



schema.virtual('canBanCreate').get(function() {
    return this.privacy.some(x => x === 'create-ban');
});

schema.virtual('canBanEdit').get(function() {
    return this.privacy.some(x => x === 'edit-ban');
});

schema.virtual('canBanVerify').get(function() {
    return this.privacy.some(x => x === 'verify-ban');
});

schema.virtual('canBanGet').get(function() {
    return this.privacy.some(x => x === 'get-ban');
});

schema.virtual('canBanRemove').get(function() {
    return this.privacy.some(x => x === 'remove-ban');
});

schema.virtual('canBanPermote').get(function() {
    return this.privacy.some(x => x === 'permote-ban');
});




schema.virtual('canCreateEmail').get(function() {
    return this.privacy.some(x => x === 'create-email');
});

schema.virtual('canEditEmail').get(function() {
    return this.privacy.some(x => x === 'edit-email');
});

schema.virtual('canVerifyEmail').get(function() {
    return this.privacy.some(x => x === 'verify-email');
});

schema.virtual('canGetEmail').get(function() {
    return this.privacy.some(x => x === 'get-email');
});

schema.virtual('canRemoveEmail').get(function() {
    return this.privacy.some(x => x === 'remove-email');
});

schema.virtual('canPermoteEmail').get(function() {
    return this.privacy.some(x => x === 'permote-email');
});


schema.virtual('canCreateMobile').get(function() {
    return this.privacy.some(x => x === 'create-mobile');
});

schema.virtual('canEditMobile').get(function() {
    return this.privacy.some(x => x === 'edit-mobile');
});

schema.virtual('canVerifyMobile').get(function() {
    return this.privacy.some(x => x === 'verify-mobile');
});

schema.virtual('canGetMobile').get(function() {
    return this.privacy.some(x => x === 'get-mobile');
});

schema.virtual('canRemoveMobile').get(function() {
    return this.privacy.some(x => x === 'remove-mobile');
});

schema.virtual('canPermoteMobile').get(function() {
    return this.privacy.some(x => x === 'permote-mobile');
});


schema.virtual('canCreatePassword').get(function() {
    return this.privacy.some(x => x === 'create-password');
});

schema.virtual('canEditPassword').get(function() {
    return this.privacy.some(x => x === 'edit-password');
});

schema.virtual('canVerifyPassword').get(function() {
    return this.privacy.some(x => x === 'verify-password');
});

schema.virtual('canGetPassword').get(function() {
    return this.privacy.some(x => x === 'get-password');
});

schema.virtual('canRemovePassword').get(function() {
    return this.privacy.some(x => x === 'remove-password');
});

schema.virtual('canPermotePassword').get(function() {
    return this.privacy.some(x => x === 'permote-password');
});




schema.virtual('canCreateAlias').get(function() {
    return this.privacy.some(x => x === 'create-alias');
});

schema.virtual('canEditAlias').get(function() {
    return this.privacy.some(x => x === 'edit-alias');
});

schema.virtual('canVerifyAlias').get(function() {
    return this.privacy.some(x => x === 'verify-alias');
});

schema.virtual('canGetAlias').get(function() {
    return this.privacy.some(x => x === 'get-alias');
});

schema.virtual('canRemoveAlias').get(function() {
    return this.privacy.some(x => x === 'remove-alias');
});

schema.virtual('canPermoteAlias').get(function() {
    return this.privacy.some(x => x === 'permote-alias');
});

schema.virtual('canGetTokenAlias').get(function() {
    return this.privacy.some(x => x === 'get-token-alias');
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

module.exports = mongoose.model('Access', schema);