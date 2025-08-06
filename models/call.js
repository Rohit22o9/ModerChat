const mongoose = require('mongoose');

const callSchema = new mongoose.Schema({
    caller: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    receiver: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: false 
    },
    groupId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Group',
        required: false
    },
    participants: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    type: { 
        type: String, 
        enum: ['audio', 'video'], 
        required: true 
    },
    status: { 
        type: String, 
        enum: ['ringing', 'accepted', 'declined', 'missed', 'ended', 'cancelled'], 
        default: 'ringing' 
    },
    startTime: { 
        type: Date, 
        default: Date.now 
    },
    endTime: Date,
    duration: Number, // in seconds
    created_at: { 
        type: Date, 
        default: Date.now 
    }
}, {
    timestamps: true
});

// Calculate duration before saving
callSchema.pre('save', function(next) {
    if (this.endTime && this.startTime && this.status === 'ended') {
        this.duration = Math.floor((this.endTime - this.startTime) / 1000);
    }
    next();
});

// Virtual field for formatted duration
callSchema.virtual('formattedDuration').get(function() {
    if (!this.duration) return '0:00';
    const minutes = Math.floor(this.duration / 60);
    const seconds = this.duration % 60;
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
});

// Instance method to check if call is active
callSchema.methods.isActive = function() {
    return ['ringing', 'accepted'].includes(this.status);
};

// Instance method to check if call was successful
callSchema.methods.wasSuccessful = function() {
    return ['accepted', 'ended'].includes(this.status) && this.duration > 0;
};

// Static method to get call history for a user
callSchema.statics.getHistoryForUser = function(userId, limit = 50) {
    return this.find({
        $or: [
            { caller: userId },
            { receiver: userId }
        ]
    })
    .populate('caller receiver', 'username avatar online')
    .sort({ created_at: -1 })
    .limit(limit);
};

// Static method to get active calls for a user
callSchema.statics.getActiveCallsForUser = function(userId) {
    return this.find({
        $or: [
            { caller: userId },
            { receiver: userId }
        ],
        status: { $in: ['ringing', 'accepted'] }
    })
    .populate('caller receiver', 'username avatar');
};

// Index for performance
callSchema.index({ caller: 1, created_at: -1 });
callSchema.index({ receiver: 1, created_at: -1 });
callSchema.index({ status: 1, created_at: -1 });

module.exports = mongoose.model('Call', callSchema);