
// Group Call Management
class GroupCallManager {
    constructor() {
        this.socket = io();
        this.localStream = null;
        this.peerConnections = new Map();
        this.currentCall = null;
        this.isInGroupCall = false;
        
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        // Listen for incoming group calls
        this.socket.on('incoming-group-call', (data) => {
            this.showIncomingGroupCallNotification(data);
        });

        // Listen for group call events
        this.socket.on('group-call-joined', (data) => {
            if (this.isInGroupCall) {
                this.handleUserJoined(data);
            }
        });

        this.socket.on('group-call-left', (data) => {
            if (this.isInGroupCall) {
                this.handleUserLeft(data);
            }
        });

        this.socket.on('group-call-ended', (data) => {
            this.endGroupCall();
        });

        this.socket.on('group-call-timeout', (data) => {
            this.hideCallNotification();
        });

        // WebRTC signaling for group calls
        this.socket.on('group-call-offer', (data) => {
            this.handleGroupCallOffer(data);
        });

        this.socket.on('group-call-answer', (data) => {
            this.handleGroupCallAnswer(data);
        });

        this.socket.on('group-ice-candidate', (data) => {
            this.handleGroupIceCandidate(data);
        });
    }

    async initiateGroupCall(groupId, type) {
        try {
            const response = await fetch('/call/initiate/group', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ groupId, type })
            });

            const result = await response.json();
            if (result.success) {
                this.currentCall = {
                    callId: result.callId,
                    groupId: groupId,
                    type: type
                };
                
                // Get user media
                await this.getUserMedia(type);
                this.showGroupCallInterface();
                this.isInGroupCall = true;
            } else {
                alert(result.error);
            }
        } catch (error) {
            console.error('Error initiating group call:', error);
            alert('Failed to start group call');
        }
    }

    showIncomingGroupCallNotification(data) {
        const notification = document.createElement('div');
        notification.id = 'group-call-notification';
        notification.className = 'fixed top-4 left-1/2 transform -translate-x-1/2 bg-white p-6 rounded-lg shadow-xl border z-50 max-w-md';
        
        notification.innerHTML = `
            <div class="text-center">
                <div class="mb-4">
                    <img src="${data.caller.avatar || '/icons/user-default.png'}" alt="${data.caller.username}" class="w-16 h-16 rounded-full mx-auto mb-2">
                    <h3 class="text-lg font-semibold">${data.caller.username}</h3>
                    <p class="text-gray-600">is calling in ${data.groupName}</p>
                    <p class="text-sm text-gray-500">${data.type.charAt(0).toUpperCase() + data.type.slice(1)} Call</p>
                </div>
                <div class="flex justify-center space-x-4">
                    <button onclick="groupCallManager.acceptGroupCall('${data.callId}', '${data.groupId}', '${data.type}')" 
                            class="bg-green-500 text-white px-6 py-2 rounded-lg hover:bg-green-600">
                        Accept
                    </button>
                    <button onclick="groupCallManager.declineGroupCall('${data.callId}')" 
                            class="bg-red-500 text-white px-6 py-2 rounded-lg hover:bg-red-600">
                        Decline
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(notification);
    }

    async acceptGroupCall(callId, groupId, type) {
        try {
            const response = await fetch(`/call/${callId}/respond`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action: 'accept' })
            });

            if (response.ok) {
                this.currentCall = { callId, groupId, type };
                await this.getUserMedia(type);
                this.showGroupCallInterface();
                this.isInGroupCall = true;
                this.hideCallNotification();
            }
        } catch (error) {
            console.error('Error accepting group call:', error);
        }
    }

    async declineGroupCall(callId) {
        try {
            await fetch(`/call/${callId}/respond`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ action: 'decline' })
            });
            this.hideCallNotification();
        } catch (error) {
            console.error('Error declining group call:', error);
        }
    }

    hideCallNotification() {
        const notification = document.getElementById('group-call-notification');
        if (notification) {
            notification.remove();
        }
    }

    async getUserMedia(type) {
        const constraints = {
            audio: true,
            video: type === 'video'
        };

        try {
            this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
            return this.localStream;
        } catch (error) {
            console.error('Error accessing media devices:', error);
            throw error;
        }
    }

    showGroupCallInterface() {
        const callInterface = document.createElement('div');
        callInterface.id = 'group-call-interface';
        callInterface.className = 'fixed inset-0 bg-gray-900 z-50 flex flex-col';
        
        callInterface.innerHTML = `
            <div class="flex-1 flex flex-wrap justify-center items-center p-4 gap-4" id="video-container">
                <div class="relative">
                    <video id="local-video" autoplay muted class="w-64 h-48 bg-gray-800 rounded-lg"></video>
                    <div class="absolute bottom-2 left-2 bg-black bg-opacity-50 text-white px-2 py-1 rounded text-sm">You</div>
                </div>
            </div>
            <div class="bg-gray-800 p-4 flex justify-center space-x-4">
                <button id="toggle-audio" class="bg-gray-600 text-white p-3 rounded-full hover:bg-gray-700">
                    <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M9 4a1 1 0 011 1v6a1 1 0 01-1 1h-6a1 1 0 01-1-1V5a1 1 0 011-1h6z" clip-rule="evenodd"></path>
                    </svg>
                </button>
                <button id="toggle-video" class="bg-gray-600 text-white p-3 rounded-full hover:bg-gray-700">
                    <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4 4a2 2 0 00-2 2v8a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2H4z" clip-rule="evenodd"></path>
                    </svg>
                </button>
                <button id="end-group-call" onclick="groupCallManager.endGroupCall()" 
                        class="bg-red-500 text-white p-3 rounded-full hover:bg-red-600">
                    <svg class="w-6 h-6" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M18 10c0 3.866-3.582 7-8 7s-8-3.134-8-7 3.582-7 8-7 8 3.134 8 7zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>
                    </svg>
                </button>
            </div>
        `;
        
        document.body.appendChild(callInterface);

        // Set local video stream
        if (this.localStream) {
            const localVideo = document.getElementById('local-video');
            localVideo.srcObject = this.localStream;
        }

        // Add event listeners for controls
        document.getElementById('toggle-audio').addEventListener('click', () => {
            this.toggleAudio();
        });

        document.getElementById('toggle-video').addEventListener('click', () => {
            this.toggleVideo();
        });
    }

    toggleAudio() {
        if (this.localStream) {
            const audioTrack = this.localStream.getAudioTracks()[0];
            if (audioTrack) {
                audioTrack.enabled = !audioTrack.enabled;
                const button = document.getElementById('toggle-audio');
                button.classList.toggle('bg-red-500', !audioTrack.enabled);
            }
        }
    }

    toggleVideo() {
        if (this.localStream) {
            const videoTrack = this.localStream.getVideoTracks()[0];
            if (videoTrack) {
                videoTrack.enabled = !videoTrack.enabled;
                const button = document.getElementById('toggle-video');
                button.classList.toggle('bg-red-500', !videoTrack.enabled);
            }
        }
    }

    async endGroupCall() {
        if (this.currentCall) {
            try {
                await fetch(`/call/${this.currentCall.callId}/end`, {
                    method: 'POST'
                });
            } catch (error) {
                console.error('Error ending group call:', error);
            }
        }

        // Clean up
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
        }

        this.peerConnections.forEach(pc => pc.close());
        this.peerConnections.clear();

        const callInterface = document.getElementById('group-call-interface');
        if (callInterface) {
            callInterface.remove();
        }

        this.currentCall = null;
        this.isInGroupCall = false;
    }

    handleUserJoined(data) {
        // Add new user video element
        const videoContainer = document.getElementById('video-container');
        const userVideo = document.createElement('div');
        userVideo.className = 'relative';
        userVideo.id = `user-${data.user.id}`;
        
        userVideo.innerHTML = `
            <video autoplay class="w-64 h-48 bg-gray-800 rounded-lg"></video>
            <div class="absolute bottom-2 left-2 bg-black bg-opacity-50 text-white px-2 py-1 rounded text-sm">${data.user.username}</div>
        `;
        
        videoContainer.appendChild(userVideo);
    }

    handleUserLeft(data) {
        const userElement = document.getElementById(`user-${data.user.id}`);
        if (userElement) {
            userElement.remove();
        }

        const peerConnection = this.peerConnections.get(data.user.id);
        if (peerConnection) {
            peerConnection.close();
            this.peerConnections.delete(data.user.id);
        }
    }

    async handleGroupCallOffer(data) {
        // WebRTC offer handling for group calls
        console.log('Received group call offer:', data);
    }

    async handleGroupCallAnswer(data) {
        // WebRTC answer handling for group calls
        console.log('Received group call answer:', data);
    }

    async handleGroupIceCandidate(data) {
        // WebRTC ICE candidate handling for group calls
        console.log('Received group ICE candidate:', data);
    }
}

// Initialize group call manager
const groupCallManager = new GroupCallManager();

// Add group call buttons to group chat interface
document.addEventListener('DOMContentLoaded', function() {
    const groupChatContainer = document.querySelector('.group-chat-container');
    if (groupChatContainer) {
        const groupId = groupChatContainer.dataset.groupId;
        
        // Add call buttons to group header
        const callButtons = document.createElement('div');
        callButtons.className = 'flex space-x-2 ml-auto';
        callButtons.innerHTML = `
            <button onclick="groupCallManager.initiateGroupCall('${groupId}', 'audio')" 
                    class="bg-green-500 text-white p-2 rounded-full hover:bg-green-600" title="Audio Call">
                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M2 3a1 1 0 011-1h2.153a1 1 0 01.986.836l.74 4.435a1 1 0 01-.54 1.06l-1.548.773a11.037 11.037 0 006.105 6.105l.774-1.548a1 1 0 011.059-.54l4.435.74a1 1 0 01.836.986V17a1 1 0 01-1 1h-2C7.82 18 2 12.18 2 5V3z"></path>
                </svg>
            </button>
            <button onclick="groupCallManager.initiateGroupCall('${groupId}', 'video')" 
                    class="bg-blue-500 text-white p-2 rounded-full hover:bg-blue-600" title="Video Call">
                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M2 6a2 2 0 012-2h6a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6zM14.553 7.106A1 1 0 0014 8v4a1 1 0 00.553.894l2 1A1 1 0 0018 13V7a1 1 0 00-1.447-.894l-2 1z"></path>
                </svg>
            </button>
        `;
        
        const groupHeader = document.querySelector('.group-header');
        if (groupHeader) {
            groupHeader.appendChild(callButtons);
        }
    }
});
