let isSocketInitialized = false;
let incomingCallData;
let peerConnection = null;
let remoteCandidatesQueue = [];
let didIOffer = false;
let localStream;
let remoteStream;
let currentEmail = '';
let currentFriend = '';
let socket;
const userName = "Pantsbro"+Math.floor(Math.random() * 100000)
const password = "x";
const userId = "YOUR_USER_ID";
let isInCall = false; 
const localVideoEl = document.querySelector('#local-video');
const remoteVideoEl = document.querySelector('#remote-video');

let servers = {
    iceServers: [
        {
            urls: [
                'stun:stun.l.google.com:19302',
                'stun:stun1.l.google.com:19302'
            ]
        },
        {
            urls: 'turn:relay1.expressturn.com:3478',
            username: 'efJ3O8UT1NCM9BH5NE', 
            credential: '7txHlplcvesmzjo8' 
        }
    ]
}




















function initializeSocket() {
    
    socket = io.connect('https://r3dxx-9ce6f110c87b.herokuapp.com', {
        auth: {
            userName: userName, // Use email as userName or keep them separate if needed
            password: password,
            userEmail: currentEmail  // Include userEmail in the auth object
        }
    });

    socket.on('disconnect', (reason) => {
        console.error(`Socket disconnected, reason: ${reason}`);
    });

    socket.on('connect_error', (error) => {
        console.error('Connection Error:', error);
    });





    var answer1 = document.getElementById("answer");

socket.on('availableOffers', offers => {
    console.log(offers);
    createOfferEls(offers);
});
socket.on('message1', (messageData) => {
    appendMessageToChat(messageData);
});
// Someone just made a new offer and we're already here - call createOfferEls
socket.on('newOfferAwaiting', offers => {
    createOfferEls(offers);
});

socket.on('answerResponse', offerObj => {
    console.log(offerObj);
    addAnswer(offerObj);
});

socket.on('receivedIceCandidateFromServer', iceCandidate => {
    addNewIceCandidate(iceCandidate);
    console.log(iceCandidate);
});

function createOfferEls(offers) {
    const offersContainer = document.getElementById("answer"); // Assuming there's a container for offers
    offersContainer.innerHTML = ''; // Clear previous offers

    offers.forEach(o => {
        const offerEl = document.createElement('div'); // Create a new div for each offer
        offerEl.classList.add('offer'); // Add a class for styling

        // Create the accept button
        const newOfferEl = document.createElement('button');
        newOfferEl.textContent = 'Accept Call';
        newOfferEl.id = 'acceptCallButton'; // Optionally assign an ID if needed

        newOfferEl.addEventListener('click', () => {
            answerOffer(o);
            answer1.style.display = "none"; // Hide the answer element
            offerEl.remove(); // Remove this offer element from the DOM
        });

        // Append the button to the offer element and then to the container
        offerEl.appendChild(newOfferEl);
        offersContainer.appendChild(offerEl);
    });

    answer1.style.display = "block"; // Make sure to show the answer element
}

}
   

    

    
        
   
    
    
   
        


const jwtToken = '239479281asdkjf';
const apiEndpoints = {
    getFriends: 'https://r3dxx-9ce6f110c87b.herokuapp.com/get-friends',
    addFriend: 'https://r3dxx-9ce6f110c87b.herokuapp.com/add-friend',
    sendMessage: 'https://r3dxx-9ce6f110c87b.herokuapp.com/send-message',
    getMessages: 'https://r3dxx-9ce6f110c87b.herokuapp.com/get-messages'
};



    
    
    function displayMessage({ sender, message }) {
    const messagesContainer = document.getElementById('messagesContainer');
    
    // Create a message wrapper
    const messageElement = document.createElement('div');
    messageElement.classList.add('message');
    
    // Create the sender element
    const senderElement = document.createElement('span');
    senderElement.classList.add('sender');
    senderElement.textContent = sender;
    
    // Create the message content element
    const contentElement = document.createElement('span');
    contentElement.classList.add('content');
    contentElement.textContent = message;
    
    // Append sender and content to the message element
    messageElement.appendChild(senderElement);
    messageElement.appendChild(contentElement);
    
    // Append the message element to the container
    messagesContainer.appendChild(messageElement);
    
    // Scroll to the bottom of the chat
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
    

document.addEventListener('DOMContentLoaded', function() {
  
 
    
   
   
   
    // Replace with valid token
  
   
 

 
 

   
  

document.getElementById('sendMessageButton').addEventListener('click', async function() {
const messageInput = document.getElementById('messageInput').value;

if (!currentFriend || !messageInput) {
   console.error('Both friend email and message are required');
   return;
}

try {
   const response = await fetch(apiEndpoints.sendMessage, {
       method: 'POST',
       headers: {
           'Content-Type': 'application/json',
           'Authorization': `Bearer ${jwtToken}`,
       },
       body: JSON.stringify({ recipient: currentFriend, message: messageInput })
   });

   if (!response.ok) {
       const errorText = await response.text();
       throw new Error(errorText || response.statusText);
   }

   const messageData = {
   sender: currentEmail, // Replace with the actual sender's email
   recipient: currentFriend,
   message: messageInput,
};

   // Clear input field after sending message
   document.getElementById('messageInput').value = '';
   socket.emit('message1',messageData )

   appendMessageToChat(messageData);
   // Reload chat window after sending message
   

} catch (error) {
   console.error('Failed to send message:', error);
}


});

});
function appendMessageToChat(messageData) {
    const messagesContainer = document.getElementById('messagesContainer');
    const messageEl = document.createElement('div');
    messageEl.classList.add("message")
    messageEl.textContent = `${messageData.sender}: ${messageData.message}`;
    messagesContainer.appendChild(messageEl);
}

// Listen for incoming messages via socket



function openMessageModal(friend) {
    // Close the current chat if it's open
    if (currentFriend) {
        document.getElementById('messagesContainer').innerHTML = ''; // Clear existing messages
        document.getElementById('messageModal').style.display = 'none'; // Close the modal
        
    }

    fetch('/api/user/email', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${jwtToken}` // Include your token if you're using JWT or similar
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log('User Email:', data.email);
        currentEmail = data.email;
        if (!isSocketInitialized) {
            initializeSocket();  // Initialize the socket if not done already
            isSocketInitialized = true; // Mark socket as initialized
        }
        // Ensure currentFriend is an array
        const friendEmails = [friend.email]; // Wrap in an array if single
        socket.emit('registerUser', currentEmail, userName, friendEmails);
        document.getElementById("hey1").style.display = 'none';
    })
    .catch(error => {
        console.error('Error fetching email:', error);
    });
    
    currentFriend = friend.email; // Set currentFriend to email
    console.log('Current friend selected:', currentFriend);

    // Initialize the socket connection now that currentFriend is set
   

    document.getElementById('modalFriendName').textContent = `Chat with ${friend.name}`;
    document.getElementById('messageModal').style.display = 'block'; // Open new chat
    loadMessages(friend.email); // Load messages for this friend
    


}


// Accept call button

// Handle incoming video answers

const call = async e=>{
    
    await fetchUserMedia();

    //peerConnection is all set with our STUN servers sent over
    await createPeerConnection();

    //create offer time!
    try{
        console.log("Creating offer...")
        const offer = await peerConnection.createOffer();
        console.log(offer);
        peerConnection.setLocalDescription(offer);
        didIOffer = true;
        socket.emit('newOffer',offer); //send offer to signalingServer
    }catch(err){
        console.log(err)
    }

}

const answerOffer = async(offerObj)=>{
    await fetchUserMedia()
    await createPeerConnection(offerObj);
    const answer = await peerConnection.createAnswer({}); //just to make the docs happy
    await peerConnection.setLocalDescription(answer); //this is CLIENT2, and CLIENT2 uses the answer as the localDesc
    console.log(offerObj)
    console.log(answer)
    // console.log(peerConnection.signalingState) //should be have-local-pranswer because CLIENT2 has set its local desc to it's answer (but it won't be)
    //add the answer to the offerObj so the server knows which offer this is related to
    offerObj.answer = answer 
    //emit the answer to the signaling server, so it can emit to CLIENT1
    //expect a response from the server with the already existing ICE candidates
    const offerIceCandidates = await socket.emitWithAck('newAnswer',offerObj)
    offerIceCandidates.forEach(c=>{
        peerConnection.addIceCandidate(c);
        console.log("======Added Ice Candidate======")
    })
    console.log(offerIceCandidates)
}

const addAnswer = async(offerObj)=>{
    //addAnswer is called in socketListeners when an answerResponse is emitted.
    //at this point, the offer and answer have been exchanged!
    //now CLIENT1 needs to set the remote
    await peerConnection.setRemoteDescription(offerObj.answer)
    // console.log(peerConnection.signalingState)
}

const fetchUserMedia = ()=>{
    return new Promise(async(resolve, reject)=>{
        try{
            const stream = await navigator.mediaDevices.getUserMedia({
                video: true,
                audio: true
            });
            localVideoEl.srcObject = stream;
            localStream = stream;    
            resolve();    
        }catch(err){
            console.log(err);
            reject()
        }
    })
}

const createPeerConnection = (offerObj)=>{
    return new Promise(async(resolve, reject)=>{
        //RTCPeerConnection is the thing that creates the connection
        //we can pass a config object, and that config object can contain stun servers
        //which will fetch us ICE candidates
        peerConnection = await new RTCPeerConnection(servers)
        remoteStream = new MediaStream()
        remoteVideoEl.srcObject = remoteStream;


        localStream.getTracks().forEach(track=>{
            //add localtracks so that they can be sent once the connection is established
            peerConnection.addTrack(track,localStream);
        })

        peerConnection.addEventListener("signalingstatechange", (event) => {
            console.log(event);
            console.log(peerConnection.signalingState)
        });

        peerConnection.addEventListener('icecandidate',e=>{
            console.log('........Ice candidate found!......')
            console.log(e)
            if(e.candidate){
                socket.emit('sendIceCandidateToSignalingServer',{
                    iceCandidate: e.candidate,
                    iceUserName: currentEmail,
                    didIOffer,
                })    
            }
        })
        
        peerConnection.addEventListener('track',e=>{
            console.log("Got a track from the other peer!! How excting")
            console.log(e)
            e.streams[0].getTracks().forEach(track=>{
                remoteStream.addTrack(track,remoteStream);
                console.log("Here's an exciting moment... fingers cross")
            })
        })

        if(offerObj){
            //this won't be set when called from call();
            //will be set when we call from answerOffer()
            // console.log(peerConnection.signalingState) //should be stable because no setDesc has been run yet
            await peerConnection.setRemoteDescription(offerObj.offer)
            // console.log(peerConnection.signalingState) //should be have-remote-offer, because client2 has setRemoteDesc on the offer
        }
        resolve();
    })
}

const addNewIceCandidate = iceCandidate=>{
    peerConnection.addIceCandidate(iceCandidate)
    console.log("======Added Ice Candidate======")
}
async function fetchData(url, options = {}) {
    try {
        const response = await fetch(url, options);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json(); // Assuming the server sends JSON response
    } catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
}

document.querySelector('#callButton').addEventListener('click',call)
   async function loadMessages(friendName) {
       try {
           const messages = await fetchData(`${apiEndpoints.getMessages}?friend=${friendName}`, {
               headers: {
                   'Authorization': `Bearer ${jwtToken}`,
               },
           });
           messages.forEach(displayMessage); // Display all loaded messages
       } catch (error) {
           console.error('Failed to load messages:', error);
       }
   }

   async function loadFriends() {
    try {
        const friendsList = await fetchData(apiEndpoints.getFriends, {
            headers: {
                'Authorization': `Bearer ${jwtToken}`, // Ensure your token is valid
            },
        });
        console.log('Fetched friends:', friendsList); // Log the response
        renderFriends(friendsList); // Render the friends list
    } catch (error) {
        console.error('Error loading friends:', error); // Log errors
        displayError('Failed to load friends.');
    }
}
   
   

   document.getElementById('addFriendForm').addEventListener('submit', async (event) => {
event.preventDefault(); // Prevent default form submission

const friendEmail = document.getElementById('friendEmail').value; // Get the email input
const responseMessage = document.getElementById('responseMessage'); // Message container

try {
   const response = await fetch(apiEndpoints.addFriend, {
       method: 'POST',
       headers: {
           'Content-Type': 'application/json',
           'Authorization': `Bearer ${jwtToken}`,
       },
       body: JSON.stringify({ friendEmail }) // Send only the email
   });

   // Log the response for debugging
   console.log('Response:', response);

   // Check if the response is in JSON format
   let responseData;
   if (response.headers.get('content-type')?.includes('application/json')) {
       responseData = await response.json(); // Only parse JSON if content type is correct
   } else {
       const text = await response.text(); // Get the response as plain text
       responseMessage.textContent = text; // Directly display text response
       responseMessage.style.color = 'red'; // Set color to red for error messages
       return; // Exit early to avoid further processing
   }

   // Check for a successful response
   if (response.ok) {
       responseMessage.textContent = 'Friend request sent successfully!';
       responseMessage.style.color = 'green';
       renderNewFriend(friendEmail); // Update the UI to show the new friend
   } else {
       // If not ok, throw an error with the message from response data
       throw new Error(responseData.message || 'Error adding friend.'); 
   }

} catch (error) {
   console.error('Error:', error); // Log the error for debugging
   responseMessage.textContent = 'Error adding friend: ' + error.message; // Display error message
   responseMessage.style.color = 'red';
}
});



document.getElementById('Login122').addEventListener('click', function() {
fetch('/logout', {
   method: 'POST',
   credentials: 'same-origin',
   headers: {
       'Content-Type': 'application/json'
   }
})
.then(response => {
   if (response.ok) {
       window.location.href = '/login'; // Redirect to login page after successful sign-out
   } else {
       alert('Failed to sign out');
   }
})
.catch(error => {
   console.error('Error:', error);
});
});




   function renderFriends(friends) {
const friendsContainer = document.getElementById('FriendsList');
friendsContainer.innerHTML = ''; // Clear the container

friends.forEach(friend => {
    const friendElement = document.createElement('div');
    friendElement.classList.add("frnd");
    friendElement.textContent = friend.name; // Assuming friend has a 'name' property
    friendElement.addEventListener('click', () => openMessageModal(friend)); // Pass the entire friend object
    
    // Adding styles directly
    friendElement.style.cursor = 'pointer'; // Change cursor to pointer on hover
    friendElement.style.padding = '10px'; // Add padding
    friendElement.style.margin = '5px'; // Add margin between friends
    friendElement.style.border = '1px solid black'; // Add a border
    friendElement.style.borderRadius = '5px'; // Round the corners
    friendElement.style.backgroundColor = '#222222'; // Background color
    friendElement.style.transition = 'background-color 0.3s'; // Transition effect on hover

    // Add hover effect using event listeners
    friendElement.addEventListener('mouseenter', () => {
        friendElement.style.backgroundColor = '#e0e0e0'; // Darker background on hover
    });
    friendElement.addEventListener('mouseleave', () => {
        friendElement.style.backgroundColor = '#222222'; // Original background
    });

    friendsContainer.appendChild(friendElement);
});
}

function renderNewFriend(friendName) {
    const friendsContainer = document.getElementById('FriendsList');
    const friendElement = document.createElement('div');
    friendElement.classList.add("frnd");
    friendElement.textContent = friendName;
    friendElement.addEventListener('click', () => openMessageModal(friendName));
    
    // Adding styles directly
    friendElement.style.cursor = 'pointer'; // Change cursor to pointer on hover
    friendElement.style.padding = '10px'; // Add padding
    friendElement.style.margin = '5px'; // Add margin between friends
    friendElement.style.border = '1px solid #ccc'; // Add a border
    friendElement.style.borderRadius = '5px'; // Round the corners
    friendElement.style.backgroundColor = '#222222'; // Background color
    friendElement.style.transition = 'background-color 0.3s'; // Transition effect on hover

    // Add hover effect using event listeners
    friendElement.addEventListener('mouseenter', () => {
        friendElement.style.backgroundColor = '#222222'; // Darker background on hover
    });
    friendElement.addEventListener('mouseleave', () => {
        friendElement.style.backgroundColor = '#222222'; // Original background
    });

    friendsContainer.appendChild(friendElement);
}

   function displayError(message) {
       const errorContainer = document.getElementById('responseMessage');
       errorContainer.textContent = message;
       errorContainer.style.color = 'red';
   }

   loadFriends();

const cntr7 = document.querySelector(".container7")
const addfriendbtn = document.getElementById("Login1223");
const msg = document.getElementById("messageModal");
addfriendbtn.addEventListener('click', () => { 
   msg.style.display = "none";
   cntr7.style.display = "block";

});

