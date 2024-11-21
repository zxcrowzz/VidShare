if (process.env.NODE_ENV !== "production") {
    require("dotenv").config();
}
let db;

const userFriends = {};
const users = {};
let friends = [];
let messages = {};
let peerConnection;
let name = "";
const cloudinary = require('cloudinary').v2;
const ffmpeg = require('fluent-ffmpeg');
const cors = require('cors');
const multer = require('multer');
const path = require("path");
const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const flash = require("express-flash");
const session = require("express-session");
const mongoose = require('mongoose');
const { body, validationResult } = require('express-validator');
const User = require('./models/User');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https')
const express = require('express');
const app = express();
const socketio = require('socket.io');
const rooms = {};
const router = express.Router();
const Video = require('./models/video'); // Import the Video model
const axios = require('axios');
app.use(express.static(__dirname))
const ObjectId = require('mongoose').Types.ObjectId;
const { v4: uuidV4 } = require('uuid');
//we need a key and cert to run https
//we generated them with mkcert
// $ mkcert create-ca
// $ mkcert create-cert

let connectedClients = 0;
//we changed our express setup so we can use https
//pass the key and cert to createServer on https
const mega = require('mega');
const expressServer = app.listen(process.env.PORT || 3000, () => {
    console.log(`Server running on port ${process.env.PORT || 3000}`);
});
// Create our socket.io server
const PendingUser = require('./models/PendingUser');
const { title } = require("process");
//create our socket.io server... it will listen to our express port
const io = socketio(expressServer,{
    cors: {
        origin: [
            "https://localhost",
             'https://r3dxx-9ce6f110c87b.herokuapp.com' //if using a phone or another computer
        ],
        methods: ["GET", "POST"]
    }
});



cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.API_KEY,
    api_secret: process.env.API_SECRET
  });
// Set up WebDAV client

const storage = multer.memoryStorage();

// Initialize Multer with memory storage
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const validTypes = ['image/jpeg', 'image/png', 'video/mp4'];
    if (validTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only .jpeg, .png, and .mp4 files are supported'), false);
    }
  },
});
//offers will contain {}
let offers = [

];
let connectedSockets = [
    
]
const connectedUsers = {};
io.on('connection',(socket)=>{
  
    console.log('Socket connected:', socket.id);
    console.log("hey buddy")
    connectedClients++;
    // console.log("Someone has connected");
    const userName = socket.handshake.auth.userName;
    const password = socket.handshake.auth.password;

    if(password !== "x"){
        socket.disconnect(true);
        return;
    }



  
    
  

    const userEmail = socket.handshake.auth.userEmail;
    console.log(userEmail)
    connectedSockets.push({
        socketId: socket.id,
        userEmail
    })

    //a new client has joined. If there are any offers available,
    //emit them out
    if(offers.length){
        socket.emit('availableOffers',offers);
    }
    socket.on('message1', (messageData) => {
        console.log('Message received:', messageData);
        // Broadcast the message to all connected clients
        socket.broadcast.emit('message1', messageData);
    });
    socket.on('newOffer',newOffer=>{
        offers.push({
            offererUserName: userEmail,
            offer: newOffer,
            offerIceCandidates: [],
            answererUserName: null,
            answer: null,
            answererIceCandidates: []
        })
        // console.log(newOffer.sdp.slice(50))
        //send out to all connected sockets EXCEPT the caller
        socket.broadcast.emit('newOfferAwaiting',offers.slice(-1))
    })

    socket.on('newAnswer',(offerObj,ackFunction)=>{
        console.log(offerObj);
        console.log(userEmail)
        //emit this answer (offerObj) back to CLIENT1
        //in order to do that, we need CLIENT1's socketid
        const socketToAnswer = connectedSockets.find(s=>s.userEmail === offerObj.offererUserName)
        if(!socketToAnswer){
            console.log("No matching socket")
            return;
        }
        //we found the matching socket, so we can emit to it!
        const socketIdToAnswer = socketToAnswer.socketId;
        //we find the offer to update so we can emit it
        const offerToUpdate = offers.find(o=>o.offererUserName === offerObj.offererUserName)
        if(!offerToUpdate){
            console.log("No OfferToUpdate")
            return;
        }
        //send back to the answerer all the iceCandidates we have already collected
        ackFunction(offerToUpdate.offerIceCandidates);
        offerToUpdate.answer = offerObj.answer
        offerToUpdate.answererUserName = userEmail
        //socket has a .to() which allows emiting to a "room"
        //every socket has it's own room
        socket.to(socketIdToAnswer).emit('answerResponse',offerToUpdate)
    })

    socket.on('sendIceCandidateToSignalingServer',iceCandidateObj=>{
        const { didIOffer, iceUserName, iceCandidate } = iceCandidateObj;
        // console.log(iceCandidate);
        if(didIOffer){
            //this ice is coming from the offerer. Send to the answerer
            const offerInOffers = offers.find(o=>o.offererUserName === iceUserName);
            if(offerInOffers){
                offerInOffers.offerIceCandidates.push(iceCandidate)
                // 1. When the answerer answers, all existing ice candidates are sent
                // 2. Any candidates that come in after the offer has been answered, will be passed through
                if(offerInOffers.answererUserName){
                    //pass it through to the other socket
                    const socketToSendTo = connectedSockets.find(s=>s.userEmail === offerInOffers.answererUserName);
                    if(socketToSendTo){
                        socket.to(socketToSendTo.socketId).emit('receivedIceCandidateFromServer',iceCandidate)
                    }else{
                        console.log("Ice candidate recieved but could not find answere")
                    }
                }
            }
        }else{
            //this ice is coming from the answerer. Send to the offerer
            //pass it through to the other socket
            const offerInOffers = offers.find(o=>o.answererUserName === iceUserName);
            const socketToSendTo = connectedSockets.find(s=>s.userEmail === offerInOffers.offererUserName);
            if(socketToSendTo){
                socket.to(socketToSendTo.socketId).emit('receivedIceCandidateFromServer',iceCandidate)
            }else{
                console.log("Ice candidate recieved but could not find offerer")
            }
        }
        // console.log(offers)
    })

    // Handle disconnection
    socket.on('disconnect', () => {
        console.log('A user disconnected:', socket.id);

        // Remove the user's socket from connectedSockets
        connectedSockets = connectedSockets.filter(s => s.socketId !== socket.id);

        // Remove offers associated with the disconnected user
        offers = offers.filter(offer => offer.offererUserName !== userEmail && offer.answererUserName !== userEmail);
        
        // Optionally notify other users or clean up UI here if needed
    });
    

   


})

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cors());
app.use(require('cookie-parser')());
app.set('view engine', 'ejs');
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: 'pantsbro4@gmail.com', // Replace with your email
        pass: 'tpxy ymac aupu ktow'   // Replace with your password
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Initialize Passport
function initialize(passport) {
    const authenticateUser = async (email, password, done) => {
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { message: 'No user with that email' });
            }
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user); // Pass the whole user object
            } else {
                return done(null, false, { message: 'Password incorrect' });
            }
        } catch (e) {
            return done(e);
        }
    };

    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));
    
    passport.serializeUser((user, done) => {
        done(null, user.id); // Serialize by user ID
    });

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            done(null, user); // Pass the entire user object
        } catch (err) {
            done(err, null);
        }
    });
}

initialize(passport);

// MongoDB connection
mongoose.connect('mongodb+srv://pantsbro4:Saggytits101@cluster0.mthcl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    serverSelectionTimeoutMS: 30000
    
})

.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));
app.use('/api', router);
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
function isVerified(req, res, next) {
    if (!req.isAuthenticated()) {
        return res.redirect('/login'); // Redirect if the user is not logged in
    }
    
    if (!req.user.isVerified) {
        return res.redirect('/verify'); // Redirect to the verify page if not verified
    }

    next(); // If authenticated and verified, allow access to the route
}
// Authentication middleware
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}
async function getUserByEmail(email) {
    console.log('hasfhjba ' , email)
    try {
        return await User.findOne({ email }).populate('friends'); // Populate friends if needed
    } catch (error) {
        console.error(`Error fetching user by email: ${email}`, error);
        return null; // Return null in case of error
    }


    
}
function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    next();
}

// Register route
app.post("/register", [
    body('username').notEmpty().withMessage('Username is required'),
    body('email').isEmail().withMessage('Enter a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords must match');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        // Generate a random 6-digit confirmation code
        const confirmationCode = crypto.randomInt(100000, 999999).toString();

        // Save pending user with confirmation code
        const pendingUser = new PendingUser({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword,
            confirmationCode
        });

        await pendingUser.save();

        // Send confirmation email with the 6-digit code
        await transporter.sendMail({
            to: pendingUser.email,
            subject: 'Confirm Email',
            html: `Your confirmation code is: <strong>${confirmationCode}</strong>. Please enter it to verify your email.`
        });
        res.redirect('/enter-code');
     
    } catch (e) {
        console.log(e);
        res.status(500).send('Server error');
    }
});

const messageSchema = new mongoose.Schema({
    sender: String,
    recipient: String,
    message: String,
    timestamp: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);
// Email confirmation
app.post('/verify-email', [
    body('email').isEmail().withMessage('Enter a valid email'),
    body('confirmationCode').isLength({ min: 6, max: 6 }).withMessage('Confirmation code must be 6 digits')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const { email, confirmationCode } = req.body;

        // Find pending user by email and confirmation code
        const pendingUser = await PendingUser.findOne({ email, confirmationCode });

        if (!pendingUser) {
            return res.status(400).send('Invalid confirmation code or email');
        }

        // Create new user from the pending user
        const newUser = new User({
            name: pendingUser.username,
            email: pendingUser.email,
            password: pendingUser.password,
            isVerified: true
        });

        await newUser.save();
        await PendingUser.deleteOne({ email: pendingUser.email });

        res.send('Email confirmed. You can now log in.');
    } catch (e) {
        console.log(e);
        res.status(500).send('Server error');
    }
});
// Login route
app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render("login.ejs");
});

// Handle login with verification
app.post("/login", async (req, res, next) => {
    passport.authenticate('local', async (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.redirect('/login');
        }
        req.logIn(user, async (err) => {
            if (err) {
                return next(err);
            }

            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            req.session.verificationCode = verificationCode;
            
            await transporter.sendMail({
                to: user.email,
                subject: 'Your Verification Code',
                html: `<p>Your verification code is: <strong>${verificationCode}</strong></p>`,
            });

            // Redirect to the verification page after login
            req.session.userEmail1 = req.body.email;
          
            return res.redirect('/verify');
           
            
        });
    })(req, res, next);
});


// Verification route
app.get('/verify', checkAuthenticated, (req, res) => {
    if (req.isAuthenticated()) {
        return res.render('verify.ejs'); // Render verification form if not verified
    }

    // If the user is already verified, redirect them to another page
    if (req.isAuthenticated()) {
        return res.redirect('/insighta.html'); // Or any other page
    }

    // If the user is not authenticated, redirect to login page
    res.redirect('/login');
});

// Handle verification code submission
app.post('/verify', async (req, res) => {
    const { code } = req.body;

    // Check if the verification code is valid
    if (code === req.session.verificationCode) {
        try {
            const userEmail = req.session.userEmail1;

            // Find the user by email and update their isVerified field to true
            const user = await User.findOne({ email: userEmail });

            if (!user) {
                return res.status(404).send('User not found.');
            }

            // Update the isVerified field to true
            req.session.isVerified = true;

            // Save the user with the updated isVerified field
            await user.save();

            // Optionally, you can delete the session data after successful verification
            delete req.session.verificationCode;
            delete req.session.userEmail;

            // Redirect to insighta.html or any other page after successful verification
            return res.redirect('/insighta.html');
        } catch (err) {
            console.error(err);
            return res.status(500).send('Server error');
        }
    } else {
        // If the verification code is incorrect, send an error message
        res.send('Invalid verification code. Please try again.');
    }
});


app.get('/insighta.html', (req, res) => {
    if (req.session.userEmail1) {
        if (req.session.isVerified) {
            // User is logged in and verified, proceed to the page
            return res.sendFile(path.join(__dirname, 'views', 'insighta.html'));
        } else {
            // User is logged in but not verified, redirect to the verification page
            return res.redirect('/verify');
        }
    } else {
        // User is not authenticated, redirect to login
        return res.redirect('/login');
    }
});
// Redirect root to a new room
// Redirect root to a new room (home page)
app.get('/', (req, res) => {
    if (req.session.userEmail1) {
        if (req.session.isVerified) {
            // User is logged in and verified, show the main page
            return res.sendFile(path.join(__dirname, 'views', 'insighta.html'));
        } else {
            // User is logged in but not verified, redirect to the verification page
            return res.redirect('/verify');
        }
    } else {
        // User is not logged in, redirect to login
        return res.redirect('/login');
    }
});


app.post('/redirect', (req, res) => {
    res.redirect('/register');
});

// User search route
app.get('/search', async (req, res) => {
    const { name } = req.query;
    try {
        const users = await User.find({ name: new RegExp(name, 'i') }); // Case-insensitive search
        res.json(users);
    } catch (error) {
        res.status(500).send('Error searching users');
    }
});

app.post('/redirect1', (req, res) => {
    res.redirect('/login');
});

// Room route
app.get('/:room.html', (req, res) => {
    res.render('index', { roomId: req.params.room });
});

// Registration route
app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render("register.ejs");
});

 

app.post('/add-friend', checkAuthenticated, async (req, res) => {
    const { friendEmail } = req.body;

    // Validate input
    if (!friendEmail) {
        return res.status(400).send('Friend email is required.');
    }

    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).send('User not found.');
        }

        const friend = await User.findOne({ email: friendEmail });
        if (!friend) {
            return res.status(404).send('Friend not found.');
        }

        if (user.friends.includes(friend.id)) {
            return res.status(400).send('You are already friends.');
        }

        // Add friend to current user's friends list
        user.friends.push(friend.id);
        await user.save(); // Ensure this only saves the current user's document

        // Optionally, add the current user to the friend's friends list
        if (!friend.friends.includes(user.id)) {
            friend.friends.push(user.id);
            await friend.save(); // This should not cause a username validation error
        }

        res.status(200).send('Friend added successfully.');
    } catch (err) {
        console.error('Error adding friend:', err);
        res.status(500).send('Server error.');
    }
});





app.get('/get-friends', async (req, res) => {
    try {
        const user = await User.findById(req.user.id).populate('friends'); // Assuming friends are referenced by ObjectId
        if (!user) {
            return res.status(404).send('User not found.');
        }

        // Return friends list
        res.status(200).json(user.friends);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error.');
    }
});

app.post('/send-message', checkAuthenticated, async (req, res) => {
    const { recipient, message } = req.body;

    // Input validation
    if (!recipient || !message) {
        return res.status(400).json({ message: 'Recipient and message are required.' });
    }

    const newMessage = new Message({
        sender: req.user.email,
        recipient,
        message
    });

    try {
        await newMessage.save();

        const recipientSocketId = users[recipient]; // This should now work
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('message1', {
                sender: req.user.email,
                recipient,
                message
            });
        }

        res.status(200).json({ message: 'Message sent successfully!' });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ message: 'Failed to send message' });
    }
});
// Get Messages Route
app.get('/get-messages', async (req, res) => {
    const { friend, lastMessageId } = req.query;

    // Find messages that are either sent or received by the user
    const query = {
        $or: [
            { sender: req.user.email, recipient: friend },
            { sender: friend, recipient: req.user.email }
        ]
    };

    // If lastMessageId is provided, filter for messages that are newer
    if (lastMessageId) {
        query._id = { $gt: lastMessageId }; // Use ObjectId for MongoDB
    }

    const messages = await Message.find(query).sort({ timestamp: 1 });

    res.json(messages);
});

app.post('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ message: 'Failed to log out' });
        }
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).json({ message: 'Failed to destroy session' });
            }
            res.clearCookie('connect.sid'); // Clear the session cookie
            res.status(200).json({ message: 'Logged out successfully' });
        });
    });
});

app.get('/get-email', async (req, res) => {
    const { userId } = req.query; // Assuming you pass userId as a query param
    try {
        const user = await User.findById(userId);
        if (user) {
            res.json({ email: user.email });
        } else {
            res.status(404).send('User not found');
        }
    } catch (error) {
        res.status(500).send('Server error');
    }
});

app.get('/api/user/email', checkAuthenticated, async (req, res) => {
    console.log('User in request:', req.user); // Log the user object
    try {
        if (!req.user) {
            return res.status(400).json({ message: 'User not authenticated' });
        }
        
        const userId = req.user._id; // Get the user's ID
        const user = await User.findById(userId).select('email');
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.status(200).json({ email: user.email });
    } catch (error) {
        console.error('Error retrieving user email:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

  
  // MongoDB schema for storing video details
  const videoSchema = new mongoose.Schema({
    title: String,
    videoPath: String
  });

  
  // Handle video upload
 


const { Readable } = require('stream');

app.post('/upload-video', upload.single('video'), async (req, res) => {
  const { title, description } = req.body;
  const videoBuffer = req.file.buffer;

  try {
    // Create a readable stream from the buffer for Cloudinary
    const bufferStream = new Readable();
    bufferStream.push(videoBuffer);
    bufferStream.push(null); // End the stream

    // Upload the video to Cloudinary using the stream
    bufferStream.pipe(
      cloudinary.uploader.upload_stream(
        { resource_type: 'video' },
        async (error, result) => {
          if (error) {
            console.error('Error uploading to Cloudinary:', error);
            return res.status(500).json({ success: false, message: 'Error uploading video to Cloudinary' });
          }

          try {
            // Save video metadata in the database (MongoDB)
            const newVideo = new Video({
              title,
              description,
              videoUrl: result.secure_url, // Cloudinary video URL
            });

            await newVideo.save();
            res.status(200).json({ success: true, video: newVideo });
          } catch (dbError) {
            console.error('Error saving video metadata:', dbError);
            res.status(500).json({ success: false, message: 'Error saving video metadata' });
          }
        }
      )
    );
  } catch (err) {
    console.error('Error uploading video:', err);
    res.status(500).json({ success: false, message: 'Error processing video upload' });
  }
});
  
  
  
  app.get('/upload-video', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'insighta.html'));
  });
  
  app.get('/search-videos', async (req, res) => {
    const title = req.query.title; // Get the search title from the query parameter
  
    if (!title) {
      return res.status(400).json({ error: 'Title query is required' });
    }
  
    console.log('Searching for title:', title); // Debugging log
  
    try {
      // Search for videos whose title contains the search string (case-insensitive)
      const videos = await Video.find({
        title: { $regex: title, $options: 'i' }, // 'i' makes it case-insensitive
      });
  
      if (videos.length === 0) {
        console.log('No videos found');
      } else {
        console.log('Videos found:', videos.length);
      }
  
      res.json(videos); // Return the found videos as JSON
    } catch (error) {
      console.error("Error querying videos:", error);
      res.status(500).json({ error: "An error occurred while fetching videos" });
    }
  });
  
app.post('/update-profile', upload.single('profileImg'), async (req, res) => {
  const { name, email } = req.body;
  const profileImgPath = req.file ? `/uploads/images/${req.file.filename}` : null;

  try {
    const user = await User.findById(req.user.id); // Assuming `req.user.id` contains the logged-in user's ID
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.name = name || user.name;
    user.email = email || user.email;
    if (profileImgPath) user.profileImg = profileImgPath;

    await user.save();
    res.status(200).json({ success: true, message: 'Profile updated', user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Error updating profile' });
  }
});

  app.get('/video/:id', async (req, res) => {
    try {
      const video = await Video.findById(req.params.id);
      if (!video) {
        return res.status(404).json({ message: 'Video not found' });
      }
      res.render('videoPage', { video });
    } catch (err) {
      console.error('Error fetching video:', err);
      res.status(500).json({ message: 'Error fetching video' });
    }
  });
 
  // Function to remove video data from the database if it doesn't exist
  async function removeVideoData(megaUrl) {
    try {
      // Find the video by the MEGA URL and remove it
      const video = await Video.findOne({ videoUrl: megaUrl });
  
      if (video) {
        // If the video exists in the database, delete it
        await Video.deleteOne({ videoUrl: megaUrl });
        console.log(`Video data for ${megaUrl} removed from the database.`);
      }
    } catch (error) {
      console.error('Error removing video data from the database:', error);
    }
  }
  app.get('/enter-code', (req, res) => {
    res.render('enter-code');  // This should render your HTML form for entering the confirmation code
});
app.delete('/delete-post/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const post = await Post.findById(id);

    if (!post) {
      return res.status(404).json({ success: false, message: 'Post not found' });
    }

    if (post.user.toString() !== req.user.id) {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    // Delete the media file from the filesystem
    if (post.media) {
      const mediaPath = path.join(__dirname, post.media);
      fs.unlink(mediaPath, (err) => {
        if (err) console.error(`Error deleting file: ${err.message}`);
      });
    }

    await Post.findByIdAndDelete(id);
    res.status(200).json({ success: true, message: 'Post deleted' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Error deleting post' });
  }
});
app.get('/get-videos', async (req, res) => {
  const { page, limit } = req.query;
  // Logic for fetching videos from the database
  const videos = await Video.find()
    .skip((page - 1) * limit)
    .limit(Number(limit));

  if (videos) {
    res.json(videos);  // Send JSON response
  } else {
    res.status(404).json({ message: 'Videos not found' });
  }
});

app.get('/user-posts', async (req, res) => {
  try {
    const posts = await Post.find({ user: req.user.id }); // Fetch posts for the logged-in user
    res.status(200).json({ success: true, posts });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Error fetching posts' });
  }
});



  module.exports = router;
