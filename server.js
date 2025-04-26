const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const multer = require('multer');
require('dotenv').config();
const postRoutes = require('./routes/posts');

const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/x-clone')
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((err) => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    following: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

const User = mongoose.model('User', userSchema);

// Post Schema
const postSchema = new mongoose.Schema({
    content: { type: String, required: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now },
    likes: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    retweets: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    replies: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Post' }]
});

const Post = mongoose.model('Post', postSchema);

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: 'mongodb://127.0.0.1:27017/x-clone',
        ttl: 24 * 60 * 60 // 1 day
    }),
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));

// Passport configuration
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
},
async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if user already exists
        let user = await User.findOne({ email: profile.emails[0].value });
        
        if (!user) {
            // Create new user if doesn't exist
            user = new User({
                username: profile.displayName.toLowerCase().replace(/\s+/g, ''),
                email: profile.emails[0].value,
                password: crypto.randomBytes(32).toString('hex') // Generate random password
            });
            await user.save();

            // Find a random user to follow (excluding the new user)
            const randomUser = await User.aggregate([
                { $match: { _id: { $ne: user._id } } },
                { $sample: { size: 1 } }
            ]);

            if (randomUser && randomUser.length > 0) {
                // Add random user to following list
                user.following.push(randomUser[0]._id);
                // Add new user to random user's followers list
                await User.findByIdAndUpdate(randomUser[0]._id, {
                    $push: { followers: user._id }
                });
                
                // Save the new user with updated following list
                await user.save();
            }
        }
        
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

// Google Auth Routes
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('/home');
    }
);

// Authentication middleware
const isAuthenticated = (req, res, next) => {
    if (req.path === "/explore") {
        return next(); // Allow access to the explore page without authentication
    }
    if (req.isAuthenticated() || req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

// Create a transporter for sending emails
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

app.use((req, res, next) => {
    console.log(`Request: ${req.method} ${req.url}`);
    next();
  });
  

// Store reset tokens temporarily (in production, use Redis or a database)
const resetTokens = new Map();

app.get('/login', (req, res) => {
    if (req.session.userId) {
        res.redirect('/home');
    } else {
        res.render('login', { error: null });
    }
});

app.get('/register', (req, res) => {
    if (req.session.userId) {
        res.redirect('/home');
    } else {
        res.render('register', { error: null });
    }
});

app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.render('register', { error: 'Username or email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const user = new User({
            username,
            email,
            password: hashedPassword
        });

        await user.save();

        // Find a random user to follow (excluding the new user)
        const randomUser = await User.aggregate([
            { $match: { _id: { $ne: user._id } } },
            { $sample: { size: 1 } }
        ]);

        if (randomUser && randomUser.length > 0) {
            // Add random user to following list
            user.following.push(randomUser[0]._id);
            // Add new user to random user's followers list
            await User.findByIdAndUpdate(randomUser[0]._id, {
                $push: { followers: user._id }
            });
            
            // Save the new user with updated following list
            await user.save();
        }

        // Set session
        req.session.userId = user._id;
        res.redirect('/home');
    } catch (error) {
        console.error('Registration error:', error);
        res.render('register', { error: 'An error occurred during registration' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password, remember } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('login', {
                error: 'Invalid email or password.'
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.render('login', {
                error: 'Invalid email or password.'
            });
        }

        // Set session
        req.session.userId = user._id;

        // If remember me is checked, set a longer session duration
        if (remember) {
            req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
        }

        res.redirect('/home');
    } catch (error) {
        console.error('Login error:', error);
        res.render('login', {
            error: 'An error occurred. Please try again.'
        });
    }
});

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('Session destruction error:', err);
            }
            res.redirect('/login');
        });
    });
});

// Home route
app.get('/home', isAuthenticated, async (req, res) => {
  try {
    const randomusers = await User.find().limit(5);
    const userId = req.user ? req.user._id : req.session.userId;
    const user = await User.findById(userId);
    const posts = await Post.find({ author: userId }).sort({ createdAt: -1 });

    

    // Check if the request is an AJAX request
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      res.render('partials/home-main', { user, posts, layout: false });
    } else {
      res.render('home', { user, posts, randomusers });
    }
  } catch (error) {
    console.error('Error loading home:', error);
    res.redirect('/login');
  }
});

// Forgot password route
app.get('/forgot-password', (req, res) => {
    res.render('forgot-password', { error: null, success: null });
});

app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('forgot-password', {
                error: 'No account found with that email address.',
                success: null
            });
        }

        // Generate reset token
        const token = crypto.randomBytes(32).toString('hex');
        const resetToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        // Store token with expiration (1 hour)
        resetTokens.set(resetToken, {
            userId: user._id,
            expires: Date.now() + 3600000 // 1 hour
        });

        // Send reset email
        const resetUrl = `${req.protocol}://${req.get('host')}/reset-password/${token}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Request',
            html: `
                <h1>Password Reset Request</h1>
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <a href="${resetUrl}">Reset Password</a>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
            `
        };

        await transporter.sendMail(mailOptions);

        res.render('forgot-password', {
            error: null,
            success: 'Password reset link sent to your email.'
        });
    } catch (error) {
        console.error('Password reset error:', error);
        res.render('forgot-password', {
            error: 'Error sending reset link. Please try again.',
            success: null
        });
    }
});

// Reset password route
app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    const resetToken = crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');

    const resetData = resetTokens.get(resetToken);

    if (!resetData || resetData.expires < Date.now()) {
        return res.render('forgot-password', {
            error: 'Invalid or expired reset link. Please request a new one.',
            success: null
        });
    }

    res.render('reset-password', { token, error: null });
});

app.post('/reset-password', async (req, res) => {
    try {
        const { token, password, confirmPassword } = req.body;

        if (password !== confirmPassword) {
            return res.render('reset-password', {
                token,
                error: 'Passwords do not match.'
            });
        }

        const resetToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const resetData = resetTokens.get(resetToken);

        if (!resetData || resetData.expires < Date.now()) {
            return res.render('forgot-password', {
                error: 'Invalid or expired reset link. Please request a new one.',
                success: null
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update user password
        await User.findByIdAndUpdate(resetData.userId, {
            password: hashedPassword
        });

        // Remove used token
        resetTokens.delete(resetToken);

        // Redirect to login with success message
        req.flash('success', 'Password has been reset. Please login with your new password.');
        res.redirect('/login');
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).redirect('/home');
    }
});

// Profile routes
app.get('/profile/:username', isAuthenticated, async (req, res) => {
  try {
    const username = req.params.username;
    const user = await User.findOne({ username });
    const currentUser = await User.findById(req.session.userId);

    if (!user) {
      return res.status(404).send('Profile not found');
    }

    // Check if the request is an AJAX request
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
      res.render('partials/profile-main', { user, currentUser, layout: false });
    } else {
      res.render('profile', { user, currentUser });
    }
  } catch (error) {
    console.error('Error loading profile:', error);
    res.status(500).send('Error loading profile');
  }
});

// Direct username route
app.get('/:username', isAuthenticated, async (req, res) => {
    try {
        const username = req.params.username;
        
        // Skip if the route is a known route
        if (['home', 'login', 'register', 'logout', 'profile', 'forgot-password', 'reset-password'].includes(username)) {
            return res.redirect('/home');
        }

        const user = await User.findOne({ username });
       
        
        if (!user) {
            return res.redirect('/home');
        }

        // Empty posts array for UI
        const posts = [];

        res.render('profile', {
            user,
            currentUser,
            posts,
            error: null,
            success: null
        });
    } catch (error) {
        console.error('Profile error:', error);
        res.redirect('/home');
    }
});

// Following route
app.get('/profile/:username/following', isAuthenticated, async (req, res) => {
    try {
        const username = req.params.username;
        const user = await User.findOne({ username })
            .populate({
                path: 'following',
                select: 'username email followers following'
            });
        
        if (!user) {
            return res.status(404).send('User not found');
        }

        const currentUser = await User.findById(req.session.userId);
        if (!currentUser) {
            return res.status(401).send('Unauthorized');
        }

        res.render('following', {
            user,
            currentUser,
            following: user.following,
            layout: false
        });
    } catch (error) {
        console.error('Following error:', error);
        res.status(500).send('Error loading following list');
    }
});

// Followers route
app.get('/profile/:username/followers', isAuthenticated, async (req, res) => {
    try {
        const username = req.params.username;
        const user = await User.findOne({ username })
            .populate({
                path: 'followers',
                select: 'username email followers following'
            });
        
        if (!user) {
            return res.status(404).send('User not found');
        }

        const currentUser = await User.findById(req.session.userId);
        if (!currentUser) {
            return res.status(401).send('Unauthorized');
        }

        res.render('followers', {
            user,
            currentUser,
            followers: user.followers,
            layout: false
        });
    } catch (error) {
        console.error('Followers error:', error);
        res.status(500).send('Error loading followers list');
    }
});

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'public/images'));
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({ storage });

// Update profile route



app.post('/profile/edit', isAuthenticated, upload.fields([{ name: 'cover' }, { name: 'Image' }]), async (req, res) => {
    try {
        const { username, email } = req.body;
        // Ensure userId is retrieved correctly
        const userId = req.user ? req.user._id : req.session.userId;

        if (!userId) {
            console.error('User ID is missing. Cannot update profile.');
            return res.status(400).redirect('/home');
        }

        // Prepare update object
        const updateData = { username, email };

        // Validate uploaded files
        if (req.files) {
            console.log('Uploaded files:', req.files);
            if (req.files.cover && req.files.cover.length > 0) {
                console.log('Cover file details:', req.files.cover[0]);
            } else {
                console.log('No cover file uploaded.');
            }
            if (req.files.Image && req.files.Image.length > 0) {
                console.log('Profile file details:', req.files.Image[0]);
            } else {
                console.log('No profile file uploaded.');
            }
        } else {
            console.log('No files uploaded.');
        }

        // Debugging: Log the final update data
        console.log('Final update data:', updateData);

        // Update user in the database
        const updatedUser = await User.findByIdAndUpdate(userId, updateData, { new: true });

        if (!updatedUser) {
            console.error('Failed to update user profile in the database.');
            return res.status(500).redirect('/home');
        }

        console.log('Profile updated successfully in the database:', updatedUser);
        res.redirect('/home');
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).redirect('/home');
    }
});

// Settings route
app.get('/:id/settings', isAuthenticated, async (req, res) => {
    try {
        const userId = req.params.id;
        const currentUserId = req.user ? req.user._id : req.session.userId;
        
        // Verify that the user is accessing their own settings
        if (userId !== currentUserId.toString()) {
            return res.redirect('/home');
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.redirect('/home');
        }
        
        res.render('settings', { user });
    } catch (error) {
        console.error('Settings error:', error);
        res.redirect('/home');
    }
});

// Delete account route
app.post('/delete-account', isAuthenticated, async (req, res) => {
    try {
        const userId = req.user ? req.user._id : req.session.userId;
        
        // Delete user's posts
        await Post.deleteMany({ author: userId });
        
        // Delete user account
        await User.findByIdAndDelete(userId);
        
        // Logout and destroy session
        req.logout((err) => {
            if (err) {
                console.error('Logout error:', err);
            }
            req.session.destroy((err) => {
                if (err) {
                    console.error('Session destruction error:', err);
                }
                res.redirect('/login');
            });
        });
    } catch (error) {
        console.error('Delete account error:', error);
        res.status(500).json({ error: 'Failed to delete account' });
    }
});

// Follow a user
app.post('/profile/:username/follow', isAuthenticated, async (req, res) => {
    try {
        console.log('Follow request received:', req.params);
        const { username } = req.params;
        const currentUserId = req.user ? req.user._id : req.session.userId;

        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        const userToFollow = await User.findOne({ username });
        const currentUser = await User.findById(currentUserId);

        if (!userToFollow || !currentUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (!currentUser.following.includes(userToFollow._id)) {
            currentUser.following.push(userToFollow._id);
            userToFollow.followers.push(currentUserId);

            await currentUser.save();
            await userToFollow.save();
        }

        res.status(200).json({ success: true, message: 'Followed successfully', following: true });
    } catch (error) {
        console.error('Follow error:', error);
        res.status(500).json({ error: 'Failed to follow user' });
    }
});

// Unfollow a user
app.post('/profile/:username/unfollow', isAuthenticated, async (req, res) => {
    try {
        const { username } = req.params;
        const currentUserId = req.user ? req.user._id : req.session.userId;

        if (!username) {
            return res.status(400).json({ error: 'Username is required' });
        }

        const userToUnfollow = await User.findOne({ username });
        const currentUser = await User.findById(currentUserId);

        if (!userToUnfollow || !currentUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        currentUser.following = currentUser.following.filter(id => id.toString() !== userToUnfollow._id.toString());
        userToUnfollow.followers = userToUnfollow.followers.filter(id => id.toString() !== currentUserId.toString());

        await currentUser.save();
        await userToUnfollow.save();
        
        res.status(200).json({ success: true, message: 'Unfollowed successfully', following: false });
    } catch (error) {
        console.error('Unfollow error:', error);
        res.status(500).json({ error: 'Failed to unfollow user' });
    }
});

// Route to render the edit profile page
app.get('/profile/:id/edit', isAuthenticated, async (req, res) => {
    try {
        const userId = req.params.id;
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).render('404', { error: 'User not found' });
        }

        res.render('editeprofile', { user });
    } catch (error) {
        console.error('Error loading edit profile page:', error);
        res.status(500).render('error', { message: 'An error occurred while loading the edit profile page.' });
    }
});

// Catch-all route for 404
app.use((req, res) => {
    res.status(404).render('404', { error: 'Page not found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
