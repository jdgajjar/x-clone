const express = require('express');
const router = express.Router();
const User = require('../models/User');
const multer = require('multer');
const path = require('path');

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, '../public/images'));
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});

const upload = multer({ storage });

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

// Get user profile
router.get('/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username })
      .populate('following', 'username name profileImage')
      .populate('followers', 'username name profileImage');
    
    if (!user) {
      return res.status(404).render('error', { message: 'User not found' });
    }

    res.render('profile', { 
      user,
      currentUser: req.user
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).render('error', { message: 'Server error' });
  }
});

// Get following list page
router.get('/:username/following', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username })
      .populate('following', 'username name profileImage');
    
    if (!user) {
      return res.status(404).render('error', { message: 'User not found' });
    }

    // Check if it's an AJAX request
    if (req.xhr) {
      res.render('following', { 
        user,
        currentUser: req.user,
        following: user.following,
        layout: false
      });
    } else {
      res.render('following', { 
        user,
        currentUser: req.user,
        following: user.following
      });
    }
  } catch (error) {
    console.error('Following list error:', error);
    res.status(500).render('error', { message: 'Server error' });
  }
});

// Get followers list page
router.get('/:username/followers', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username })
      .populate('followers', 'username name profileImage');
    
    if (!user) {
      return res.status(404).render('error', { message: 'User not found' });
    }

    // Check if it's an AJAX request
    if (req.xhr) {
      res.render('followers', { 
        user,
        currentUser: req.user,
        followers: user.followers,
        layout: false
      });
    } else {
      res.render('followers', { 
        user,
        currentUser: req.user,
        followers: user.followers
      });
    }
  } catch (error) {
    console.error('Followers list error:', error);
    res.status(500).render('error', { message: 'Server error' });
  }
});

module.exports = router;