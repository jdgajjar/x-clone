// Define global functions
async function loadFollowing(username) {
    try {
        const response = await fetch(`/profile/${username}/following`);
        if (!response.ok) {
            throw new Error(`Error loading following: ${response.statusText}`);
        }
        const html = await response.text();
        document.getElementById('dynamic-content').innerHTML = html;
    } catch (error) {
        console.error('Error loading following:', error);
    }
}

async function loadFollowers(username) {
    try {
        const response = await fetch(`/profile/${username}/followers`);
        if (!response.ok) {
            throw new Error(`Error loading followers: ${response.statusText}`);
        }
        const html = await response.text();
        document.getElementById('dynamic-content').innerHTML = html;
    } catch (error) {
        console.error('Error loading followers:', error);
    }
}

window.loadProfile = async function(username) {
    try {
        const response = await fetch(`/profile/${username}`);
        if (!response.ok) {
            throw new Error('Failed to load profile content');
        }
        const profileHtml = await response.text();
        
        // Create a temporary container to parse the HTML
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = profileHtml;
        
        // Get the main content from the response
        const mainContent = tempDiv.querySelector('main');
        if (!mainContent) {
            throw new Error('Profile content not found');
        }
        
        // Update the main content
        const currentMain = document.querySelector('main');
        if (currentMain) {
            currentMain.innerHTML = mainContent.innerHTML;
            
            // Update active state of navigation items
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active-nav-item');
            });
            const profileNavItem = document.querySelector('a[onclick*="loadProfile"]');
            if (profileNavItem) {
                profileNavItem.classList.add('active-nav-item');
            }
            
            // Reinitialize any event listeners
            initializeFollowButtons();
        } else {
            throw new Error('Main element not found in current page');
        }
    } catch (error) {
        console.error('Error loading profile:', error);
        // Show error message to user
        const mainContent = document.querySelector('main');
        if (mainContent) {
            mainContent.innerHTML = `
                <div class="text-gray-500 text-center py-8">
                    <p>Error loading profile. Please try again.</p>
                </div>
            `;
        }
    }
};




// Helper function to initialize follow buttons
function initializeFollowButtons() {
    const followButtons = document.querySelectorAll('.follow-button');
    console.log(`Found ${followButtons.length} follow buttons`); // Debugging to check button count

    if (followButtons.length === 0) {
        console.warn('No follow buttons found in the DOM'); // Warn if no buttons are found
        return;
    }

    followButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const username = this.dataset.username;
            const isFollowing = this.textContent.trim() === 'Following';
            const action = isFollowing ? 'unfollow' : 'follow';

            console.log(`Button clicked for user: ${username}`);
            console.log(`Current action: ${action}`);

            try {
                const response = await fetch(`/profile/${username}/${action}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        username: username // Updated field name to match backend expectations
                    })
                });

                if (!response.ok) {
                    throw new Error('Failed to perform follow/unfollow action');
                }

                const data = await response.json();
                console.log('Server response:', data);

                if (data.success) {
                    // Update button text and styling
                    this.textContent = data.following ? 'Following' : 'Follow';
                    this.classList.toggle('bg-white', data.following);
                    this.classList.toggle('text-black', data.following);
                    this.classList.toggle('bg-gray-800', !data.following);
                    this.classList.toggle('text-white', !data.following);

                    // Update follower count
                    const followerCount = document.querySelector('a[onclick*="loadFollowers"] .font-bold');
                    if (followerCount) {
                        followerCount.textContent = data.followersCount;
                    }

                    // Update following count
                    const followingCount = document.querySelector('a[onclick*="loadFollowing"] .font-bold');
                    if (followingCount) {
                        followingCount.textContent = data.followingCount;
                    }
                } else {
                    console.error('Error:', data.message || 'Failed to update follow status');
                }
            } catch (error) {
                console.error('Error:', error.message);
            }
        });
    });
}

// Initialize when the document is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded and parsed'); // Debugging to ensure script runs

    // Initialize follow buttons
    initializeFollowButtons();

    // Set up profile button if it exists
    const followButton = document.querySelector('.follow-button');
    if (followButton) {
        const isFollowing = followButton.dataset.following === 'true';
        followButton.classList.toggle('bg-white', isFollowing);
        followButton.classList.toggle('text-black', isFollowing);
        followButton.classList.toggle('bg-gray-800', !isFollowing);
        followButton.classList.toggle('text-white', !isFollowing);
    }
});




