document.addEventListener('DOMContentLoaded', () => {
    const followButtons = document.querySelectorAll('.follow-button');

    followButtons.forEach(button => {
        button.addEventListener('click', async function () {
            const username = this.dataset.username;
            const isFollowing = this.dataset.following === 'true';
            const action = isFollowing ? 'unfollow' : 'follow';

            try {
                const response = await fetch(`/profile/${username}/${action}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ username })
                });

                if (!response.ok) {
                    throw new Error('Failed to perform follow/unfollow action');
                }

                const data = await response.json();

                if (data.success) {
                    // Update button text and styling
                    this.textContent = data.following ? 'Following' : 'Follow';
                    this.classList.toggle('bg-white', data.following);
                    this.classList.toggle('text-black', data.following);
                    this.classList.toggle('bg-gray-800', !data.following);
                    this.classList.toggle('text-white', !data.following);

                    // Update the `data-following` attribute
                    this.dataset.following = data.following;
                } else {
                    console.error('Error:', data.message || 'Failed to update follow status');
                }
            } catch (error) {
                console.error('Error:', error.message);
            }
        });
    });
});