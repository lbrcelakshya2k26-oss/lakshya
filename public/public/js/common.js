document.addEventListener('DOMContentLoaded', function() {
    // 1. Define the Sidebar HTML
    // We verify if the user is logged in or not to adjust the menu if needed, 
    // but for now we stick to the standard participant menu.
    
    const sidebarHTML = `
    <!-- Mobile Header (Visible only on mobile) -->
    <div class="mobile-header">
        <div class="mobile-logo">LAKSHYA 2K26</div>
        <i class="fa-solid fa-bars menu-toggle" onclick="toggleSidebar()"></i>
    </div>

    <!-- Sidebar Overlay (Background dimming on mobile) -->
    <div class="sidebar-overlay" onclick="toggleSidebar()"></div>

    <!-- The Sidebar -->
    <aside class="sidebar" id="sidebar">
        <div class="logo">LAKSHYA</div>
        <ul class="menu">
            <li><a href="dashboard" data-page="dashboard"><i class="fa-solid fa-gauge"></i> Dashboard</a></li>
            <li><a href="events" data-page="events"><i class="fa-solid fa-calendar-days"></i> Events</a></li>
            <li><a href="cart" data-page="cart"><i class="fa-solid fa-cart-shopping"></i> Cart</a></li>
            <li><a href="my-registrations" data-page="my-registrations"><i class="fa-solid fa-list-check"></i> My Registrations</a></li>
            <li><a href="feedback" data-page="feedback"><i class="fa-solid fa-comments"></i> Feedback</a></li>
            <li><a href="#" onclick="logout()" class="logout"><i class="fa-solid fa-right-from-bracket"></i> Logout</a></li>
        </ul>
    </aside>
    `;

    // 2. Inject Sidebar into the Body
    // We prepend it so it becomes the first element (important for flexbox layouts)
    document.body.insertAdjacentHTML('afterbegin', sidebarHTML);

    // 3. Highlight the Active Link
    // We look for a global variable 'CURRENT_PAGE' defined in the HTML file
    if (typeof CURRENT_PAGE !== 'undefined') {
        const activeLink = document.querySelector(`.menu a[data-page="${CURRENT_PAGE}"]`);
        if (activeLink) {
            activeLink.classList.add('active');
        }
    }
});

// --- Global Functions ---

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.querySelector('.sidebar-overlay');
    
    sidebar.classList.toggle('active');
    
    if (sidebar.classList.contains('active')) {
        overlay.style.display = 'block';
        setTimeout(() => overlay.style.opacity = '1', 10); // Fade in
    } else {
        overlay.style.opacity = '0';
        setTimeout(() => overlay.style.display = 'none', 300); // Wait for fade out
    }
}

function logout() {
    if(confirm('Are you sure you want to logout?')) {
        localStorage.clear();
        window.location.href = '/login'; // Adjust path as needed
    }
}