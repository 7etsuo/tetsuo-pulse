/**
 * Pulse Branding Customizations
 */
document.addEventListener('DOMContentLoaded', function() {
    // Replace Doxygen footer with Tetsuo Corp copyright
    var footer = document.querySelector('.footer');
    if (footer) {
        footer.innerHTML = '© <a href="https://tetsuocorp.com" target="_blank" rel="noopener">Tetsuo Corp</a>';
    }
});
