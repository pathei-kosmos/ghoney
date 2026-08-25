document.addEventListener('DOMContentLoaded', () => {
    const SUBMIT_TIMEOUT_MS = 5000;
    const form = document.querySelector('form');
    const button = form?.querySelector('button[type="submit"]');
    const errorMessage = document.getElementById('login-error');

    // Keep regular form submission when the page is incomplete
    if (!form || !button || !errorMessage) {
        return;
    }

    // Bound the in-place request so the form always becomes usable again
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        button.disabled = true;
        errorMessage.textContent = '';
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), SUBMIT_TIMEOUT_MS);
        try {
            await fetch(form.action, {
                method: 'POST',
                body: new URLSearchParams(new FormData(form)),
                cache: 'no-store',
                credentials: 'same-origin',
                signal: controller.signal
            });
        } catch (error) {
            // Use the same message for HTTP and network failures
            console.error('Authentication request failed:', error);
        } finally {
            window.clearTimeout(timeout);
            errorMessage.textContent = 'Unable to sign in. Check your credentials and try again.';
            button.disabled = false;
        }
    });
});
