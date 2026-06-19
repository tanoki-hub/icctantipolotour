// Initialize the form when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  const loginForm = document.getElementById('form-login');
  const passwordInput = document.getElementById('login-password');
  const passwordToggle = document.querySelector('.password-mask-toggle');

  // Password visibility toggle
  if (passwordToggle && passwordInput) {
    passwordToggle.textContent = '👁️';
    passwordToggle.addEventListener('click', function() {
      if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        passwordToggle.textContent = '👁️‍🗨️';
      } else {
        passwordInput.type = 'password';
        passwordToggle.textContent = '👁️';
      }
    });
  }

  // Form submission handler
  if (loginForm) {
    loginForm.addEventListener('submit', async function(e) {
      e.preventDefault();

      const schoolId = document.getElementById('login-id').value.trim();
      const password = document.getElementById('login-password').value;
      const submitBtn = loginForm.querySelector('button[type="submit"]');

      // Validate inputs
      if (!schoolId || !password) {
        showToast('Please fill in all fields', 'error');
        return;
      }

      if (submitBtn) submitBtn.disabled = true;
      showToast('Authenticating...', 'info');

      try {
        // ── Real credential check, merged in from db.js ──
        const result = await DB.validateUser(schoolId, password);

        if (!result.ok) {
          showToast(result.msg || 'Login failed.', 'error');
          if (submitBtn) submitBtn.disabled = false;
          return;
        }

        DB.setSession(result.user);
        showToast('Login successful. Redirecting to dashboard...', 'success');

        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 1200);

      } catch (err) {
        console.error(err);
        showToast('Something went wrong. Please try again.', 'error');
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }
});

// Toast notification system
function showToast(message, type = 'info') {
  const toastContainer = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;

  const styles = {
    padding: '12px 20px',
    marginBottom: '10px',
    borderRadius: '8px',
    fontSize: '14px',
    animation: 'slideIn 0.3s ease',
  };

  const typeStyles = {
    success: { background: '#4caf50', color: 'white' },
    error: { background: '#f44336', color: 'white' },
    info: { background: '#2196f3', color: 'white' }
  };

  Object.assign(toast.style, styles, typeStyles[type] || typeStyles.info);

  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Add animations
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from {
      transform: translateX(400px);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }

  @keyframes slideOut {
    from {
      transform: translateX(0);
      opacity: 1;
    }
    to {
      transform: translateX(400px);
      opacity: 0;
    }
  }
`;
document.head.appendChild(style);