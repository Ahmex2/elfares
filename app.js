// Helper function to handle errors
async function handleResponse(response) {
  const data = await response.json();
  if (response.ok) {
    return data;
  } else {
    throw new Error(data.error);
  }
}

// Register form
async function register() {
  const usernameInput = document.querySelector('#register-form input[name="username"]');
  const emailInput = document.querySelector('#register-form input[name="email"]');
  const passwordInput = document.querySelector('#register-form input[name="password"]');
  const username = usernameInput.value;
  const email = emailInput.value;
  const password = passwordInput.value;

  // Validate input
  if (!username || !email || !password) {
    return alert('Please fill in all fields');
  }

  if (!validateEmail(email)) {
    return alert('Please enter a valid email');
  }

  try {
    const response = await fetch('http://localhost:8000/register', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, email, password })
    });
    await handleResponse(response);
    alert('Registration successful!');
    document.querySelector('#register-form').reset();
  } catch (error) {
    console.error(error);
    alert(error.message || 'Could not connect to the server');
  }
}

// Login form
async function login() {
  const emailInput = document.querySelector('#login-form input[name="email"]');
  const passwordInput = document.querySelector('#login-form input[name="password"]');
  const email = emailInput.value;
  const password = passwordInput.value;

  // Validate input
  if (!email || !password) {
    return alert('Please fill in all fields');
  }

  if (!validateEmail(email)) {
    return alert('Please enter a valid email');
  }

  try {
    const response = await fetch('http://localhost:8000/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email, password })
    });
    const data = await handleResponse(response);
    localStorage.setItem('token', data.token);
    loadPage('dashboard');
  } catch (error) {
    console.error(error);
    alert(error.message || 'Could not connect to the server');
  }
}

// Get user info
async function getUserInfo() {
  const token = localStorage.getItem('token');
  if (!token) {
    return;
  }

  try {
    const response = await fetch('http://localhost:8000/users/me', {
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await handleResponse(response);
    document.getElementById('username').innerText = data.username;
    document.getElementById('balance').innerText = `$${data.balance.toFixed(2)}`;
  } catch (error) {
    console.error(error);
    alert(error.message || 'Could not connect to the server');
  }
}

// Deposit form
async function deposit() {
  const amountInput = document.querySelector('#deposit-form input[name="amount"]');
  const amount = parseFloat(amountInput.value);

  // Validate input
  if (isNaN(amount) || amount <= 0) {
    return alert('Please enter a valid amount');
  }

  const token = localStorage.getItem('token');
  if (!token) {
    return;
  }

  try {
    const response = await fetch('http://localhost:8000/transactions/deposit', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount }),
    });
    const data = await handleResponse(response);
    const qrCodeImg = document.querySelector('#deposit-qr img');
    qrCodeImg.src = await createQRCode(data.depositAddress);
    document.querySelector('#deposit-qr p').innerText = data.depositAddress;
    loadPage('deposit');
  } catch (error) {
    console.error(error);
    alert(error.message || 'Could not connect to the server');
  }
}

// Withdraw form
async function withdraw() {
  const amountInput = document.querySelector('#withdraw-form input[name="amount"]');
  constamount = parseFloat(amountInput.value);

  // Validate input
  if (isNaN(amount) || amount <= 0) {
    return alert('Please enter a valid amount');
  }

  const token = localStorage.getItem('token');
  if (!token) {
    return;
  }

  try {
    const response = await fetch('http://localhost:8000/transactions/withdraw', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount }),
    });
    const data = await handleResponse(response);
    alert('Withdrawal successful!');
    document.querySelector('#withdraw-form').reset();
    document.getElementById('balance').innerText = `$${data.balance.toFixed(2)}`;
  } catch (error) {
    console.error(error);
    alert(error.message || 'Could not connect to the server');
  }
          }
