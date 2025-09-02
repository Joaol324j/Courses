async function handleSubmit(event) {
    event.preventDefault();

    const username = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
      const response = await fetch('/auth/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
      });

      if (response.ok) {
        const data = await response.json();
        localStorage.setItem('token', data.access_token);
        window.location.href = '/home';
      } else {
        const data = await response.json();
        alert(data.detail || 'Erro ao fazer login');
      }
    } catch (error) {
      alert('Erro ao fazer login');
    }
  }