async function handleSubmit(event) {
  event.preventDefault();
  
  const new_password = document.getElementById('new_password').value;
  const token = new URLSearchParams(window.location.search).get('token');

  if (!token) {
    alert('Token inválido ou expirado');
    window.location.href = '/login';
    return;
  }

  try {
    const response = await fetch('/auth/reset-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ 
        token,
        new_password
      })
    });

    if (response.ok) {
      alert('Senha redefinida com sucesso!');
      window.location.href = '/login';
    } else {
      const data = await response.json();
      alert(data.detail || 'Erro ao redefinir senha');
    }
  } catch (error) {
    alert('Erro ao redefinir senha');
  }
}
