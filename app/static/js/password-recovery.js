async function handleSubmit(event) {
    event.preventDefault();
    
    const email = document.getElementById('email').value;

    try {
      const response = await fetch('/auth/password-recovery', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email })
      });

      if (response.ok) {
        alert('Link de recuperação enviado para seu email!');
        window.location.href = '/login';
      } else {
        const data = await response.json();
        alert(data.detail || 'Erro ao enviar link de recuperação');
      }
    } catch (error) {
      alert('Erro ao enviar link de recuperação');
    }
  }