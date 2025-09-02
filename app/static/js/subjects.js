let currentPage = 1;
const itemsPerPage = 10;
let subjects = [];

function formatDate(dateString) {
  if (!dateString) return '-';
  const date = new Date(dateString);
  return date.toLocaleDateString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

function showSuccess(message) {
  const toast = document.createElement('div');
  toast.className = 'toast align-items-center text-white bg-success border-0 position-fixed top-0 end-0 m-3';
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'assertive');
  toast.setAttribute('aria-atomic', 'true');
  
  toast.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">
        <i class="fas fa-check-circle me-2"></i>${message}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  `;
  
  document.body.appendChild(toast);
  const bsToast = new bootstrap.Toast(toast);
  bsToast.show();
  
  toast.addEventListener('hidden.bs.toast', () => {
    document.body.removeChild(toast);
  });
}

function showError(message) {
  const toast = document.createElement('div');
  toast.className = 'toast align-items-center text-white bg-danger border-0 position-fixed top-0 end-0 m-3';
  toast.setAttribute('role', 'alert');
  toast.setAttribute('aria-live', 'assertive');
  toast.setAttribute('aria-atomic', 'true');
  
  toast.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">
        <i class="fas fa-exclamation-circle me-2"></i>${message}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
    </div>
  `;
  
  document.body.appendChild(toast);
  const bsToast = new bootstrap.Toast(toast);
  bsToast.show();
  
  toast.addEventListener('hidden.bs.toast', () => {
    document.body.removeChild(toast);
  });
}

async function loadSubjects() {
  try {
    const response = await fetch('/subjects');
    if (!response.ok) throw new Error('Erro ao carregar disciplinas');
    
    subjects = await response.json();
    updateSubjectsTable();
    updatePagination();
    updateCounters();
  } catch (error) {
    console.error('Erro:', error);
    showError('Erro ao carregar disciplinas');
  }
}

function updateSubjectsTable() {
  const start = (currentPage - 1) * itemsPerPage;
  const end = start + itemsPerPage;
  const paginatedSubjects = subjects.slice(start, end);
  
  const tbody = document.getElementById('subjectsTable');
  tbody.innerHTML = '';
  
  if (paginatedSubjects.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center py-4">
          <i class="fas fa-info-circle me-2"></i>Nenhuma disciplina encontrada
        </td>
      </tr>
    `;
    return;
  }
  
  paginatedSubjects.forEach(subject => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${subject.id}</td>
      <td>${subject.name}</td>
      <td>${subject.code}</td>
      <td>${subject.credits}</td>
      <td>
        <span class="${subject.is_active ? 'status-active' : 'status-inactive'}">
          <i class="fas fa-${subject.is_active ? 'check-circle' : 'times-circle'} me-1"></i>
          ${subject.is_active ? 'Ativo' : 'Inativo'}
        </span>
      </td>
      <td>
        <div class="action-buttons">
          <button class="btn btn-curso-primary btn-sm" onclick="editSubject(${subject.id})">
            <i class="fas fa-edit"></i>
          </button>
          <button class="btn btn-delete btn-sm" onclick="confirmDelete(${subject.id})">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function updatePagination() {
  const totalPages = Math.ceil(subjects.length / itemsPerPage);
  const pagination = document.getElementById('pagination');
  pagination.innerHTML = '';
  
  if (totalPages <= 1) return;
  
  const prevLi = document.createElement('li');
  prevLi.className = `page-item ${currentPage === 1 ? 'disabled' : ''}`;
  prevLi.innerHTML = `
    <a class="page-link" href="#" aria-label="Anterior" onclick="changePage(${currentPage - 1})">
      <span aria-hidden="true">&laquo;</span>
    </a>
  `;
  pagination.appendChild(prevLi);
  
  for (let i = 1; i <= totalPages; i++) {
    const li = document.createElement('li');
    li.className = `page-item ${currentPage === i ? 'active' : ''}`;
    li.innerHTML = `<a class="page-link" href="#" onclick="changePage(${i})">${i}</a>`;
    pagination.appendChild(li);
  }
  
  const nextLi = document.createElement('li');
  nextLi.className = `page-item ${currentPage === totalPages ? 'disabled' : ''}`;
  nextLi.innerHTML = `
    <a class="page-link" href="#" aria-label="Próximo" onclick="changePage(${currentPage + 1})">
      <span aria-hidden="true">&raquo;</span>
    </a>
  `;
  pagination.appendChild(nextLi);
}

function updateCounters() {
  const totalCount = subjects.length;
  const start = (currentPage - 1) * itemsPerPage + 1;
  const end = Math.min(start + itemsPerPage - 1, totalCount);
  
  document.getElementById('totalSubjects').textContent = `${totalCount} disciplina${totalCount !== 1 ? 's' : ''}`;
  document.getElementById('showingCount').textContent = totalCount > 0 ? `${start}-${end}` : '0';
  document.getElementById('totalCount').textContent = totalCount;
}

function changePage(page) {
  if (page < 1 || page > Math.ceil(subjects.length / itemsPerPage)) return;
  currentPage = page;
  updateSubjectsTable();
  updatePagination();
}

async function addSubject() {
  const name = document.getElementById('subjectName').value.trim();
  const code = document.getElementById('subjectCode').value.trim();
  const credits = parseInt(document.getElementById('subjectCredits').value);
  const is_active = document.getElementById('subjectStatus').value === 'true';
  const description = document.getElementById('subjectDescription').value.trim();
  
  if (!name || !code) {
    showError('Nome e código são obrigatórios');
    return;
  }
  
  try {
    const response = await fetch('/subjects', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name,
        code,
        credits,
        is_active,
        description
      })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Erro ao adicionar disciplina');
    }
    
    const subject = await response.json();
    subjects.unshift(subject);
    
    const modal = bootstrap.Modal.getInstance(document.getElementById('addSubjectModal'));
    modal.hide();
    
    document.getElementById('subjectForm').reset();
    updateSubjectsTable();
    updatePagination();
    updateCounters();
    
    showSuccess('Disciplina adicionada com sucesso');
  } catch (error) {
    console.error('Erro:', error);
    showError(error.message);
  }
}

async function editSubject(id) {
  try {
    const response = await fetch(`/subjects/${id}`);
    if (!response.ok) throw new Error('Erro ao carregar disciplina');
    
    const subject = await response.json();
    
    document.getElementById('editSubjectId').value = subject.id;
    document.getElementById('editSubjectName').value = subject.name;
    document.getElementById('editSubjectCode').value = subject.code;
    document.getElementById('editSubjectCredits').value = subject.credits;
    document.getElementById('editSubjectStatus').value = subject.is_active;
    document.getElementById('editSubjectDescription').value = subject.description || '';
    
    const modal = new bootstrap.Modal(document.getElementById('editSubjectModal'));
    modal.show();
  } catch (error) {
    console.error('Erro:', error);
    showError('Erro ao carregar disciplina');
  }
}

async function updateSubject() {
  const id = document.getElementById('editSubjectId').value;
  const name = document.getElementById('editSubjectName').value.trim();
  const code = document.getElementById('editSubjectCode').value.trim();
  const credits = parseInt(document.getElementById('editSubjectCredits').value);
  const is_active = document.getElementById('editSubjectStatus').value === 'true';
  const description = document.getElementById('editSubjectDescription').value.trim();
  
  if (!name || !code) {
    showError('Nome e código são obrigatórios');
    return;
  }
  
  try {
    const response = await fetch(`/subjects/${id}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name,
        code,
        credits,
        is_active,
        description
      })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Erro ao atualizar disciplina');
    }
    
    const updatedSubject = await response.json();
    const index = subjects.findIndex(s => s.id === updatedSubject.id);
    if (index !== -1) {
      subjects[index] = updatedSubject;
    }
    
    const modal = bootstrap.Modal.getInstance(document.getElementById('editSubjectModal'));
    modal.hide();
    
    updateSubjectsTable();
    showSuccess('Disciplina atualizada com sucesso');
  } catch (error) {
    console.error('Erro:', error);
    showError(error.message);
  }
}

// Função para confirmar exclusão
function confirmDelete(id) {
  document.getElementById('confirmActionBtn').onclick = () => deleteSubject(id);
  const modal = new bootstrap.Modal(document.getElementById('confirmModal'));
  modal.show();
}

// Função para excluir uma disciplina
async function deleteSubject(id) {
  try {
    const response = await fetch(`/subjects/${id}`, {
      method: 'DELETE'
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Erro ao excluir disciplina');
    }
    
    subjects = subjects.filter(s => s.id !== id);
    
    const modal = bootstrap.Modal.getInstance(document.getElementById('confirmModal'));
    modal.hide();
    
    updateSubjectsTable();
    updatePagination();
    updateCounters();
    
    showSuccess('Disciplina excluída com sucesso');
  } catch (error) {
    console.error('Erro:', error);
    showError(error.message);
  }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  loadSubjects();
  
  document.getElementById('saveSubjectBtn').addEventListener('click', addSubject);
  document.getElementById('updateSubjectBtn').addEventListener('click', updateSubject);
  
  // Logout
  document.getElementById('logoutBtn').addEventListener('click', () => {
    localStorage.removeItem('token');
    window.location.href = '/login';
  });
}); 