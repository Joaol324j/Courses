   let currentEditId = null;
   let deleteTeacherId = null;
   let currentPage = 1;
   const itemsPerPage = 10;
   let teachersData = [];

   document.addEventListener('DOMContentLoaded', function() {
     checkAuth();
     fetchTeachers();
     
     document.getElementById('teacherForm').addEventListener('submit', function(e) {
       e.preventDefault();
       handleSubmit(false);
     });
     
     document.getElementById('editTeacherForm').addEventListener('submit', function(e) {
       e.preventDefault();
       handleSubmit(true);
     });
     
     document.getElementById('confirmDelete').addEventListener('click', function() {
       if (deleteTeacherId) {
         deleteTeacher(deleteTeacherId);
       }
     });
     
     document.getElementById("logoutBtn").addEventListener("click", logout);
   });

   function checkAuth() {
     const token = localStorage.getItem("token");
     if (!token) {
       window.location.href = "/login";
     }
   }

   function logout() {
     localStorage.removeItem("token");
     window.location.href = "/login";
   }

   async function fetchTeachers() {
     try {
       const token = localStorage.getItem("token");
       const response = await fetch('/professores/', {
         headers: {
           Authorization: `Bearer ${token}`,
         },
       });
       
       if (response.ok) {
         teachersData = await response.json();
         renderTeachers(currentPage);
         updatePagination();
       } else if (response.status === 401) {
         logout();
       } else {
         showError('Erro ao carregar professores');
       }
     } catch (error) {
       showError('Erro ao conectar ao servidor');
     }
   }

   function updatePagination() {
     const totalPages = Math.ceil(teachersData.length / itemsPerPage);
     const pagination = document.getElementById('pagination');
     pagination.innerHTML = '';

     if (totalPages <= 1) return;

     const prevLi = document.createElement('li');
     prevLi.className = `page-item ${currentPage === 1 ? 'disabled' : ''}`;
     prevLi.innerHTML = `
       <a class="page-link" href="#" onclick="changePage(${currentPage - 1})">Anterior</a>
     `;
     pagination.appendChild(prevLi);

     for (let i = 1; i <= totalPages; i++) {
       const pageLi = document.createElement('li');
       pageLi.className = `page-item ${i === currentPage ? 'active' : ''}`;
       pageLi.innerHTML = `
         <a class="page-link" href="#" onclick="changePage(${i})">${i}</a>
       `;
       pagination.appendChild(pageLi);
     }

     // Botão Próximo
     const nextLi = document.createElement('li');
     nextLi.className = `page-item ${currentPage === totalPages ? 'disabled' : ''}`;
     nextLi.innerHTML = `
       <a class="page-link" href="#" onclick="changePage(${currentPage + 1})">Próximo</a>
     `;
     pagination.appendChild(nextLi);
   }

   function changePage(page) {
     if (page < 1 || page > Math.ceil(teachersData.length / itemsPerPage)) return;
     currentPage = page;
     renderTeachers(page);
   }

   async function handleSubmit(isEdit) {
     const modalId = isEdit ? 'editTeacherModal' : 'addTeacherModal';
     const modal = bootstrap.Modal.getInstance(document.getElementById(modalId));
     
     const name = isEdit ? document.getElementById('editName').value : document.getElementById('name').value;
     const email = isEdit ? document.getElementById('editEmail').value : document.getElementById('email').value;
     const phone = isEdit ? document.getElementById('editPhone').value : document.getElementById('phone').value;
     const specialty = isEdit ? document.getElementById('editSpecialty').value : document.getElementById('specialty').value;

     if (!name || !email) {
       showError('Nome e email são obrigatórios!');
       return;
     }

     const formData = new FormData();
     formData.append('name', name);
     formData.append('email', email);
     formData.append('phone', phone);
     formData.append('specialty', specialty);

     try {
       const token = localStorage.getItem("token");
       if (isEdit) {
         await updateTeacher(currentEditId, formData, token);
       } else {
         await addTeacher(formData, token);
       }
       
       if (modal) modal.hide();
     } catch (error) {
       showError('Erro ao salvar professor');
     }
   }

   async function addTeacher(formData, token) {
     const response = await fetch('/professores/?' + new URLSearchParams(formData), {
       method: 'POST',
       headers: {
         Authorization: `Bearer ${token}`,
       },
     });

     if (response.ok) {
       fetchTeachers();
       clearForm('teacherForm');
     } else {
       const error = await response.json();
       showError(error.detail || 'Erro ao adicionar professor');
     }
   }

   async function updateTeacher(id, formData, token) {
     const response = await fetch(`/professores/${id}?` + new URLSearchParams(formData), {
       method: 'PUT',
       headers: {
         Authorization: `Bearer ${token}`,
       },
     });

     if (response.ok) {
       fetchTeachers();
       clearForm('editTeacherForm');
     } else {
       const error = await response.json();
       showError(error.detail || 'Erro ao atualizar professor');
     }
   }

   function renderTeachers(page = 1) {
     currentPage = page;
     const startIndex = (page - 1) * itemsPerPage;
     const endIndex = startIndex + itemsPerPage;
     const paginatedData = teachersData.slice(startIndex, endIndex);

     const tbody = document.getElementById('teachersTableBody');
     tbody.innerHTML = '';
     
     document.getElementById('totalCount').textContent = teachersData.length;
     document.getElementById('showingCount').textContent = `${startIndex + 1}-${Math.min(endIndex, teachersData.length)}`;
     
     const countElement = document.getElementById('teacherCount');
     if (teachersData.length === 0) {
       countElement.textContent = 'Nenhum professor';
       tbody.innerHTML = `
         <tr>
           <td colspan="5" class="text-center py-4">Nenhum professor cadastrado</td>
         </tr>
       `;
       return;
     } else if (teachersData.length === 1) {
       countElement.textContent = '1 professor';
     } else {
       countElement.textContent = `${teachersData.length} professores`;
     }
     
     paginatedData.forEach(teacher => {
       const row = document.createElement('tr');
       row.innerHTML = `
         <td>
           <div class="d-flex align-items-center">
             <div class="avatar-curso me-3">
               ${teacher.name.charAt(0).toUpperCase()}
             </div>
             <div>
               <div class="fw-semibold">${escapeHtml(teacher.name)}</div>
               <small class="text-muted">ID: ${teacher.id}</small>
             </div>
           </div>
         </td>
         <td>${escapeHtml(teacher.email)}</td>
         <td>${teacher.phone ? formatPhone(escapeHtml(teacher.phone)) : '-'}</td>
         <td>${teacher.specialty ? escapeHtml(teacher.specialty) : '-'}</td>
         <td>
           <button onclick="openEditModal(${teacher.id}, '${escapeHtml(teacher.name)}', '${escapeHtml(teacher.email)}', '${teacher.phone ? escapeHtml(teacher.phone) : ''}', '${teacher.specialty ? escapeHtml(teacher.specialty) : ''}')" 
                   class="btn btn-sm btn-outline-primary action-btn me-2">
             <i class="fas fa-edit"></i>
           </button>
           <button onclick="openDeleteModal(${teacher.id})" 
                   class="btn btn-sm btn-outline-danger action-btn">
             <i class="fas fa-trash"></i>
           </button>
         </td>
       `;
       tbody.appendChild(row);
     });
   }

   function openEditModal(id, name, email, phone, specialty) {
     currentEditId = id;
     document.getElementById('editId').value = id;
     document.getElementById('editName').value = name;
     document.getElementById('editEmail').value = email;
     document.getElementById('editPhone').value = phone || '';
     document.getElementById('editSpecialty').value = specialty || '';
     
     const modal = new bootstrap.Modal(document.getElementById('editTeacherModal'));
     modal.show();
   }

   function openDeleteModal(id) {
     deleteTeacherId = id;
     const modal = new bootstrap.Modal(document.getElementById('deleteTeacherModal'));
     modal.show();
   }

   async function deleteTeacher(id) {
     try {
       const token = localStorage.getItem("token");
       const response = await fetch(`/professores/${id}`, {
         method: 'DELETE',
         headers: {
           Authorization: `Bearer ${token}`,
         },
       });

       if (response.ok) {
         fetchTeachers();
         const modal = bootstrap.Modal.getInstance(document.getElementById('deleteTeacherModal'));
         if (modal) modal.hide();
       } else {
         const error = await response.json();
         showError(error.detail || 'Erro ao excluir professor');
       }
     } catch (error) {
       showError('Erro ao excluir professor');
     } finally {
       deleteTeacherId = null;
     }
   }

   function clearForm(formId) {
     document.getElementById(formId).reset();
   }

   function showError(message) {
     const errorDiv = document.getElementById('error');
     errorDiv.textContent = message;
     errorDiv.style.display = 'block';
     setTimeout(() => {
       errorDiv.style.display = 'none';
     }, 3000);
   }

   function escapeHtml(unsafe) {
     if (!unsafe) return '';
     return unsafe
       .replace(/&/g, "&amp;")
       .replace(/</g, "&lt;")
       .replace(/>/g, "&gt;")
       .replace(/"/g, "&quot;")
       .replace(/'/g, "&#039;");
   }

   function formatPhone(phone) {
     const cleaned = phone.replace(/\D/g, "");
     const match = cleaned.match(/^(\d{2})(\d{4,5})(\d{4})$/);
     if (match) {
       return `(${match[1]}) ${match[2]}-${match[3]}`;
     }
     return phone;
   }

   window.changePage = changePage;