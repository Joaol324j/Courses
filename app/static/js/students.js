let studentsData = [];
let currentPage = 1;
const itemsPerPage = 10;
let currentEditId = null;
let confirmCallback = null;

document.addEventListener("DOMContentLoaded", function () {
  checkAuth();
  setupEventListeners();

  fetchStudents();

  setupMasks();
});

function checkAuth() {
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "/login";
  }
}

function setupMasks() {
  const phoneInput = document.getElementById("studentPhone");
  phoneInput.addEventListener("input", function (e) {
    const value = e.target.value.replace(/\D/g, "");
    if (value.length > 10) {
      e.target.value = `(${value.substring(0, 2)}) ${value.substring(
        2,
        7
      )}-${value.substring(7, 11)}`;
    } else if (value.length > 2) {
      e.target.value = `(${value.substring(0, 2)}) ${value.substring(
        2,
        6
      )}-${value.substring(6, 10)}`;
    } else if (value.length > 0) {
      e.target.value = `(${value}`;
    }
  });

  const cpfInput = document.getElementById("studentCpf");
  cpfInput.addEventListener("input", function (e) {
    const value = e.target.value.replace(/\D/g, "");
    if (value.length > 9) {
      e.target.value = `${value.substring(0, 3)}.${value.substring(
        3,
        6
      )}.${value.substring(6, 9)}-${value.substring(9, 11)}`;
    } else if (value.length > 6) {
      e.target.value = `${value.substring(0, 3)}.${value.substring(
        3,
        6
      )}.${value.substring(6)}`;
    } else if (value.length > 3) {
      e.target.value = `${value.substring(0, 3)}.${value.substring(3)}`;
    }
  });
}

function setupEventListeners() {
  document.getElementById("logoutBtn").addEventListener("click", logout);

  document
    .getElementById("saveStudentBtn")
    .addEventListener("click", addStudent);

  document
    .getElementById("updateStudentBtn")
    .addEventListener("click", updateStudent);

  document
    .getElementById("confirmActionBtn")
    .addEventListener("click", function () {
      if (confirmCallback) confirmCallback();
    });

  const modals = ["addStudentModal", "editStudentModal", "confirmModal"];
  modals.forEach((modalId) => {
    const modal = document.getElementById(modalId);
    modal.addEventListener("hidden.bs.modal", function () {
      if (modalId === "addStudentModal") {
        document.getElementById("studentForm").reset();
      }
    });
  });
}

async function fetchStudents() {
  try {
    showLoading(true);
    const token = localStorage.getItem("token");
    const response = await fetch("/alunos/", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.ok) {
      studentsData = await response.json();
      renderStudentsTable();
      updatePagination();
    } else if (response.status === 401) {
      logout();
    } else {
      showAlert("Erro ao carregar alunos", "danger");
    }
  } catch (error) {
    showAlert("Erro de conexão com o servidor", "danger");
    console.error("Erro ao buscar alunos:", error);
  } finally {
    showLoading(false);
  }
}

function showLoading(show) {
  const loadingElement = document.getElementById("loadingIndicator");
  if (show) {
    if (!loadingElement) {
      const loader = document.createElement("div");
      loader.id = "loadingIndicator";
      loader.className =
        "position-fixed top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center";
      loader.style.backgroundColor = "rgba(255, 255, 255, 0.7)";
      loader.style.zIndex = "9999";
      loader.innerHTML = `
                  <div class="spinner-border text-primary" role="status">
                      <span class="visually-hidden">Carregando...</span>
                  </div>
              `;
      document.body.appendChild(loader);
    }
  } else {
    if (loadingElement) {
      loadingElement.remove();
    }
  }
}

function renderStudentsTable(page = 1) {
  currentPage = page;
  const startIndex = (page - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedData = studentsData.slice(startIndex, endIndex);

  const tableBody = document.getElementById("studentsTable");
  tableBody.innerHTML = "";

  // Atualiza o contador
  const countElement = document.getElementById("totalStudents");
  if (studentsData.length === 0) {
    countElement.textContent = 'Nenhum aluno';
  } else if (studentsData.length === 1) {
    countElement.textContent = '1 aluno';
  } else {
    countElement.textContent = `${studentsData.length} alunos`;
  }

  if (paginatedData.length === 0) {
    tableBody.innerHTML = `
              <tr>
                  <td colspan="7" class="text-center py-4">Nenhum aluno cadastrado</td>
              </tr>
          `;
    return;
  }
  
  paginatedData.forEach((student, index) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${startIndex + index + 1}</td>
      <td>
        <div class="d-flex align-items-center">
          <div style="
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            width: 36px !important;
            height: 36px !important;
            border-radius: 50% !important;
            background-color: #4361ee !important;
            color: white !important;
            font-weight: bold !important;
            margin-right: 12px !important;
            font-size: 16px !important;
          ">${student.name.charAt(0).toUpperCase()}</div>
          <div>
            <div class="fw-semibold">${escapeHtml(student.name)}</div>
            <small class="text-muted">ID: ${student.id}</small>
          </div>
        </div>
      </td>
      <td>${escapeHtml(student.email)}</td>
      <td>${student.phone ? formatPhone(escapeHtml(student.phone)) : "-"}</td>
      <td class="text-center">
        <span style="
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            padding: 4px 12px !important;
            border-radius: 50px !important;
            font-size: 0.8rem !important;
            font-weight: 500 !important;
            background-color: ${student.status === 'active' ? 'rgba(240, 255, 243, 0.1)' : 'rgba(108, 117, 125, 0.1)'} !important;
            color: ${student.status === 'active' ? '#28a745' : '#6c757d'} !important;
        ">
            ${student.status === 'active' ? 'Ativo' : 'Ativo'}
        </span>
      </td>
      <td class="text-center">
        <div class="action-buttons">
          <button class="btn btn-sm btn-curso-outline" 
                  onclick="openEditModal(${student.id})" 
                  title="Editar">
            <i class="fas fa-edit"></i>
          </button>
          <button class="btn btn-sm btn-delete" 
                  onclick="confirmDelete(${student.id})" 
                  title="Excluir">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      </td>
    `;
    tableBody.appendChild(row);
});

  document.getElementById("totalCount").textContent = studentsData.length;
  document.getElementById("showingCount").textContent = `${startIndex + 1}-${Math.min(endIndex, studentsData.length)}`;
}

function updatePagination() {
  const totalPages = Math.ceil(studentsData.length / itemsPerPage);
  const pagination = document.getElementById("pagination");
  pagination.innerHTML = "";

  if (totalPages <= 1) return;

  const prevLi = document.createElement("li");
  prevLi.className = `page-item ${currentPage === 1 ? "disabled" : ""}`;
  prevLi.innerHTML = `
          <a class="page-link" href="#" onclick="changePage(${
            currentPage - 1
          })">Anterior</a>
      `;
  pagination.appendChild(prevLi);

  for (let i = 1; i <= totalPages; i++) {
    const pageLi = document.createElement("li");
    pageLi.className = `page-item ${i === currentPage ? "active" : ""}`;
    pageLi.innerHTML = `
              <a class="page-link" href="#" onclick="changePage(${i})">${i}</a>
          `;
    pagination.appendChild(pageLi);
  }

  const nextLi = document.createElement("li");
  nextLi.className = `page-item ${
    currentPage === totalPages ? "disabled" : ""
  }`;
  nextLi.innerHTML = `
          <a class="page-link" href="#" onclick="changePage(${
            currentPage + 1
          })">Próximo</a>
      `;
  pagination.appendChild(nextLi);
}

function changePage(page) {
  if (page < 1 || page > Math.ceil(studentsData.length / itemsPerPage))
    return;
  renderStudentsTable(page);
}

async function addStudent() {
  const name = document.getElementById("studentName").value.trim();
  const email = document.getElementById("studentEmail").value.trim();
  const phone = document
    .getElementById("studentPhone")
    .value.replace(/\D/g, "");
  const birthDate = document.getElementById("studentBirthDate").value;
  const cpf = document
    .getElementById("studentCpf")
    .value.replace(/\D/g, "");
  const status = document.getElementById("studentStatus").value;

  if (!name || !email) {
    showAlert("Nome e e-mail são obrigatórios", "warning");
    return;
  }

  const studentData = {
    name,
    email,
    phone: phone || null,
    birth_date: birthDate || null,
    cpf: cpf || null,
    status,
  };

  try {
    showLoading(true);
    const token = localStorage.getItem("token");
    const response = await fetch("/alunos/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(studentData),
    });

    if (response.ok) {
      const modal = bootstrap.Modal.getInstance(
        document.getElementById("addStudentModal")
      );
      modal.hide();

      showAlert("Aluno cadastrado com sucesso!", "success");
      fetchStudents();
    } else {
      const error = await response.json();
      showAlert(error.detail || "Erro ao cadastrar aluno", "danger");
    }
  } catch (error) {
    showAlert("Erro de conexão com o servidor", "danger");
    console.error("Erro ao salvar aluno:", error);
  } finally {
    showLoading(false);
  }
}

async function openEditModal(studentId) {
  try {
    showLoading(true);
    const token = localStorage.getItem("token");
    const response = await fetch(`/alunos/${studentId}`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.ok) {
      const student = await response.json();

      document.getElementById("editStudentId").value = student.id;
      document.getElementById("editStudentName").value = student.name;
      document.getElementById("editStudentEmail").value = student.email;
      document.getElementById("editStudentPhone").value =
        student.phone || "";
      document.getElementById("editStudentBirthDate").value =
        student.birth_date || "";
      document.getElementById("editStudentCpf").value = student.cpf || "";
      document.getElementById("editStudentStatus").value =
        student.status || "active";

      const modal = new bootstrap.Modal(
        document.getElementById("editStudentModal")
      );
      modal.show();
    } else {
      showAlert("Erro ao carregar dados do aluno", "danger");
    }
  } catch (error) {
    showAlert("Erro de conexão com o servidor", "danger");
    console.error("Erro ao editar aluno:", error);
  } finally {
    showLoading(false);
  }
}

async function updateStudent() {
  const id = document.getElementById("editStudentId").value;
  const name = document.getElementById("editStudentName").value.trim();
  const email = document.getElementById("editStudentEmail").value.trim();
  const phone = document
    .getElementById("editStudentPhone")
    .value.replace(/\D/g, "");
  const birthDate = document.getElementById("editStudentBirthDate").value;
  const cpf = document
    .getElementById("editStudentCpf")
    .value.replace(/\D/g, "");
  const status = document.getElementById("editStudentStatus").value;

  if (!name || !email) {
    showAlert("Nome e e-mail são obrigatórios", "warning");
    return;
  }

  const studentData = {
    name,
    email,
    phone: phone || null,
    birth_date: birthDate || null,
    cpf: cpf || null,
    status,
  };

  try {
    showLoading(true);
    const token = localStorage.getItem("token");
    const response = await fetch(`/alunos/${id}`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(studentData),
    });

    if (response.ok) {
      const modal = bootstrap.Modal.getInstance(
        document.getElementById("editStudentModal")
      );
      modal.hide();

      showAlert("Aluno atualizado com sucesso!", "success");
      fetchStudents();
    } else {
      const error = await response.json();
      showAlert(error.detail || "Erro ao atualizar aluno", "danger");
    }
  } catch (error) {
    showAlert("Erro de conexão com o servidor", "danger");
    console.error("Erro ao atualizar aluno:", error);
  } finally {
    showLoading(false);
  }
}

function confirmDelete(studentId) {
  currentEditId = studentId;
  confirmCallback = deleteStudent;

  document.getElementById("confirmModalTitle").textContent =
    "Confirmar Exclusão";
  document.getElementById("confirmModalBody").textContent =
    "Tem certeza que deseja excluir este aluno? Esta ação não pode ser desfeita.";
  document.getElementById("confirmActionBtn").className =
    "btn btn-danger";

  const modal = new bootstrap.Modal(
    document.getElementById("confirmModal")
  );
  modal.show();
}

async function deleteStudent() {
  try {
    showLoading(true);
    const token = localStorage.getItem("token");
    const response = await fetch(`/alunos/${currentEditId}`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.ok) {
      showAlert("Aluno excluído com sucesso", "success");
      fetchStudents();

      const modal = bootstrap.Modal.getInstance(
        document.getElementById("confirmModal")
      );
      modal.hide();
    } else {
      const error = await response.json();
      showAlert(error.detail || "Erro ao excluir aluno", "danger");
    }
  } catch (error) {
    showAlert("Erro de conexão com o servidor", "danger");
    console.error("Erro ao excluir aluno:", error);
  } finally {
    showLoading(false);
  }
}

function showAlert(message, type) {
  const existingAlerts = document.querySelectorAll(".alert-curso");
  existingAlerts.forEach((alert) => alert.remove());

  const alertDiv = document.createElement("div");
  alertDiv.className = `alert-curso alert-${type} alert-dismissible fade show`;
  alertDiv.role = "alert";
  alertDiv.innerHTML = `
          <div class="d-flex align-items-center">
              <i class="fas ${
                type === "success"
                  ? "fa-check-circle"
                  : type === "warning"
                  ? "fa-exclamation-triangle"
                  : "fa-times-circle"
              } me-2"></i>
              <div>${message}</div>
              <button type="button" class="btn-close ms-auto" data-bs-dismiss="alert" aria-label="Close"></button>
          </div>
      `;

  const container = document.querySelector(".main-container .container");
  container.prepend(alertDiv);

  setTimeout(() => {
    alertDiv.classList.remove("show");
    setTimeout(() => alertDiv.remove(), 150);
  }, 5000);
}

function logout() {
  localStorage.removeItem("token");
  window.location.href = "/login";
}

function escapeHtml(unsafe) {
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
window.openEditModal = openEditModal;
window.confirmDelete = confirmDelete;