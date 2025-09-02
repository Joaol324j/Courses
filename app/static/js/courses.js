let coursesData = [];
let currentPage = 1;
const itemsPerPage = 10;
let currentEditId = null;
let confirmCallback = null;

function checkAuth() {
    const token = localStorage.getItem("token");
    if (!token) {
        window.location.href = "/login";
    }
}

function setupEventListeners() {
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", logout);
    }

    const saveCourseBtn = document.getElementById("saveCourseBtn");
    if (saveCourseBtn) {
        saveCourseBtn.addEventListener("click", addCourse);
    }

    const updateCourseBtn = document.getElementById("updateCourseBtn");
    if (updateCourseBtn) {
        updateCourseBtn.addEventListener("click", updateCourse);
    }

    const confirmActionBtn = document.getElementById("confirmActionBtn");
    if (confirmActionBtn) {
        confirmActionBtn.addEventListener("click", function () {
            if (confirmCallback) confirmCallback();
        });
    }

    const modals = ["addCourseModal", "editCourseModal", "confirmModal"];
    modals.forEach((modalId) => {
        const modalElement = document.getElementById(modalId);
        if (modalElement) {
            modalElement.addEventListener("hidden.bs.modal", function () {
                if (modalId === "addCourseModal") {
                    const courseForm = document.getElementById("courseForm");
                    if (courseForm) courseForm.reset();
                }
            });
        }
    });
}

function showLoading(show) {
    if (show) {
        const existingLoader = document.getElementById("loadingIndicator");
        if (!existingLoader) {
            const loader = document.createElement("div");
            loader.id = "loadingIndicator";
            loader.className = "position-fixed top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center";
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
        const loader = document.getElementById("loadingIndicator");
        if (loader) loader.remove();
    }
}

async function fetchCourses() {
    try {
        showLoading(true);
        const token = localStorage.getItem("token");
        const response = await fetch("/cursos/", {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        });

        if (response.ok) {
            coursesData = await response.json();
            renderCoursesTable();
            updatePagination();
        } else if (response.status === 401) {
            logout();
        } else {
            showAlert("Erro ao carregar cursos", "danger");
        }
    } catch (error) {
        showAlert("Erro de conexão com o servidor", "danger");
        console.error("Erro ao buscar cursos:", error);
    } finally {
        showLoading(false);
    }
}

function renderCoursesTable(page = 1) {
    currentPage = page;
    const startIndex = (page - 1) * itemsPerPage;
    const endIndex = startIndex + itemsPerPage;
    const paginatedData = coursesData.slice(startIndex, endIndex);

    const tableBody = document.getElementById("coursesTable");
    if (!tableBody) return;

    tableBody.innerHTML = "";

    if (paginatedData.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="4" class="text-center py-4">Nenhum curso cadastrado</td>
            </tr>
        `;
        return;
    }

    paginatedData.forEach((course) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${escapeHtml(course.name)}</td>
            <td>${escapeHtml(course.description || "-")}</td>
            <td>${course.time}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary action-btn me-2" 
                        onclick="openEditModal(${course.id})" 
                        title="Editar">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="btn btn-sm btn-outline-danger action-btn" 
                        onclick="confirmDelete(${course.id})" 
                        title="Excluir">
                    <i class="fas fa-trash"></i>
                </button>
            </td>
        `;
        tableBody.appendChild(row);
    });

    const totalCoursesElement = document.getElementById("totalCourses");
    if (totalCoursesElement) {
        totalCoursesElement.textContent = `${coursesData.length} cursos`;
    }

    const totalCountElement = document.getElementById("totalCount");
    const showingCountElement = document.getElementById("showingCount");
    if (totalCountElement && showingCountElement) {
        totalCountElement.textContent = coursesData.length;
        showingCountElement.textContent = `${startIndex + 1}-${Math.min(endIndex, coursesData.length)}`;
    }
}

function updatePagination() {
    const totalPages = Math.ceil(coursesData.length / itemsPerPage);
    const pagination = document.getElementById("pagination");
    if (!pagination) return;

    pagination.innerHTML = "";

    if (totalPages <= 1) return;

    const prevLi = document.createElement("li");
    prevLi.className = `page-item ${currentPage === 1 ? "disabled" : ""}`;
    prevLi.innerHTML = `
        <a class="page-link" href="#" onclick="changePage(${currentPage - 1})">Anterior</a>
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
    nextLi.className = `page-item ${currentPage === totalPages ? "disabled" : ""}`;
    nextLi.innerHTML = `
        <a class="page-link" href="#" onclick="changePage(${currentPage + 1})">Próximo</a>
    `;
    pagination.appendChild(nextLi);
}

async function addCourse() {
    const nameInput = document.getElementById("courseName");
    const descriptionInput = document.getElementById("courseDescription");
    const durationInput = document.getElementById("courseDuration");

    if (!nameInput || !durationInput) {
        showAlert("Campos obrigatórios não encontrados", "warning");
        return;
    }

    const name = nameInput.value.trim();
    const description = descriptionInput ? descriptionInput.value.trim() : "";
    const duration = durationInput.value;

    if (!name || !duration) {
        showAlert("Nome e duração são obrigatórios", "warning");
        return;
    }

    const courseData = {
        name,
        description: description || null,
        time: parseInt(duration),
    };

    try {
        showLoading(true);
        const token = localStorage.getItem("token");
        const response = await fetch("/cursos/", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify(courseData),
        });

        if (response.ok) {
            const modalElement = document.getElementById("addCourseModal");
            if (modalElement) {
                const modal = bootstrap.Modal.getInstance(modalElement);
                if (modal) modal.hide();
            }

            showAlert("Curso cadastrado com sucesso!", "success");
            fetchCourses();
        } else {
            const error = await response.json();
            showAlert(error.detail || "Erro ao cadastrar curso", "danger");
        }
    } catch (error) {
        showAlert("Erro de conexão com o servidor", "danger");
        console.error("Erro ao salvar curso:", error);
    } finally {
        showLoading(false);
    }
}

async function openEditModal(courseId) {
    try {
        showLoading(true);
        const token = localStorage.getItem("token");
        const response = await fetch(`/cursos/${courseId}`, {
            headers: {
                Authorization: `Bearer ${token}`,
            },
        });

        if (response.ok) {
            const course = await response.json();

            const editCourseId = document.getElementById("editCourseId");
            const editCourseName = document.getElementById("editCourseName");
            const editCourseDescription = document.getElementById("editCourseDescription");
            const editCourseDuration = document.getElementById("editCourseDuration");

            if (editCourseId && editCourseName && editCourseDuration) {
                editCourseId.value = course.id;
                editCourseName.value = course.name;
                if (editCourseDescription) {
                    editCourseDescription.value = course.description || "";
                }
                editCourseDuration.value = course.time;

                const modalElement = document.getElementById("editCourseModal");
                if (modalElement) {
                    const modal = new bootstrap.Modal(modalElement);
                    modal.show();
                }
            }
        } else {
            showAlert("Erro ao carregar dados do curso", "danger");
        }
    } catch (error) {
        showAlert("Erro de conexão com o servidor", "danger");
        console.error("Erro ao editar curso:", error);
    } finally {
        showLoading(false);
    }
}

async function updateCourse() {
    const editCourseId = document.getElementById("editCourseId");
    const editCourseName = document.getElementById("editCourseName");
    const editCourseDescription = document.getElementById("editCourseDescription");
    const editCourseDuration = document.getElementById("editCourseDuration");

    if (!editCourseId || !editCourseName || !editCourseDuration) {
        showAlert("Campos obrigatórios não encontrados", "warning");
        return;
    }

    const id = editCourseId.value;
    const name = editCourseName.value.trim();
    const description = editCourseDescription ? editCourseDescription.value.trim() : "";
    const duration = editCourseDuration.value;

    if (!name || !duration) {
        showAlert("Nome e duração são obrigatórios", "warning");
        return;
    }

    const courseData = {
        name,
        description: description || null,
        time: parseInt(duration),
    };

    try {
        showLoading(true);
        const token = localStorage.getItem("token");
        const response = await fetch(`/cursos/${id}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify(courseData),
        });

        if (response.ok) {
            const modalElement = document.getElementById("editCourseModal");
            if (modalElement) {
                const modal = bootstrap.Modal.getInstance(modalElement);
                if (modal) modal.hide();
            }

            showAlert("Curso atualizado com sucesso!", "success");
            fetchCourses();
        } else {
            const error = await response.json();
            showAlert(error.detail || "Erro ao atualizar curso", "danger");
        }
    } catch (error) {
        showAlert("Erro de conexão com o servidor", "danger");
        console.error("Erro ao atualizar curso:", error);
    } finally {
        showLoading(false);
    }
}

function confirmDelete(courseId) {
    currentEditId = courseId;
    confirmCallback = deleteCourse;

    const confirmModalTitle = document.getElementById("confirmModalTitle");
    const confirmModalBody = document.getElementById("confirmModalBody");
    const confirmActionBtn = document.getElementById("confirmActionBtn");

    if (confirmModalTitle && confirmModalBody && confirmActionBtn) {
        confirmModalTitle.textContent = "Confirmar Exclusão";
        confirmModalBody.textContent = "Tem certeza que deseja excluir este curso? Esta ação não pode ser desfeita.";
        confirmActionBtn.className = "btn btn-danger";

        const modalElement = document.getElementById("confirmModal");
        if (modalElement) {
            const modal = new bootstrap.Modal(modalElement);
            modal.show();
        }
    }
}

async function deleteCourse() {
    try {
        showLoading(true);
        const token = localStorage.getItem("token");
        const response = await fetch(`/cursos/${currentEditId}`, {
            method: "DELETE",
            headers: {
                Authorization: `Bearer ${token}`,
            },
        });

        if (response.ok) {
            showAlert("Curso excluído com sucesso", "success");
            fetchCourses();

            const modalElement = document.getElementById("confirmModal");
            if (modalElement) {
                const modal = bootstrap.Modal.getInstance(modalElement);
                if (modal) modal.hide();
            }
        } else {
            const error = await response.json();
            showAlert(error.detail || "Erro ao excluir curso", "danger");
        }
    } catch (error) {
        showAlert("Erro de conexão com o servidor", "danger");
        console.error("Erro ao excluir curso:", error);
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
    if (container) {
        container.prepend(alertDiv);

        setTimeout(() => {
            alertDiv.classList.remove("show");
            setTimeout(() => alertDiv.remove(), 150);
        }, 5000);
    }
}

function logout() {
    localStorage.removeItem("token");
    window.location.href = "/login";
}

function escapeHtml(unsafe) {
    if (!unsafe) return "";
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Função para mudar de página
function changePage(page) {
    if (page < 1 || page > Math.ceil(coursesData.length / itemsPerPage)) return;
    renderCoursesTable(page);
}

document.addEventListener("DOMContentLoaded", function () {
    checkAuth();
    setupEventListeners();
    fetchCourses();
});

window.changePage = changePage;
window.openEditModal = openEditModal;
window.confirmDelete = confirmDelete;