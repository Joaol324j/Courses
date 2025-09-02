# 🎓 FastAPI Educational Management System

## 📌 Project Overview

This **FastAPI-based educational platform** provides a complete solution for managing courses, students, teachers, and enrollments with robust JWT authentication. The system features a clean architecture following repository pattern and modern Python practices.

## 🌟 Key Features

- **JWT Authentication**: Secure user registration/login system with password recovery
- **Comprehensive CRUD Operations**:
  - Courses management
  - Students system (student_id based)
  - Enrollment tracking
- **Production-ready architecture** with Docker support
- **Automated testing** infrastructure
- **Swagger UI** for interactive API documentation

## 🏗️ Project Structure

```
.
├── app/
│   ├── config/               # Configuration files
│   ├── core/                 # Core utilities and middleware
│   ├── database/             # Database connection and setup
│   ├── models/               # SQLAlchemy data models
│   ├── repositories/         # Data access layer
│   ├── routes/               # API endpoints
│   │   ├── auth.py           # Authentication routes
│   │   ├── cursos.py         # Course management
│   │   ├── alunos.py         # Student operations
│   │   └── matriculas.py     # Enrollment system
│   ├── schemas/              # Pydantic validation schemas
│   ├── services/             # Business logic layer
│   ├── static/               # Static files
│   └── utils/                # Helper functions
├── tests/                    # Test suite
├── .env                      # Environment variables
├── docker-compose.yml        # Docker orchestration
├── Dockerfile                # Docker configuration
└── README.md                 # Project documentation
```

## 🛠️ Technology Stack

- **Python 3.10+** with FastAPI framework
- **SQLAlchemy** ORM with PostgreSQL/SQLite
- **JWT** for secure authentication
- **Pydantic** for data validation
- **Docker** for containerization
- **Swagger UI** for interactive documentation

## 🚀 Quick Start

### With Docker (Recommended)

```bash
docker-compose up --build
```

Access the API at `http://localhost:8000` and interactive docs at `http://localhost:8000/docs`

### Local Development

1. Create and activate virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   .\venv\Scripts\activate   # Windows
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment:
   ```bash
   cp .env.example .env
   ```

4. Run application:
   ```bash
   uvicorn main:app --reload
   ```

## 🔐 Authentication Endpoints

| Endpoint                 | Method | Description                  | Request Body Example               |
|--------------------------|--------|------------------------------|------------------------------------|
| `/auth/register`         | POST   | User registration            | `{"username":"user1","password":"pass123","email":"user@example.com"}` |
| `/auth/token`            | POST   | Login to get JWT             | `{"username":"user1","password":"pass123"}` |
| `/auth/password-recovery`| POST   | Initiate password recovery   | `{"email":"user@example.com"}` |
| `/auth/reset-password`   | POST   | Reset password               | `{"token":"...","new_password":"newpass123"}` |

## 📚 Course Management

| Endpoint              | Method | Description                  | Protected |
|-----------------------|--------|------------------------------|-----------|
| `/cursos/`            | GET    | List all courses             | No        |
| `/cursos/`            | POST   | Create new course            | Yes       |
| `/cursos/{course_id}` | GET    | Get course details           | No        |
| `/cursos/{course_id}` | PUT    | Update course                | Yes       |
| `/cursos/{course_id}` | DELETE | Delete course                | Yes       |

## 👨‍🎓 Student Management

| Endpoint               | Method | Description                  | Protected |
|------------------------|--------|------------------------------|-----------|
| `/alunos/`             | GET    | List all students            | Yes       |
| `/alunos/`             | POST   | Create new student           | Yes       |
| `/alunos/{student_id}` | GET    | Get student details          | Yes       |
| `/alunos/{student_id}` | PUT    | Update student               | Yes       |
| `/alunos/{student_id}` | DELETE | Delete student               | Yes       |

## 🧑‍🏫 Teacher Management

| Endpoint               | Method | Description                  | Protected |
|------------------------|--------|------------------------------|-----------|
| `/professores/`             | GET    | List all teacher           | Yes       |
| `/professores/`             | POST   | Create new teacher           | Yes       |
| `/professores/{teacher_id}` | GET    | Get teacher details          | Yes       |
| `/professores/{teacher_id}` | PUT    | Update teacher               | Yes       |
| `/professores/{teacher_id}` | DELETE | Delete teacher               | Yes       |


## 📝 Enrollment System

| Endpoint                   | Method | Description                  | Protected |
|----------------------------|--------|------------------------------|-----------|
| `/matriculas/`             | GET    | List all enrollments         | Yes       |
| `/matriculas/`             | POST   | Create new enrollment        | Yes       |
| `/matriculas/{enrollment_id}` | GET | Get enrollment details   | Yes       |
| `/matriculas/{enrollment_id}` | PUT | Update enrollment        | Yes       |
| `/matriculas/{enrollment_id}` | DELETE | Delete enrollment        | Yes       |


## 📘 Discipline System

| Endpoint                   | Method | Description                  | Protected |
|----------------------------|--------|------------------------------|-----------|
| `/subjects/`             | GET    | List all subjects         | Yes       |
| `/subjects/`             | POST   | Create new subject        | Yes       |
| `/subjects/{subjec_id}` | GET | Get subject details   | Yes       |
| `/subjects/{subject_id}` | PUT | Update subject      | Yes       |
| `/subjects/{subject_id}` | DELETE | Delete subject       | Yes       |


## 🧪 Testing the API

1. First register a user:
   ```http
   POST /auth/register
   Content-Type: application/json

   {
     "username": "testuser",
     "password": "testpass123",
     "email": "test@example.com"
   }
   ```

2. Login to get JWT token:
   ```http
   POST /auth/token
   Content-Type: application/json

   {
     "username": "testuser",
     "password": "testpass123"
   }
   ```

3. Use the token in Authorization header:
   ```
   Authorization: Bearer <your_jwt_token>
   ```

4. Test protected endpoints like creating a course:
   ```http
   POST /cursos/
   Authorization: Bearer <your_jwt_token>
   Content-Type: application/json

   {
     "title": "Advanced Python",
     "description": "Deep dive into Python",
     "duration": 40
   }
   ```

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Contact

For questions or support, please contact:  
**Wesnei Paiva**  
📧 [wesneipaiva@gmail.com](mailto:wesneipaiva@gmail.com)  
🔗 [API Documentation](http://localhost:8000/docs) 
