# Todo List for Microservices Migration - **FRESH START APPROACH**

**Starting from scratch with proper shared packages architecture from day one.**

---

## 🆕 Phase 0: Fresh Start Setup (Week 1)

### **Clean Slate Preparation**
- [x] **Backup Current Work** *(skipped - not needed)*
  - [x] Create backup branch: `git checkout -b backup-old-implementation`
  - [x] Commit current state: `git add . && git commit -m "Backup before fresh start"`
  - [x] Return to main: `git checkout main`
  
- [x] **Clean Project Structure**
  - [x] Remove all existing Go code (keep only docs)
  - [x] Remove old go.mod files
  - [x] Keep: `toDo.md`, `microservice.md`, `docker-compose.yml` (will update)
  - [x] Remove: all `internal/`, `user-service/`, `cmd/` directories

### **Create Proper Foundation**
- [x] **Initialize Root Module**
  - [x] Create new `go.mod` with valid Go version (1.21)
  - [x] Set up proper module name: `github.com/facuhernandez99/blog`
  - [x] Dependencies will be added when packages are created and import them
  
- [x] **Create Shared Packages Architecture**
  - [x] Create `pkg/` directory structure
  - [x] Create `pkg/models/` - shared data models
  - [x] Create `pkg/auth/` - authentication utilities  
  - [x] Create `pkg/errors/` - custom error types
  - [x] Create `pkg/database/` - database utilities
  - [x] Create `pkg/http/` - HTTP utilities and responses

### **Implement Core Shared Packages**
- [x] **Models Package (`pkg/models/`)**
  - [x] Create `user.go` - User model and request structs
  - [x] Create `common.go` - common types and interfaces
  - [x] Add proper JSON tags and validation rules
  
- [x] **Auth Package (`pkg/auth/`)**
  - [x] Create `password.go` - bcrypt password hashing
  - [x] Create `jwt.go` - JWT token generation/validation
  - [x] Create `middleware.go` - authentication middleware
  
- [x] **Errors Package (`pkg/errors/`)**
  - [x] Create `errors.go` - custom application errors
  - [x] Define user-related errors
  - [x] Create error response helpers
  
- [x] **Database Package (`pkg/database/`)**
  - [x] Create `connection.go` - database connection utilities
  - [x] Create `migration.go` - migration runner utilities
  
- [x] **HTTP Package (`pkg/http/`)**
  - [x] Create `response.go` - standardized API responses
  - [x] Create `client.go` - inter-service HTTP client

### **Test Shared Packages**
- [x] **Compilation Verification**
  - [x] Ensure all packages compile: `go build ./pkg/...`
- [ ] **Unit Tests for Shared Packages**
  - [ ] **Auth Package Tests**
    - [x] `pkg/auth/password_test.go`
      - [x] Test HashPassword() with valid passwords
      - [x] Test HashPassword() with invalid inputs (empty, too long)
      - [x] Test CheckPasswordHash() with correct/incorrect passwords
      - [x] Test ValidatePasswordStrength() with weak/strong passwords
      - [x] Test ValidatePasswordBasic() edge cases
    - [x] `pkg/auth/jwt_test.go`
      - [x] Test GenerateJWT() with valid claims
      - [x] Test ValidateJWT() with valid/expired/malformed tokens
      - [x] Test ValidateJWT() with invalid signatures
      - [x] Test ExtractUserID() and ExtractUsername()
      - [x] Test IsTokenExpired() scenarios
      - [x] Test RefreshToken() functionality
    - [x] `pkg/auth/middleware_test.go`
      - [x] Test AuthMiddleware() with valid/invalid/missing tokens
      - [x] Test OptionalAuthMiddleware() scenarios
      - [x] Test RequireUserID() middleware protection
      - [x] Test context helpers (GetUserID, GetUsername, GetClaims)
      - [x] Test CORSMiddleware() headers
  - [x] **Errors Package Tests**
    - [x] `pkg/errors/errors_test.go`
      - [x] Test AppError creation (New, Newf, Wrap, Wrapf)
      - [x] Test HTTP status code mapping for all error codes
      - [x] Test error response helpers (RespondWithError, etc.)
      - [x] Test validation helpers (ValidateRequired, ValidateLength)
      - [x] Test IsAppError() type checking
      - [x] Test HandleError() conversion and responses
  - [x] **Database Package Tests**
    - [x] `pkg/database/connection_test.go`
      - [x] Test Connect() with valid/invalid configurations
      - [x] Test ConnectWithDSN() functionality
      - [x] Test HealthCheck() and IsHealthy()
      - [x] Test WithTransaction() success/failure/rollback scenarios
      - [x] Test query helpers (Query, QueryRow, Exec, Prepare)
      - [x] Test utility functions (TableExists, ColumnExists)
    - [x] `pkg/database/migration_test.go`
      - [x] Test Migrator initialization and table creation
      - [x] Test GetAppliedMigrations() and GetCurrentVersion()
      - [x] Test ApplyMigration() and RollbackMigration()
      - [x] Test MigrateUp() and MigrateDown() workflows
      - [x] Test migration Status() reporting
      - [x] Test parseMigrationFileName() parsing logic
      - [x] Test LoadMigrationsFromFS() with mock filesystem
  - [x] **HTTP Package Tests**
    - [x] `pkg/http/response_test.go`
      - [x] Test success response helpers (RespondWithSuccess, etc.)
      - [x] Test error response helpers (RespondWithError, etc.)
      - [x] Test pagination responses and query extraction
      - [x] Test validation helpers (ValidateContentType, etc.)
      - [x] Test security and cache headers
      - [x] Test SetTotalCount() pagination calculations
    - [x] `pkg/http/client_test.go`
      - [x] Test NewClient() with various configurations
      - [x] Test HTTP methods (Get, Post, Put, Delete) with mock server
      - [x] Test retry logic with server failures
      - [x] Test authentication token handling
      - [x] Test request/response parsing and error handling
      - [x] Test HealthCheck() and IsHealthy() functionality
      - [x] Test UnmarshalResponse() data extraction

---

## 🔧 Phase 0.5: Learning-Focused Enhancements (Week 1.5 - Pre-User Service)

### **Configuration Management**
- [x] **Environment-Based Configuration (`pkg/config/`)**
  - [x] Create configuration package with environment variable loading
  - [x] Add validation for required fields (DATABASE_URL, JWT_SECRET)
  - [x] Implement defaults and environment detection helpers
  - [x] Create comprehensive test suite
  - [x] Add documentation and usage examples

### **Enhanced Authentication**
- [x] **Refresh Tokens and Logout (`pkg/auth/`)**
  - [x] Implement refresh token generation and validation
  - [x] Create token storage interface (memory/Redis implementations)
  - [x] Add logout functionality with token blacklist
  - [x] Update tests for new authentication features

### **HTTP Layer Improvements**
- [x] **Middleware and Security (`pkg/http/`)**
  - [x] Add request ID middleware for correlation
  - [x] Implement simple rate limiting middleware
  - [x] Enhanced input validation and sanitization
  - [x] Configurable CORS with security improvements
  - [x] Comprehensive testing for all middleware

### **Structured Logging**
- [x] **Context-Aware Logging (`pkg/logging/`)**
  - [x] Create logging package with structured output
  - [x] Add context propagation (request ID, user ID)
  - [x] HTTP logging middleware with request/response tracking
  - [x] Error sanitization for production safety
  - [x] Testing and documentation

### **Testing Infrastructure**
- [x] **Reusable Test Utilities (`pkg/testing/`)**
  - [x] HTTP test helpers for API testing
    - [x] `HTTPTestHelper` with Gin router integration
    - [x] Support for GET, POST, PUT, DELETE, PATCH requests
    - [x] Authentication support with `WithAuth()` method
    - [x] Response validation methods (`AssertStatusCode`, `AssertSuccess`, etc.)
    - [x] JSON request/response handling and query parameters
  - [x] Database test utilities and fixtures
    - [x] `DatabaseTestHelper` for isolated test database creation
    - [x] Automatic test database setup/teardown with unique names
    - [x] `SeedData` for creating test fixtures (users, etc.)
    - [x] Transaction testing support with auto-rollback
    - [x] Database assertion methods and SQL execution helpers
  - [x] Mock implementations for external dependencies
    - [x] `MockTokenStorage`, `MockUserRepository`, `MockDatabase`
    - [x] `MockHTTPClient`, `MockEmailService`, `MockCacheService`
    - [x] Test data builders (`UserBuilder`) with fluent interface
    - [x] Error builders for testing error scenarios
  - [x] Integration test framework with setup/teardown
    - [x] `IntegrationTestSuite` base class extending testify suite
    - [x] `IntegrationTestRunner` for configurable test execution
    - [x] `TestScenario` struct for scenario-based testing
    - [x] Utility functions (retry logic, condition waiting, logging)
    - [x] Environment management and configuration options
  - [x] Comprehensive documentation and examples
    - [x] Complete README with usage examples and best practices
    - [x] Comprehensive test suite demonstrating all features

### **Integration & Validation**
- [ ] **Cross-Package Integration**
  - [x] **Authentication Package Integration**
    - [x] Update `pkg/auth/middleware.go` to use `pkg/logging` for structured authentication logs
    - [x] Update `pkg/auth/redis_storage.go` to use `pkg/config` for Redis configuration
    - [x] Integration: Auth → Logging + Config
    - [x] Added comprehensive tests for new integration features
    - [x] Modify the test accordingly
  - [x] **HTTP Package Integration**
    - [x] Update `pkg/http/middleware.go` to use `pkg/logging` for request/response logging
    - [x] Update `pkg/http/client.go` to use `pkg/auth` for service-to-service authentication
    - [x] Integration: HTTP → Logging + Auth
    - [x] Modify the test accordingly
  - [x] **Database Package Integration**
    - [x] Update `pkg/database/connection.go` to use `pkg/config` for database configuration
    - [x] Update `pkg/database/migration.go` to use `pkg/logging` for migration logs
    - [x] Integration: Database → Config + Logging
    - [x] Modify the test accordingly

- [ ] **End-to-End Testing of Enhanced Functionality**
  - [ ] **Comprehensive Integration Tests**
    - [x] Test authentication flow with logging and config integration
    - [x] Test HTTP middleware stack with all packages working together
    - [x] Test database operations with configuration and logging
    - [x] Test inter-service communication scenarios
  - [ ] **Multi-Package Workflow Testing**
    - [x] User registration/login flow using all packages
    - [x] Request lifecycle with full middleware stack
    - [x] Database migration with logging and configuration
    - [x] Error handling across package boundaries

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


## 📦 Phase 1: Build User Service from Scratch (Week 2)

### **User Service Foundation**
- [ ] **Create User Service Structure**
  - [ ] Create `user-service/` directory
  - [ ] Initialize `user-service/go.mod` with shared package dependency
  - [ ] Create proper directory structure:
    ```
    user-service/
    ├── cmd/api/main.go
    ├── cmd/migrate/main.go
    ├── internal/
    │   ├── config/
    │   ├── handlers/
    │   ├── repository/
    │   └── logger/
    ├── db/migrations/
    ├── Dockerfile
    └── go.mod
    ```

### **Core User Service Implementation**
- [ ] **Configuration (`internal/config/`)**
  - [ ] Use `pkg/config/` for configuration management
  - [ ] Configure environment variables: PORT, DB_DSN, JWT_SECRET
  - [ ] Add basic configuration validation
  
- [ ] **Database Layer (`internal/repository/`)**
  - [ ] Create `repository.go` using shared models and database utils
  - [ ] Implement `CreateUser()` with shared auth package
  - [ ] Implement `GetUserByUsername()` 
  - [ ] Implement `GetUserByID()`
  - [ ] Add proper error handling using shared errors
  
- [ ] **HTTP Handlers (`internal/handlers/`)**
  - [ ] Create `handlers.go` using shared packages
  - [ ] Implement health check endpoints
  - [ ] Implement user registration 
  - [ ] Implement user login with optional refresh tokens
  - [ ] Implement user logout (if refresh tokens implemented)
  - [ ] Implement user profile endpoints
  - [ ] Use HTTP response utilities and basic middleware
  
- [ ] **Logging & Observability (`internal/logger/`)**
  - [x] Use `pkg/logging/` for structured logging *(pkg ready)*
  - [x] Add request correlation IDs *(pkg ready)*
  - [x] Basic request/response logging *(pkg ready)*

### **Database Setup**
- [ ] **Migration System**
  - [ ] Create `cmd/migrate/main.go` using shared database utilities
  - [ ] Create `db/migrations/001_create_users_table.up.sql`
  - [ ] Test migration runner locally
  
- [ ] **Database Integration**
  - [ ] Set up PostgreSQL connection using shared database utilities
  - [ ] Add connection pooling
  - [ ] Implement basic database health checks

### **Authentication & Middleware**
- [ ] **JWT Authentication**
  - [ ] Implement JWT middleware using shared auth package
  - [ ] Protect profile endpoints
  - [ ] Add token validation
  - [ ] Optional: Implement refresh token validation
  
- [ ] **Input Validation & Security**
  - [ ] Add comprehensive request validation
  - [ ] Password strength requirements
  - [ ] Username format validation
  - [ ] Basic input sanitization
  - [ ] Optional: Basic rate limiting

### **Containerization**
- [ ] **Docker Setup**
  - [ ] Create `Dockerfile` with valid Go version
  - [ ] Multi-stage build with shared packages
  - [ ] Add migration step to container startup
  
- [ ] **Docker Compose**
  - [ ] Update `docker-compose.yml` for user-service only
  - [ ] Add PostgreSQL service
  - [ ] Optional: Add Redis service for refresh tokens
  - [ ] Add proper environment variables (PORT, DB_DSN, JWT_SECRET)
  - [ ] Add basic health checks

### **Testing & Validation**
- [ ] **Local Testing**
  - [ ] Test compilation: `go build ./...`
  - [ ] Test Docker build
  - [ ] Test docker-compose up
  - [ ] Test all API endpoints manually
  
- [ ] **Integration Tests**
  - [ ] User registration flow
  - [ ] User login flow
  - [ ] Protected endpoint access
  - [ ] Database operations
  - [ ] JWT token lifecycle

---

## 🌐 Phase 2: API Gateway & Post Service (Week 3-4)

### **API Gateway Setup**
- [ ] **Gateway Configuration**
  - [ ] Choose gateway solution (Kong/Traefik/Nginx)
  - [ ] Configure routing for user-service
  - [ ] Add authentication middleware using shared auth
  - [ ] Set up load balancing
  - [ ] Add request/response logging

### **Post Service Implementation**
- [ ] **Extend Shared Packages**
  - [ ] Add `pkg/models/post.go` - Post model and requests
  - [ ] Add post-related errors to `pkg/errors/`
  - [ ] Add post validation rules
  
- [ ] **Create Post Service**
  - [ ] Create `post-service/` with same structure as user-service
  - [ ] Implement post CRUD operations
  - [ ] Add pagination and search
  - [ ] Connect to user-service for author information
  
- [ ] **Inter-Service Communication**
  - [ ] Use shared HTTP client for service-to-service calls
  - [ ] Implement service discovery
  - [ ] Add circuit breaker pattern
  - [ ] Add retry logic

### **Enhanced Multi-Service Features**
- [ ] **Service Discovery & Circuit Breakers**
  - [ ] Implement service discovery mechanism
  - [ ] Add circuit breaker pattern for service calls
  - [ ] Implement health check dependencies validation
  - [ ] Add service registry with health monitoring

### **Testing Multi-Service Setup**
- [ ] **Integration Testing**
  - [ ] Test user registration → post creation flow
  - [ ] Test API gateway routing
  - [ ] Test service-to-service communication
  - [ ] Test authentication across services
  - [ ] Test rate limiting across service boundaries
  - [ ] Validate correlation ID propagation between services
- [x] **Enhanced Testing Infrastructure**
  - [x] Use `pkg/testing/` helpers for integration tests
    - [x] Complete testing infrastructure ready for service integration
    - [x] HTTP test helpers with authentication support
    - [x] Database test utilities with isolation
    - [x] Mock implementations for all dependencies
  - [ ] Add contract testing between services
  - [ ] Implement end-to-end test scenarios  
  - [ ] Add performance benchmarking for service interactions

---

## 🔗 Phase 3: Extended Services & Messaging (Week 5-6)

### **Optional: Basic Role System (CV Skill: Authorization Patterns)**
- [ ] **Simple Role Implementation (Optional - demonstrates authorization understanding)**
  - [ ] Add basic `role` field to user model (admin, user)
  - [ ] Include role in JWT tokens
  - [ ] Add simple role-based middleware
  - [ ] Demonstrate admin-only endpoints

### **Comment Service (CV Skill: Inter-Service Communication)**
- [ ] **Shared Package Extensions**
  - [ ] Add `pkg/models/comment.go`
  - [ ] Add comment-related errors
  
- [ ] **Service Implementation**
  - [ ] Create `comment-service/` 
  - [ ] Implement comment CRUD
  - [ ] Link to posts and users via HTTP calls
  - [ ] Demonstrate service-to-service authentication

### **Like Service (CV Skill: Database Design & Caching)**
- [ ] **Like System Implementation**
  - [ ] Add `pkg/models/like.go`
  - [ ] Create `like-service/`
  - [ ] Optional: Use Redis for like counts (demonstrates caching)
  - [ ] Add like/unlike logic
  - [ ] Implement like count aggregation

### **Optional: Basic Event System (CV Skill: Async Communication)**
- [ ] **Simple Message Queue (Optional - demonstrates async patterns)**
  - [ ] Add basic RabbitMQ to docker-compose
  - [ ] Create simple `pkg/events/` for event definitions
  - [ ] Implement basic event publishing
  
- [ ] **Simple Event Consumers**
  - [ ] User registered → log event
  - [ ] Post created → initialize like count
  - [ ] Comment added → simple notification

---

## 📊 Phase 4: Portfolio Completion & Documentation (Week 7-8)

### **Documentation & Presentation (CV Skill: Technical Communication)**
- [ ] **Project Documentation**
  - [ ] Create comprehensive README.md with setup instructions
  - [ ] Document API endpoints with examples
  - [ ] Add architecture diagrams showing microservices interaction
  - [ ] Write blog post or technical writeup about learnings
  - [ ] Document design decisions and trade-offs made

### **Basic Monitoring (CV Skill: Observability)**
- [ ] **Simple Monitoring Setup**
  - [ ] Optional: Add basic Prometheus metrics
  - [ ] Create simple health check dashboard
  - [ ] Add basic application metrics (request count, response times)
  - [ ] Demonstrate understanding of monitoring concepts

### **Testing Excellence (CV Skill: Quality Assurance)**
- [ ] **Comprehensive Testing**
  - [ ] Ensure good unit test coverage for all packages
  - [ ] Add integration tests for each service
  - [ ] End-to-end API testing scenarios
  - [ ] Simple load testing with basic tools
  - [ ] Document testing strategy and results

### **Deployment & DevOps (CV Skill: Deployment & Automation)**
- [ ] **Simple Kubernetes Setup (Optional)**
  - [ ] Create basic deployment manifests for services
  - [ ] Set up ConfigMaps and Secrets
  - [ ] Demonstrate understanding of container orchestration
  
- [ ] **Basic CI/CD (CV Skill: Automation)**
  - [ ] Simple GitHub Actions workflow for testing
  - [ ] Automated Docker image building
  - [ ] Basic deployment automation
  - [ ] Demonstrate understanding of DevOps principles

### **Portfolio Preparation**
- [ ] **CV/Resume Updates**
  - [ ] Add microservices project to technical experience
  - [ ] Highlight specific technologies used (Go, PostgreSQL, Docker, etc.)
  - [ ] Quantify achievements (number of services, test coverage, etc.)
  
- [ ] **Demo Preparation**
  - [ ] Create demo script showing all functionality
  - [ ] Prepare to explain architectural decisions
  - [ ] Document lessons learned and challenges overcome

---

## 📁 Final Project Structure

```
blog/
├── pkg/                          # Shared packages (demonstrates reusable code)
│   ├── auth/                     # Authentication utilities
│   ├── models/                   # Data models
│   ├── errors/                   # Error definitions
│   ├── database/                 # DB utilities
│   ├── http/                     # HTTP utilities
│   ├── config/                   # Configuration management
│   ├── logging/                  # Structured logging
│   └── events/                   # Event definitions (optional)
├── user-service/                 # User management service
├── post-service/                 # Post management service
├── comment-service/              # Comment management service
├── like-service/                 # Like/reaction system
├── deployments/                  # K8s manifests (optional)
├── docker-compose.yml            # Local development
├── README.md                     # Project documentation
├── toDo.md
└── microservice.md
```

## 🎯 Success Criteria for CV/Portfolio

### **Technical Demonstration**
- [ ] All services build and run independently
- [ ] Shared packages are properly reused across services
- [ ] No circular dependencies
- [ ] All API endpoints work end-to-end
- [ ] Database migrations run automatically
- [ ] Authentication works across services
- [ ] Good test coverage demonstrates testing skills
- [ ] Services communicate via HTTP APIs
- [ ] Clean, documented, readable code

### **CV Value Demonstration**
- [ ] **Microservices Architecture**: Multi-service design with proper separation
- [ ] **Go Programming**: Clean, idiomatic Go code with proper error handling
- [ ] **Database Integration**: PostgreSQL with migrations and proper queries
- [ ] **API Development**: RESTful APIs with proper HTTP handling
- [ ] **Authentication/Security**: JWT implementation with proper validation
- [ ] **Testing**: Unit and integration tests demonstrating quality practices
- [ ] **Containerization**: Docker and docker-compose for easy deployment
- [ ] **Documentation**: Clear README and code documentation

---

**Benefits of Learning-Focused Approach:**
- **Portfolio Ready**: Professional-quality code that demonstrates skills
- **Interview Talking Points**: Real examples of microservices patterns
- **Scalable Foundation**: Can be extended with more advanced features later
- **Modern Practices**: Current Go and microservices best practices
- **Practical Experience**: Hands-on learning with real-world patterns
- **Manageable Scope**: Completable within reasonable timeframe 