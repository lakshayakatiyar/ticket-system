# EVA Bharat Backend Intern Assignment - Ticket System

A small ticket-system backend written in Golang. It supports user registration, JWT login, ticket creation, ownership-based access, and controlled status updates.

## What is implemented

- `GET /health` public health check
- `POST /auth/register` user registration
- `POST /auth/login` JWT login
- `POST /tickets` create a ticket
- `GET /tickets` list only the logged-in user's tickets
- `GET /tickets/{id}` get only the logged-in user's ticket
- `PATCH /tickets/{id}/status` update only the logged-in user's ticket status
- Password hashing with salted PBKDF2-HMAC-SHA256
- JWT authentication with `Authorization: Bearer <token>`
- Ownership checks on every ticket read/update
- Status flow: `open -> in_progress -> closed`
- Closed tickets cannot be reopened
- Dockerfile for local Docker run
- Small browser page at `/` for manual testing

## Assumptions

1. The API accepts either `email` or `username` as the login identity, which keeps the request format flexible while preserving the required auth flow.
2. Ticket status always starts as `open`.
3. The allowed forward transitions are `open -> in_progress` and `in_progress -> closed`.
4. Asking for another user's ticket returns `404` so the API does not reveal whether that ticket exists.
5. In-memory storage is intentionally used because the assignment allows it and asks to keep the implementation simple.

## Request examples

### Register

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Lakshaya","email":"lakshaya@example.com","password":"demo123"}'
```

### Login

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"lakshaya@example.com","password":"demo123"}'
```

Copy the returned `token` and use it in the following requests.

### Create ticket

```bash
curl -X POST http://localhost:8080/tickets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"title":"Unable to update profile","description":"Profile save is failing."}'
```

### List my tickets

```bash
curl http://localhost:8080/tickets \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Get one of my tickets

```bash
curl http://localhost:8080/tickets/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Update status

```bash
curl -X PATCH http://localhost:8080/tickets/1/status \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"status":"in_progress"}'
```

## Run with Go

```bash
go mod download
go run ./cmd/server
```

The server runs at `http://localhost:8080` by default.

## Run with Docker

These commands match the assignment contract:

```bash
docker build -t ticket-system .
docker run -p 8080:8080 -e JWT_SECRET="change-this-secret" ticket-system
curl http://localhost:8080/health
```

Expected health response:

```json
{"status":"ok"}
```

## Run tests

```bash
go test ./...
```

## Environment variables

Use `.env.example` as a reference for environment variables. The application reads variables from the process environment (it does not require a dotenv package).

- `JWT_SECRET`: secret used to sign JWTs.
- `PORT`: optional runtime port. It defaults to `8080`; hosting platforms can provide their own port automatically.

## Deployment

Deploy the same project on a free Go/Docker-compatible hosting service. After deployment, add the public application URL and `/health` URL here before submission.

Deployment URL: _add after deployment_

Public health URL: _add after deployment_/health
