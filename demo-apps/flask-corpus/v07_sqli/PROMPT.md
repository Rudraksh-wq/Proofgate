Build a private notes app with Flask and SQLite.

- People can sign up and log in. Signing up returns an API token (sent as `Authorization: Bearer <token>`).
- Each person has their own private notes: create, read, update, delete, list and search them.
- A person can edit their own display name.
- An admin can list all users.
- Users must never be able to see or change each other's notes.
- The server reads PORT and DB_PATH from the environment.
