# Project 2: Extending the JWKS Server

## Overview
This project extends the simple FastAPI server from Project 1 to use SQLite for persistent storage of private keys, ensuring keys survive server restarts. It:

1. Generates and manages RSA key pairs (with expiry timestamps) stored in a SQLite database.
2. Serves public keys in JWKS format via a RESTful endpoint (only unexpired keys).
3. Issues signed JWTs via a POST endpoint, reading keys from the database.
4. Prevents SQL injection via parameterized queries.

## Project Structure

```
Project-1/
├─ app/
│  ├─ __init__.py       # Empty
│  ├─ jwk_utils.py      # Helpers to convert public key to JWK format
│  ├─ keys.py           # Key manager: generate, store, and query RSA keys
│  ├─ main.py           # FastAPI app that provides JWKS and JWT
│  └─ settings.py       # Config constants for the JWKS server
├─ tests/
│  ├─ conftest.py       # Pytest fixtures (e.g., temp DB)
│  ├─ test_jwk_utils.py # Tests jwk_utils.py
│  ├─ test_keys.py      # Tests keys.py
│  └─ test_main.py      # Tests main.py
├─ README.md            # Overview / Project Documentation
└─ requirements.txt     # List of required dependencies
```

## Setup

1. Clone the repository
`git clone https://github.com/LandonMurr/Project-1.git`

2. Create and activate a virtual environment
```bash
python 3 -m venv .venv
source .venv/bin/activate # macOS / Linux
# .venv/Scripts/activate # Windows
```

3. Install dependencies
`pip install -r requirements.txt`

## Running the Server

Start the FastAPI server:
`python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8080`

- Server will initialize the SQLite database, create the keys table, and generate one active key and one expired key on startup.

## REST Endpoints

| Endpoint               | Method | Description                                              |
| :--------------------- | :----- | :------------------------------------------------------- |
| /.well-known/jwks.json | GET    | Returns all active public keys in JWK format             |
| /auth                  | POST   | Returns a signed JWT. Add ?expired to use an expired key |

## Usage

**Fetch JWKS**
`curl http://localhost:8080/.well-known/jwks.json`

**Generate JWT**
`curl -X POST "http://localhost:8080/auth`

**Generate JWT with expired key**
`curl -X POST "http://localhost:8080/auth?expired`

## Functionality

1. **Key Management (`keys.py`)**
    - Generates RSA key pairs with unique IDs and expiry timestamps.
        - Provides helper functions to fetch expired or unexpired keys.

2. **Public Key Conversion (`jwk_utils.py`)**
    - Converts RSA public key objects into JWK dictionaries.
        - Encodes modulus and exponent as URL-safe base64 without padding.

3. **FastAPI App (`main.py`)**
    - Lifecycle generates initial keys on startup.
    - JWKS endpoint shows active public keys.
    - Auth endpoint issues JWTs with selected key.

## Notes

- For ease of testing under project circumstances, keys persist in SQLite only whiel the server is running; restarting the server resets the database.
- Expired keys are included for testing JWT verification failures.
- Per the instructions, this project employs no real authentication functionality, nor are there realistic countermeasures (i.e. encryption) for several potential security vulernabilities.

## References

**Official Documentation**
- [Cryptography - RSA Key Generation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key)
- [Cryptography — Public Key Objects](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-objects)
- [Cryptography — Key Serialization](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#serialization-of-keys)
- [Python uuid module](https://docs.python.org/3/library/uuid.html#uuid.uuid4)
- [Python time module](https://docs.python.org/3/library/time.html#time.time)
- [Python base64 module](https://docs.python.org/3/library/base64.html#base64.urlsafe_b64encode)
- [Python int.to_bytes](https://docs.python.org/3/library/stdtypes.html#int.to_bytes)
- [FastAPI Tutorial](https://fastapi.tiangolo.com/tutorial/)
- [FastAPI Path & Query Parameters](https://fastapi.tiangolo.com/tutorial/query-params/)
- [FastAPI Responses](https://fastapi.tiangolo.com/advanced/response-directly/)
- [Python contextlib.asynccontextmanager](https://docs.python.org/3/library/contextlib.html#contextlib.asynccontextmanager)
- [PyJWT — Encoding Tokens](https://pyjwt.readthedocs.io/en/stable/usage.html#encoding-decoding-tokens)
- [Official unittest documentation](https://docs.python.org/3/library/unittest.html)
- [Pytest documentation - assert](https://docs.pytest.org/en/stable/assert.html)
- [Pytest documentation - monkeypatch](https://docs.pytest.org/en/stable/how-to/monkeypatch.html)
- [Black - Basic Usage](https://black.readthedocs.io/en/stable/usage_and_configuration/the_basics.html)
- [Python sqlite3 Module Documentation](https://docs.python.org/3/library/sqlite3.html)


**AI Assistance**
This project utilized AI assistance via Grok 4 Expert. Unfortunately, Grok has a distinct ability over other popular LLMs to maintain consideration of detailed list of requirements via its project instructions feature, which made it one of the better tools for this assignment. My goal was to complete this project in Python - a language am largely unfamiliar in - and this helped to supplement a lack of experience. AI assistance was used exclusively for the following categories:

1. Project 1 Research & Initial Project Structure

After saving the Canvas project instructions to Grok's memory, I sent the following prompt:

*"Based on instructions provided, what are some libraries I may find helpful to complete this school project in Python? Without showing me your solution, work through the project on your own, inform me of a general project structure, and procure a list of links to relevant sections of documentation within the libraries you use. My goal is to learn the process myself and write the code on my own."*

This gave me the list of resources provided above, a basic description of project structure, and a brief description of expected functionality for each file (including the test suite).

2. Project 2 Research

For the functionality added in Project 2, I employed the following prompt after updating Grok's file memory to include the most up-to-date content:

*"Without providing code, help me identify the necessary libraries and documentation necessary to add SQLite functionality. I'm looking to save private keys and modify the POST:/auth and GET:/.well-known/jwks.json endpoints to use the database."*

This provided me with some details on SQLite documentation, included in the official documentation links above.

3. Project 2 Test Suite

Due to the increased complexity of the project, I consulted Grok on what specific test cases to examine using the following prompt:

*"Based on the source code in the app directory, generate a sufficient list of test cases to confirm the code's functionality."*

This provided me with an extensive list of test cases to implement.

4. Debugging

After running the test suite and struggling with failed tests, I uploaded my project files to the conversation, pasted the terminal output containing test status, and asked the following prompt:

*"Help me interpret these error messages. I'm not looking for code; just provide a simple explanation of what the terminal is already saying."*

To ensure the integrity of this practice, this prompt was used for each additional error message until no further assistance was needed.

5. Linting & Syntactical Improvements

After implementing all primary functionality, I allowed Grok to review all of my code in search of any redunancies, syntactical inefficiencies, or locations where minor changes could significantly help adherence to best practices. The prompt for this is pasted below:

*"I would like you to review all of my code and locate any minor issues that do not concern broader functionality. This will consist primarily syntactical issues like minor functional redunancies/inefficiencies, or single lines that may be edited to better fit Python best practices."*

In this turn, Grok made a few edits all of the categories listed. It also recommended Black for final polishes on formatting, attaching both instructions on usage as well as providing a link to its online documentation.