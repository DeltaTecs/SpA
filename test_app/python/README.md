# Login App

This is a desktop application with a Python backend and frontend.

## Prerequisites

- Docker and Docker Compose
- Python 3.11+

## Setup

1.  **Start the Backend:**
    ```bash
    docker-compose up --build
    ```
    The backend will be available at `http://localhost:8000`.
    A default user is created:
    - Username: `admin`
    - Password: `admin123`

2.  **Setup the Desktop App:**
    Open a new terminal and navigate to the `desktop` directory. It is highly recommended to use a virtual environment to avoid system package conflicts.

    **Windows:**
    ```bash
    cd desktop
    python -m venv venv
    .\venv\Scripts\activate
    pip install -r requirements.txt
    ```

    **Linux (Ubuntu):**
    ```bash
    cd desktop
    # You might need to install venv first: sudo apt install python3-venv
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

## Running the App

Run the desktop application:
```bash
python main.py
```

## Building the Executable (Compile)

To create a standalone executable (`.exe` on Windows, binary on Linux):

1.  **Prepare Environment:**
    Ensure you are in the `desktop` directory and your virtual environment is activated (see Setup above).

2.  **Run the Build Script:**
    ```bash
    python build.py
    ```

3.  **Locate the App:**
    The executable will be in the `desktop/dist` folder.
    - **Windows:** `desktop/dist/LoginApp.exe`
    - **Linux:** `desktop/dist/LoginApp`

    *Note: You must build the app on the operating system you intend to run it on (e.g., build on Windows for Windows, build on Ubuntu for Ubuntu).*

## Configuration

- **Backend:** Configure `backend/.env` for database URL and secret keys.
- **Desktop:** Configure `desktop/.env` for the API URL.
    - When running the compiled executable, place the `.env` file in the same directory as the executable so it can load the configuration.
