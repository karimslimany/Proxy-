import asyncio
import base64
import logging
import os
import websockets
from quart import Quart, request, jsonify
from dotenv import load_dotenv

# Load environment variables from .env (for local testing)
# On Fly.io, these should be set via flyctl secrets set
load_dotenv()

SECRET_TOKEN = os.getenv("SECRET_TOKEN")
BACKEND_WS_URL = os.getenv("BACKEND_WS_URL", "wss://uk.sshws.net:443/") # Default, change if needed
RECEIVE_TIMEOUT = int(os.getenv("RECEIVE_TIMEOUT", 25)) # Seconds for long polling timeout

# Ensure the secret token is set
if not SECRET_TOKEN:
    # For deployment, ensure this is set via flyctl secrets set
    # For local testing, ensure .env is present
    logging.warning("SECRET_TOKEN not set. App might not work correctly without it.")


app = Quart(__name__)

# In-memory storage for client sessions
# { token: { 'ws': WebSocketClientProtocol, 'recv_queue': asyncio.Queue, 'data_available': asyncio.Event } }
# NOTE: This uses in-memory storage. Restarts will lose active sessions.
# For higher availability or sticky sessions, a shared store like Redis would be needed.
client_sessions = {}

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

async def handle_websocket_receive(token, websocket):
    """Reads data from the backend WebSocket and puts it into the client's queue."""
    logging.info(f"[{token}] Starting WebSocket receive handler")
    try:
        while True:
            data = await websocket.recv()
            # logging.debug(f"[{token}] Received {len(data)} bytes from backend WS") # Keep this debug only, lots of traffic
            session = client_sessions.get(token)
            if session:
                await session['recv_queue'].put(data)
                session['data_available'].set() # Signal data is ready for polling
            else:
                logging.warning(f"[{token}] Session not found while receiving from WS. Stopping handler.")
                break # Session disappeared, stop handler
    except websockets.exceptions.ConnectionClosedOk:
        logging.info(f"[{token}] WebSocket connection closed gracefully.")
    except websockets.exceptions.ConnectionClosedError as e:
        logging.error(f"[{token}] WebSocket connection closed with error: {e}")
    except Exception as e:
        logging.error(f"[{token}] Error in WebSocket receive handler: {e}", exc_info=True)
    finally:
        # Clean up session after WS connection closes
        logging.info(f"[{token}] Cleaning up session after WS close")
        if token in client_sessions:
            # Setting the event one last time can help unblock waiting /receive requests
            session = client_sessions[token]
            session['data_available'].set()
            # It's safer to let /receive handle reporting session closure/error
            # The WS handler's job is just to clean up its end and state.
            del client_sessions[token]
            logging.info(f"[{token}] Session cleaned up.")


async def get_session(token):
    """Gets or creates a client session and establishes the WebSocket connection."""
    session = client_sessions.get(token)

    if session and not session['ws'].closed:
        logging.debug(f"[{token}] Using existing active session.")
        return session
    elif session and session['ws'].closed:
         logging.warning(f"[{token}] Existing session WS was closed, cleaning up.")
         # Clean up potentially stale session state
         del client_sessions[token]
         session = None # Ensure we create a new one below

    if not session:
        logging.info(f"[{token}] Creating new session and connecting to backend WS: {BACKEND_WS_URL}")
        try:
            # Connect to the backend WebSocket server
            websocket = await websockets.connect(BACKEND_WS_URL)
            logging.info(f"[{token}] Successfully connected to backend WS.")

            # Create session state
            session = {
                'ws': websocket,
                'recv_queue': asyncio.Queue(), # Data from WS waiting for /receive
                'data_available': asyncio.Event() # Event for long polling
            }
            client_sessions[token] = session

            # Start the background task to read from the WebSocket
            # asyncio.create_task ensures it runs concurrently without blocking
            asyncio.create_task(handle_websocket_receive(token, websocket))

            return session
        except Exception as e:
            logging.error(f"[{token}] Failed to connect to backend WS: {e}", exc_info=True)
            return None


@app.route('/send', methods=['POST'])
async def send_data():
    """Receives data from the client via POST and sends it to the backend WebSocket."""
    token = request.headers.get('X-Token')
    if not token or token != SECRET_TOKEN:
        logging.warning(f"Received /send with invalid token: {token}")
        return jsonify({"status": "error", "message": "Invalid or missing token"}), 401

    session = await get_session(token)
    if not session or session['ws'].closed:
        # If session is None here, get_session failed to connect WS
        logging.error(f"[{token}] Cannot send, session not active or WS closed.")
        return jsonify({"status": "error", "message": "Session not active or backend connection failed"}), 500

    try:
        # Get raw data from the request body
        # Assuming the data is sent directly in the body and Base64 encoded
        data_b64 = await request.get_data()
        if not data_b64:
             return jsonify({"status": "error", "message": "No data received in body"}), 400

        data = base64.b64decode(data_b64)

        # logging.debug(f"[{token}] Received {len(data)} bytes from /send") # Keep this debug only

        # Send data over the WebSocket connection
        await session['ws'].send(data)
        # logging.debug(f"[{token}] Sent {len(data)} bytes to backend WS") # Keep this debug only

        return jsonify({"status": "success", "bytes_sent": len(data)}), 200

    except Exception as e:
        logging.error(f"[{token}] Error in /send: {e}", exc_info=True)
        # If sending fails, the WS connection might be bad.
        # The receive handler will eventually catch the closure, but we can log.
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/receive', methods=['GET'])
async def receive_data():
    """Waits for data from the backend WebSocket and returns it to the client via GET (long polling)."""
    token = request.headers.get('X-Token')
    if not token or token != SECRET_TOKEN:
        logging.warning(f"Received /receive with invalid token: {token}")
        return jsonify({"status": "error", "message": "Invalid or missing token"}), 401

    # We check if the session exists, but don't auto-create here.
    # /send is expected to be called first to establish the WS connection.
    session = client_sessions.get(token)

    if not session:
         logging.warning(f"[{token}] Receive requested for non-existent session.")
         return jsonify({"status": "error", "message": "Session not active. Call /send first?"}), 400

    # Check if the WS is closed *before* waiting.
    if session['ws'].closed:
         logging.warning(f"[{token}] Receive requested for session with closed WS.")
         # Session will be cleaned up by the receive handler eventually.
         # We return an error indicating the connection is gone.
         return jsonify({"status": "error", "message": "Backend connection closed."}), 500


    try:
        # Use the data_available event for long polling
        # Wait for the event to be set (data arrived) or timeout
        try:
            # logging.debug(f"[{token}] Waiting for data on /receive (timeout={RECEIVE_TIMEOUT}s)") # Keep this debug only
            # This waits for session['data_available'].set() to be called
            await asyncio.wait_for(session['data_available'].wait(), timeout=RECEIVE_TIMEOUT)
            # logging.debug(f"[{token}] Data available or timeout on /receive.") # Keep this debug only
        except asyncio.TimeoutError:
            # If timeout occurs, clear the event just in case it was set right before the timeout exception
            # This isn't strictly necessary due to the structure below but adds robustness.
            session['data_available'].clear()
            logging.debug(f"[{token}] /receive timed out.")
            # Return an empty data response with a status indicating timeout
            return jsonify({"status": "timeout", "data": ""}), 200

        # Data is available (event was set). Clear the event for the next wait *before* getting data.
        session['data_available'].clear()

        # Get *all* available data from the queue now that the event was set
        data_chunks = []
        try:
            # Get items until the queue is empty *at this moment*
            while True:
                data_chunks.append(session['recv_queue'].get_nowait())
                session['recv_queue'].task_done() # Mark item as processed
                # logging.debug(f"[{token}] Retrieved chunk from queue.") # Keep this debug only
        except asyncio.QueueEmpty:
             # logging.debug(f"[{token}] Queue empty after retrieving chunks.") # Keep this debug only
             pass # No more data currently in the queue

        if not data_chunks:
             # This case is unlikely if data_available was correctly set just before,
             # but handle it defensively.
             logging.warning(f"[{token}] data_available was set but queue was empty after getting.")
             return jsonify({"status": "no_data", "data": ""}), 200


        # Concatenate all data chunks and base64 encode
        full_data = b"".join(data_chunks)
        encoded_data = base64.b64encode(full_data).decode('ascii')

        # logging.debug(f"[{token}] Returning {len(full_data)} bytes ({len(encoded_data)} base64) on /receive") # Keep this debug only

        return jsonify({"status": "success", "data": encoded_data}), 200

    except Exception as e:
        logging.error(f"[{token}] Error in /receive: {e}", exc_info=True)
        # The WS handler is responsible for cleanup. Don't delete session state here
        return jsonify({"status": "error", "message": str(e)}), 500

# Basic root route
@app.route('/')
async def index():
    # Check if SECRET_TOKEN is set for a basic health indicator
    status = "running" if SECRET_TOKEN else "running (WARNING: TOKEN NOT SET)"
    return f"Stealth Proxy is {status}!"

# Optional: Health check route for Fly.io
@app.route('/health')
async def health_check():
    # Could add logic to check backend WS connection health if needed
    # For now, just return OK if the app is running
    if not SECRET_TOKEN:
        return jsonify({"status": "warning", "message": "SECRET_TOKEN not set"}), 500 # Indicate config issue
    return jsonify({"status": "ok"}), 200

# Note: For deployment, you will run this with a production server like uvicorn or hypercorn.
# The fly.toml file specifies the command: uvicorn app:app --host 0.0.0.0 --port 8080