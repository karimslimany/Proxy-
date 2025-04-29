const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const net = require('net');
const { createLogger, format, transports } = require('winston');
const app = express();
const port = process.env.PORT || 3000;

// Configure logging
const logger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    new transports.Console()
  ]
});

// In-memory session store (replace with Redis in production)
const sessions = new Map();

// Middleware
app.use(bodyParser.raw({ type: '*/*', limit: '1mb' }));

// Simple XOR encryption function (for demonstration - use stronger encryption in production)
function xorEncrypt(data, key) {
  const keyBuffer = Buffer.from(key);
  const result = Buffer.alloc(data.length);
  
  for (let i = 0; i < data.length; i++) {
    result[i] = data[i] ^ keyBuffer[i % keyBuffer.length];
  }
  
  return result;
}

// Generate Facebook-like random strings
function generateFacebookId() {
  return Math.floor(100000000000000 + Math.random() * 900000000000000).toString();
}

function generateRandomCluster() {
  const clusters = ['c1', 'c2', 'c3', 'ash', 'prn', 'dfw'];
  return clusters[Math.floor(Math.random() * clusters.length)];
}

function generateRandomIp() {
  return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

function generateDebugString() {
  return crypto.randomBytes(8).toString('hex');
}

// Handle root path to look like a normal web service
app.get('/', (req, res) => {
  logger.info('Root request received', { ip: req.ip, headers: req.headers });
  
  // Send a generic response that doesn't reveal it's a proxy
  res.status(200).json({
    status: "Service online",
    time: new Date().toISOString(),
    server: "nginx",
    fb_trace: generateFacebookId()
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: "healthy" });
});

// Send endpoint - receives encrypted data from client and forwards to SSH server
app.post('/send', async (req, res) => {
  try {
    // Check user agent to enforce Facebook-like patterns
    const userAgent = req.headers['user-agent'] || '';
    if (!userAgent.includes('FBAN') && !userAgent.includes('FB_IAB')) {
      // Log suspicious request but still respond normally
      logger.warn('Suspicious request with non-Facebook user agent', { 
        agent: userAgent, 
        ip: req.ip 
      });
    }
    
    // Extract session token from headers (for persistent connections)
    const sessionToken = req.headers['x-fb-trace-id'] || generateFacebookId();
    
    // Decrypt the payload (using XOR for simplicity)
    const encryptionKey = process.env.ENCRYPTION_KEY || 'default-encryption-key';
    let payload;
    
    try {
      payload = xorEncrypt(req.body, encryptionKey);
      
      // Check if this is a control message
      const controlPrefix = Buffer.from('CONTROL:', 'utf8');
      if (payload.slice(0, controlPrefix.length).equals(controlPrefix)) {
        // Handle control message (setup session, terminate session, etc.)
        const controlMessage = payload.slice(controlPrefix.length).toString('utf8');
        const [command, ...args] = controlMessage.split(':');
        
        if (command === 'CONNECT') {
          // Format: CONNECT:host:port
          const [host, port] = args;
          logger.info('Control message: new connection', { sessionToken, host, port });
          
          // Create new session or reset existing one
          if (sessions.has(sessionToken)) {
            const oldSession = sessions.get(sessionToken);
            if (oldSession.socket) {
              oldSession.socket.destroy();
            }
          }
          
          // Store session information
          sessions.set(sessionToken, { 
            host, 
            port: parseInt(port, 10),
            lastActive: Date.now(),
            dataTransferred: 0
          });
          
          res.setHeader('X-FB-Debug', generateDebugString());
          res.setHeader('X-FB-Trace-ID', sessionToken);
          res.setHeader('Facebook-API-Version', 'v15.0');
          res.setHeader('Content-Type', 'application/json; charset=UTF-8');
          
          return res.status(200).send(xorEncrypt(Buffer.from(JSON.stringify({
            status: 'connected',
            sessionId: sessionToken
          })), encryptionKey));
        }
        
        if (command === 'DISCONNECT') {
          // Close and remove session
          if (sessions.has(sessionToken)) {
            const session = sessions.get(sessionToken);
            if (session.socket) {
              session.socket.destroy();
            }
            sessions.delete(sessionToken);
            logger.info('Session disconnected', { sessionToken });
          }
          
          res.setHeader('X-FB-Debug', generateDebugString());
          return res.status(200).send(xorEncrypt(Buffer.from(JSON.stringify({
            status: 'disconnected'
          })), encryptionKey));
        }
      }
      
      // Regular data handling
      const session = sessions.get(sessionToken);
      if (!session) {
        logger.warn('No active session for token', { sessionToken });
        return res.status(400).send(xorEncrypt(Buffer.from(JSON.stringify({
          error: 'No active session'
        })), encryptionKey));
      }
      
      // If session exists but no socket, create one
      if (!session.socket) {
        // Connect to SSH server
        const socket = new net.Socket();
        
        socket.on('error', (err) => {
          logger.error('Socket error', { sessionToken, error: err.message });
          sessions.delete(sessionToken);
        });
        
        socket.on('close', () => {
          logger.info('Socket closed', { sessionToken });
          if (sessions.has(sessionToken)) {
            const session = sessions.get(sessionToken);
            session.socket = null;
          }
        });
        
        // Connect socket to the target
        socket.connect(session.port, session.host, () => {
          logger.info('Connected to target', { 
            sessionToken, 
            host: session.host, 
            port: session.port 
          });
          
          // Write the payload to the socket
          socket.write(payload);
          session.dataTransferred += payload.length;
          session.lastActive = Date.now();
          
          // Set timeout to receive response
          const responseTimeout = setTimeout(() => {
            logger.warn('Response timeout', { sessionToken });
            res.setHeader('X-FB-Debug', generateDebugString());
            res.setHeader('X-FB-Trace-ID', sessionToken);
            res.status(504).send(xorEncrypt(Buffer.from(JSON.stringify({
              error: 'Gateway timeout'
            })), encryptionKey));
          }, 10000); // 10 second timeout
          
          // Buffer to collect data from socket
          let responseData = Buffer.alloc(0);
          
          socket.on('data', (data) => {
            responseData = Buffer.concat([responseData, data]);
            
            // If response size gets too large, send it back immediately
            if (responseData.length > 128 * 1024) { // 128KB threshold
              clearTimeout(responseTimeout);
              
              // Send the response
              res.setHeader('X-FB-Debug', generateDebugString());
              res.setHeader('X-FB-Trace-ID', sessionToken);
              res.setHeader('Facebook-API-Version', 'v15.0');
              res.setHeader('Content-Type', 'application/json; charset=UTF-8');
              
              // Send encrypted response
              res.send(xorEncrypt(responseData, encryptionKey));
              
              // Update session stats
              session.dataTransferred += responseData.length;
              session.lastActive = Date.now();
              
              // Remove data handlers to prevent additional processing
              socket.removeAllListeners('data');
              socket.removeAllListeners('end');
            }
          });
          
          socket.on('end', () => {
            clearTimeout(responseTimeout);
            
            // Send the final response
            res.setHeader('X-FB-Debug', generateDebugString());
            res.setHeader('X-FB-Trace-ID', sessionToken);
            res.setHeader('Facebook-API-Version', 'v15.0');
            res.setHeader('Content-Type', 'application/json; charset=UTF-8');
            
            // Send encrypted response
            res.send(xorEncrypt(responseData, encryptionKey));
            
            // Update session stats
            session.dataTransferred += responseData.length;
            session.lastActive = Date.now();
          });
        });
        
        // Save socket to session
        session.socket = socket;
      } else {
        // Use existing socket
        session.socket.write(payload);
        session.dataTransferred += payload.length;
        session.lastActive = Date.now();
        
        // Send acknowledgment
        res.setHeader('X-FB-Debug', generateDebugString());
        res.setHeader('X-FB-Trace-ID', sessionToken);
        res.setHeader('Facebook-API-Version', 'v15.0');
        res.setHeader('Content-Type', 'application/json; charset=UTF-8');
        
        res.status(200).send(xorEncrypt(Buffer.from(JSON.stringify({
          status: 'data_sent',
          size: payload.length
        })), encryptionKey));
      }
    } catch (err) {
      logger.error('Payload processing error', { error: err.message });
      res.status(400).send(xorEncrypt(Buffer.from(JSON.stringify({
        error: 'Invalid payload'
      })), encryptionKey));
    }
  } catch (err) {
    logger.error('Request handler error', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Receive endpoint - client polls for data that was received from SSH server
app.get('/receive', (req, res) => {
  try {
    // Extract session token
    const sessionToken = req.headers['x-fb-trace-id'];
    if (!sessionToken || !sessions.has(sessionToken)) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    const session = sessions.get(sessionToken);
    
    // Set Facebook-like headers
    res.setHeader('X-FB-Debug', generateDebugString());
    res.setHeader('X-FB-Trace-ID', sessionToken);
    res.setHeader('Facebook-API-Version', 'v15.0');
    res.setHeader('Content-Type', 'application/json; charset=UTF-8');
    
    // If there's data waiting, send it
    if (session.pendingData && session.pendingData.length > 0) {
      const encryptionKey = process.env.ENCRYPTION_KEY || 'default-encryption-key';
      const encryptedData = xorEncrypt(session.pendingData, encryptionKey);
      
      // Clear pending data
      session.pendingData = null;
      
      // Send the data
      return res.send(encryptedData);
    }
    
    // No data waiting, send empty response
    res.status(200).json({ status: 'no_data' });
  } catch (err) {
    logger.error('Receive handler error', { error: err.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Session cleanup job - run every minute
setInterval(() => {
  const now = Date.now();
  const timeoutThreshold = 10 * 60 * 1000; // 10 minutes
  
  for (const [token, session] of sessions.entries()) {
    if (now - session.lastActive > timeoutThreshold) {
      logger.info('Cleaning up inactive session', { sessionToken: token });
      if (session.socket) {
        session.socket.destroy();
      }
      sessions.delete(token);
    }
  }
}, 60 * 1000);

// Start the server
app.listen(port, '0.0.0.0', () => {
  logger.info(`Proxy server running on port ${port}`);
});
