#!/bin/bash
# Comprehensive tcurl demo - shows ALL features

set -e

# Get script directory for absolute paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TCURL="${1:-$SCRIPT_DIR/build/tcurl}"

# Find an available port
PORT=18080
while netstat -tuln 2>/dev/null | grep -q ":$PORT " || ss -tuln 2>/dev/null | grep -q ":$PORT "; do
    PORT=$((PORT + 1))
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

demo() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${BLUE}$ $2${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    eval "$2" 2>&1 || true
    echo
    sleep 0.5
}

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    tcurl FEATURE DEMO                         ║"
echo "║         Streaming HTTP Client - Full Capabilities             ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check tcurl exists
if [[ ! -x "$TCURL" ]]; then
    echo -e "${RED}Error: tcurl not found at $TCURL${NC}"
    echo "Build it first: cmake --build build"
    exit 1
fi

echo -e "${CYAN}Using: $TCURL${NC}"
echo -e "${CYAN}Server port: $PORT${NC}"
echo

# Create temp directory
DEMO_DIR=$(mktemp -d)
trap "rm -rf $DEMO_DIR; kill $SERVER_PID 2>/dev/null; kill $REDIRECT_PID 2>/dev/null" EXIT

# Create test files
echo '{"status":"ok","user":"demo","items":[1,2,3]}' > "$DEMO_DIR/api.json"
echo '<html><body><h1>tcurl Demo</h1><p>Hello World!</p></body></html>' > "$DEMO_DIR/index.html"
dd if=/dev/urandom of="$DEMO_DIR/binary.bin" bs=1024 count=10 2>/dev/null
echo "Line 1 of text file" > "$DEMO_DIR/file.txt"
echo "Line 2 of text file" >> "$DEMO_DIR/file.txt"
gzip -k "$DEMO_DIR/file.txt" 2>/dev/null || true

# Create Python test server with more features
cat > "$DEMO_DIR/server.py" << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import base64
import gzip
import sys
import urllib.parse

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress logging

    def send_cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Redirect endpoint
        if path == '/redirect':
            self.send_response(302)
            self.send_header('Location', '/final')
            self.end_headers()
            return

        if path == '/redirect-chain':
            self.send_response(301)
            self.send_header('Location', '/redirect')
            self.end_headers()
            return

        if path == '/final':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'You followed the redirect!')
            return

        # Auth endpoint
        if path == '/auth':
            auth = self.headers.get('Authorization', '')
            if auth.startswith('Basic '):
                creds = base64.b64decode(auth[6:]).decode()
                if creds == 'admin:secret':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'auth': 'success', 'user': 'admin'}).encode())
                    return
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Demo"')
            self.end_headers()
            self.wfile.write(b'Unauthorized')
            return

        # Headers echo
        if path == '/headers':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            headers = {k: v for k, v in self.headers.items()}
            self.wfile.write(json.dumps(headers, indent=2).encode())
            return

        # Cookie endpoint
        if path == '/setcookie':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Set-Cookie', 'session=abc123; Path=/')
            self.send_header('Set-Cookie', 'user=demo; Path=/')
            self.end_headers()
            self.wfile.write(b'Cookies set!')
            return

        if path == '/checkcookie':
            cookies = self.headers.get('Cookie', 'none')
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f'Received cookies: {cookies}'.encode())
            return

        # Compressed response
        if path == '/compressed':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Encoding', 'gzip')
            self.end_headers()
            data = b'This response was compressed with gzip!' * 10
            self.wfile.write(gzip.compress(data))
            return

        # Large response for download demo
        if path == '/download':
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', 'attachment; filename="data.bin"')
            self.send_header('Content-Length', '10240')
            self.end_headers()
            self.wfile.write(b'X' * 10240)
            return

        # Slow response
        if path == '/slow':
            import time
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            for i in range(3):
                self.wfile.write(f'Chunk {i+1}...\n'.encode())
                self.wfile.flush()
                time.sleep(0.3)
            self.wfile.write(b'Done!')
            return

        # Status codes
        if path.startswith('/status/'):
            code = int(path.split('/')[-1])
            self.send_response(code)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f'Status {code}'.encode())
            return

        # Default: serve files
        try:
            filepath = '.' + path
            if path == '/':
                filepath = './index.html'
            with open(filepath, 'rb') as f:
                content = f.read()
            self.send_response(200)
            if filepath.endswith('.json'):
                self.send_header('Content-Type', 'application/json')
            elif filepath.endswith('.html'):
                self.send_header('Content-Type', 'text/html')
            else:
                self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', '1234')
        self.send_header('X-Custom-Header', 'demo-value')
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length else b''

        if self.path == '/echo':
            self.send_response(200)
            self.send_header('Content-Type', self.headers.get('Content-Type', 'text/plain'))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == '/form':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                'received': body.decode('utf-8', errors='replace'),
                'content_type': self.headers.get('Content-Type'),
                'length': length
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'method': 'POST', 'path': self.path, 'body_len': length}).encode())

    def do_PUT(self):
        length = int(self.headers.get('Content-Length', 0))
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'method': 'PUT', 'path': self.path, 'body_len': length}).encode())

    def do_DELETE(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'method': 'DELETE', 'path': self.path}).encode())

    def do_PATCH(self):
        length = int(self.headers.get('Content-Length', 0))
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'method': 'PATCH', 'path': self.path, 'body_len': length}).encode())

port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
server = HTTPServer(('127.0.0.1', port), Handler)
print(f'Server running on port {port}', file=sys.stderr)
server.serve_forever()
PYEOF

# Start server
cd "$DEMO_DIR"
python3 server.py $PORT &
SERVER_PID=$!
cd - >/dev/null

# Wait for server to be ready
for i in {1..10}; do
    if curl -s "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

echo -e "${GREEN}Test server started (PID $SERVER_PID)${NC}"
echo

BASE="http://127.0.0.1:$PORT"

# ============================================================================
# BASIC REQUESTS
# ============================================================================
echo -e "${GREEN}[ BASIC REQUESTS ]${NC}"

demo "1. Simple GET request" \
    "$TCURL $BASE/index.html"

demo "2. GET JSON API" \
    "$TCURL $BASE/api.json"

demo "3. HEAD request (headers only)" \
    "$TCURL -I $BASE/index.html"

demo "4. Include response headers with body" \
    "$TCURL -i $BASE/api.json"

demo "5. Verbose mode (show request + response headers)" \
    "$TCURL -v $BASE/api.json"

# ============================================================================
# HTTP METHODS
# ============================================================================
echo -e "${GREEN}[ HTTP METHODS ]${NC}"

demo "6. POST with data" \
    "$TCURL -X POST -d 'username=demo&password=test' $BASE/form"

demo "7. POST JSON" \
    "$TCURL -X POST -H 'Content-Type: application/json' -d '{\"name\":\"tcurl\",\"version\":1}' $BASE/echo"

demo "8. PUT request" \
    "$TCURL -X PUT -d 'updated data' $BASE/resource"

demo "9. DELETE request" \
    "$TCURL -X DELETE $BASE/resource/123"

demo "10. PATCH request" \
    "$TCURL -X PATCH -d '{\"field\":\"new_value\"}' $BASE/resource"

# ============================================================================
# HEADERS & USER-AGENT
# ============================================================================
echo -e "${GREEN}[ CUSTOM HEADERS ]${NC}"

demo "11. Custom headers" \
    "$TCURL -H 'X-Custom: my-value' -H 'X-Request-ID: 12345' $BASE/headers"

demo "12. Custom User-Agent" \
    "$TCURL -A 'MyApp/2.0 (Linux)' $BASE/headers"

demo "13. Set Referer" \
    "$TCURL -e 'https://google.com' $BASE/headers"

# ============================================================================
# AUTHENTICATION
# ============================================================================
echo -e "${GREEN}[ AUTHENTICATION ]${NC}"

demo "14. Basic auth (wrong credentials)" \
    "$TCURL -u wrong:creds $BASE/auth"

demo "15. Basic auth (correct credentials)" \
    "$TCURL -u admin:secret $BASE/auth"

# ============================================================================
# REDIRECTS
# ============================================================================
echo -e "${GREEN}[ REDIRECTS ]${NC}"

demo "16. Without following redirects" \
    "$TCURL -i $BASE/redirect"

demo "17. Follow redirects (-L)" \
    "$TCURL -L $BASE/redirect"

demo "18. Follow redirect chain" \
    "$TCURL -L -v $BASE/redirect-chain"

# ============================================================================
# COOKIES
# ============================================================================
echo -e "${GREEN}[ COOKIES ]${NC}"

COOKIE_JAR="$DEMO_DIR/cookies.txt"

demo "19. Get cookies from server (save to jar)" \
    "$TCURL -c $COOKIE_JAR $BASE/setcookie && echo 'Cookie jar:' && cat $COOKIE_JAR"

demo "20. Send cookies from jar" \
    "$TCURL -b $COOKIE_JAR $BASE/checkcookie"

# ============================================================================
# FILE OPERATIONS
# ============================================================================
echo -e "${GREEN}[ FILE OPERATIONS ]${NC}"

demo "21. Download to file (-o)" \
    "$TCURL -o $DEMO_DIR/downloaded.bin $BASE/download && ls -la $DEMO_DIR/downloaded.bin"

demo "22. Download with remote name (-O)" \
    "(cd $DEMO_DIR && $TCURL -O $BASE/api.json && ls -la api.json* | tail -1)"

# ============================================================================
# COMPRESSION
# ============================================================================
echo -e "${GREEN}[ COMPRESSION ]${NC}"

demo "23. Request compressed response" \
    "$TCURL --compressed $BASE/compressed"

# ============================================================================
# TIMEOUTS & ERROR HANDLING
# ============================================================================
echo -e "${GREEN}[ TIMEOUTS & ERRORS ]${NC}"

demo "24. Connection timeout" \
    "$TCURL --connect-timeout 2 $BASE/api.json"

demo "25. HTTP 404 response" \
    "$TCURL $BASE/nonexistent"

demo "26. HTTP 500 response" \
    "$TCURL $BASE/status/500"

demo "27. Fail silently on error (-f)" \
    "$TCURL -f $BASE/status/404 && echo 'Success' || echo 'Failed (exit code: \$?)'"

# ============================================================================
# SILENT & OUTPUT MODES
# ============================================================================
echo -e "${GREEN}[ OUTPUT MODES ]${NC}"

demo "28. Silent mode (-s)" \
    "$TCURL -s $BASE/api.json"

demo "29. Silent + show errors (-sS)" \
    "$TCURL -sS $BASE/status/500"

# ============================================================================
# REAL-WORLD APIs (requires internet)
# ============================================================================
echo -e "${GREEN}[ REAL-WORLD APIs ]${NC}"

demo "30. httpbin.org - Echo GET request" \
    "$TCURL https://httpbin.org/get"

demo "31. httpbin.org - See your headers" \
    "$TCURL https://httpbin.org/headers"

demo "32. httpbin.org - Get your IP address" \
    "$TCURL https://httpbin.org/ip"

demo "33. httpbin.org - User-Agent echo" \
    "$TCURL https://httpbin.org/user-agent"

demo "34. httpbin.org - POST with JSON" \
    "$TCURL -X POST -H 'Content-Type: application/json' -d '{\"test\":\"data\",\"num\":42}' https://httpbin.org/post"

demo "35. httpbin.org - Basic auth test" \
    "$TCURL -u testuser:testpass https://httpbin.org/basic-auth/testuser/testpass"

demo "36. httpbin.org - Response headers" \
    "$TCURL -i 'https://httpbin.org/response-headers?X-Custom=hello&X-Demo=tcurl'"

demo "37. httpbin.org - Delayed response (2 sec)" \
    "$TCURL https://httpbin.org/delay/2"

demo "38. httpbin.org - Redirect test" \
    "$TCURL -L https://httpbin.org/redirect/3"

demo "39. httpbin.org - UUID generator" \
    "$TCURL https://httpbin.org/uuid"

demo "40. httpbin.org - Gzip compressed" \
    "$TCURL --compressed https://httpbin.org/gzip"

demo "41. httpbin.org - Brotli compressed" \
    "$TCURL --compressed https://httpbin.org/brotli"

demo "42. JSONPlaceholder - Get a post" \
    "$TCURL https://jsonplaceholder.typicode.com/posts/1"

demo "43. JSONPlaceholder - Get comments for post" \
    "$TCURL https://jsonplaceholder.typicode.com/posts/1/comments"

demo "44. JSONPlaceholder - Create a post (POST)" \
    "$TCURL -X POST -H 'Content-Type: application/json' -d '{\"title\":\"tcurl test\",\"body\":\"Hello from tcurl!\",\"userId\":1}' https://jsonplaceholder.typicode.com/posts"

demo "45. JSONPlaceholder - Update a post (PUT)" \
    "$TCURL -X PUT -H 'Content-Type: application/json' -d '{\"id\":1,\"title\":\"updated\",\"body\":\"modified\",\"userId\":1}' https://jsonplaceholder.typicode.com/posts/1"

demo "46. JSONPlaceholder - Get users list" \
    "$TCURL https://jsonplaceholder.typicode.com/users"

demo "47. GitHub API - Public endpoint" \
    "$TCURL -H 'Accept: application/vnd.github.v3+json' https://api.github.com"

demo "48. GitHub API - Get a repo" \
    "$TCURL https://api.github.com/repos/curl/curl"

demo "49. icanhazip.com - Simple IP check" \
    "$TCURL https://icanhazip.com"

demo "50. wttr.in - Weather (text mode)" \
    "$TCURL 'https://wttr.in/?format=3'"

# ============================================================================
# SUMMARY
# ============================================================================
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                     DEMO COMPLETE                             ║"
echo "║                                                               ║"
echo "║  Local server tests (1-29):                                   ║"
echo "║  - HTTP methods: GET, POST, PUT, DELETE, PATCH, HEAD          ║"
echo "║  - Custom headers, User-Agent, Referer                        ║"
echo "║  - Basic authentication                                       ║"
echo "║  - Redirect following                                         ║"
echo "║  - Cookie handling (jar read/write)                           ║"
echo "║  - File downloads                                             ║"
echo "║  - Compressed responses                                       ║"
echo "║  - Timeouts and error handling                                ║"
echo "║  - Verbose and silent modes                                   ║"
echo "║                                                               ║"
echo "║  Real-world API tests (30-50):                                ║"
echo "║  - httpbin.org: headers, auth, redirects, compression         ║"
echo "║  - JSONPlaceholder: REST CRUD operations                      ║"
echo "║  - GitHub API: public endpoints                               ║"
echo "║  - icanhazip.com, wttr.in: simple utilities                   ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
