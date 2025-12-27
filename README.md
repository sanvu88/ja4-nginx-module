# ja4-nginx-module

This repository contains an Nginx module that generates [JA4](https://github.com/FoxIO-LLC/ja4) fingerprints. It includes the necessary Nginx patches and module source code to integrate JA4 fingerprinting into your Nginx server.

**Note:** Development for JA4 on Nginx is currently paused. This version may have known issues. Use at your own risk.

## Quick Start with Docker

You can easily build and run the Nginx server with the JA4 module using Docker Compose. This uses the `docker-compose.yaml` file in the root directory.

1.  Clone the repository:
    ```bash
    git clone https://github.com/vncloudsco/ja4-nginx-module.git
    cd ja4-nginx-module
    ```

2.  Start the service:
    ```bash
    docker-compose up --build
    ```

This will build the image locally and start Nginx on ports **80** (HTTP) and **443** (HTTPS).

### Docker Configuration
The `docker-compose.yaml` mounts the configuration files from `nginx_utils/`:
- `nginx.conf`: Main Nginx configuration.
- `server.crt` / `server.key`: SSL certificates.
- `logs/`: Directory for Nginx logs.

## Building from Source (Nginx Integration)

To build Nginx with the JA4 module manually, follow these steps.

### Prerequisites
- Nginx source code (tested with v1.25.0)
- OpenSSL source code (tested with v3.2.1)
- Build tools: `gcc`, `make`, `patch`, `perl`, `zlib-dev`, `pcre-dev`, `openssl-dev`

### Build Steps

1.  **Download Sources**:
    Download and extract Nginx and OpenSSL.
    ```bash
    wget https://nginx.org/download/nginx-1.25.0.tar.gz
    tar -zxf nginx-1.25.0.tar.gz

    wget https://github.com/openssl/openssl/releases/download/openssl-3.2.1/openssl-3.2.1.tar.gz
    tar -zxf openssl-3.2.1.tar.gz
    ```

2.  **Apply Patch**:
    Apply the provided patch to the Nginx source.
    ```bash
    cd nginx-1.25.0
    patch -p1 < /path/to/ja4-nginx-module/patches/nginx.patch
    ```

3.  **Configure and Build**:
    Configure Nginx to include the JA4 module. Point `--add-module` to the `src` directory of this repo.
    ```bash
    ./configure \
        --with-openssl=../openssl-3.2.1 \
        --add-module=/path/to/ja4-nginx-module/src \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_v3_module \
        --prefix=/etc/nginx

    make
    make install
    ```

## Testing

Integration tests are available to validate the module's behavior.

1.  Install dependencies (requires `pytest`):
    ```bash
    pip install pytest
    ```

2.  Run tests:
    ```bash
    pytest
    ```

3.  Update "golden" files (if you are making changes):
    ```bash
    pytest --record
    ```

## Nginx Configuration

The module exposes JA4 fingerprints as Nginx variables.

### Variables
- `$http_ssl_ja4`: The JA4 fingerprint.
- `$http_ssl_ja4h`: The JA4 hash.
- `$http_ssl_ja4one`: JA4 single packet fingerprint.

### Example Usage
In your `nginx.conf`:

```nginx
http {
    log_format main '$remote_addr - ... "$http_ssl_ja4"';

    server {
        listen 443 ssl;
        
        # Add JA4 header to responses
        add_header X-JA4 $http_ssl_ja4;
        
        # Access control based on JA4 fingerprint
        location / {
            # Example: deny specific fingerprints
            ja4_deny t13d1516h2_8daaf6152771_bc9a4605e104;
        }
    }
}
```

## Access Control & Blocking

The module provides dedicated directives to allow or deny traffic based on JA4 fingerprints. These directives work similarly to Nginx's built-in `allow` and `deny` rules: the **first matching rule** wins.

### Available Directives
- **JA4 (TLS)**: `ja4_allow`, `ja4_deny`
- **JA4H (HTTP)**: `ja4h_allow`, `ja4h_deny`
- **JA4One (Single Packet)**: `ja4one_allow`, `ja4one_deny`

All directives accept a specific fingerprint string or the keyword `all`.

### Case Studies

#### Case 1: Blocking a Malicious Bot (Blacklist)
You have identified a bot with a specific JA4 fingerprint (`t13d1516h2_8daaf6152771_bc9a4605e104`) that you want to block globally.

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    location / {
        # Block this specific bad actor
        ja4_deny t13d1516h2_8daaf6152771_bc9a4605e104;
        
        # Allow everyone else (implicit, but can be explicit with ja4_allow all;)
    }
}
```

#### Case 2: Whitelist Mode (API Security)
You have a private API that should only be accessed by your own mobile app or specific clients. You want to block all other TLS signatures.

```nginx
location /api/ {
    # Allow your mobile app fingerprint
    ja4_allow t13d1516h2_8daaf6152771_bc9a4605e104;
    
    # Allow a partner's service
    ja4_allow t13d1516h2_e7d70545501f_8665089e9e54;

    # Deny everyone else
    ja4_deny all;
}
```

#### Case 3: Blocking HTTP Scrapers via JA4H
Some scrapers might rotate their TLS fingerprint (JA4) but keep the same HTTP headers (JA4H). You can block them using `ja4h_deny`.

```nginx
location / {
    # Block a scraper with a specific HTTP header fingerprint
    ja4h_deny ge11nn020000_d4cd99874e44_122421334455;
    
    # Block a curl client (example fingerprint)
    ja4h_deny ge11nn020000_d4cd99874e44_556677889900;
}
```

#### Case 4: Advanced Filtering with JA4One
If you are mitigating a DDoS attack and only have the first packet information, you can use `ja4one`.

```nginx
location / {
    # Block traffic based on the first packet fingerprint
    ja4one_deny t13d151600_8daaf6152771_bc9a4605e104;
}
```
