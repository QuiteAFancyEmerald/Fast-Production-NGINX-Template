# Fast-Production-NGINX-Template

An easy to clone fast production reverse-proxy setup using NGINX with basic connection management and DDOS mitigation.

### Overview

This configuration optimizes performance, security, and user experience by implementing best practices for Nginx. It includes rate limiting, gzip compression, SSL configuration, and error handling to ensure robust service delivery.

## Configuration Sections

#### Common Errors

`can't find user name www`

```
useradd -s /bin/false www
```

### Worker Processes and Limits

```nginx
# (One worker per CPU core)
worker_processes 8;
worker_processes auto;

# This directive controls the limit on the number of open files (file descriptors) for Nginx worker processes.
# Low Traffic: For light usage (e.g., small websites or development environments), a value of 1,024 to 2,048 might be sufficient.
# Moderate Traffic: For moderate traffic sites (e.g., small to medium-sized applications), consider setting it to 5,000 to 10,000.
# High Traffic: For high-traffic sites (e.g., e-commerce platforms, content-heavy sites), values of 20,000 to 100,000 or more can be beneficial, depending on the server's resources.

worker_rlimit_nofile 20000;

events {
    ##### Performance Setting; can be reduced if you run into CPU issues or timeouts #####
    #### max_connections = worker_processes * worker_connections
    #### worker_processes is the number of worker processes Nginx uses, and worker_connections is the limit per worker.
    #### So, if you have 4 worker processes and each has 10,000 connections, your server can handle up to 40,000 simultaneous connections.
    #### Make sure your system's resources (CPU, memory, file descriptors) are capable of handling the number of connections you configure.

    worker_connections 10000;
}
```

### HTTP Settings

```nginx
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    #### Larger bucket sizes use more memory, so it’s a balance between memory usage and performance.
    map_hash_bucket_size 128;

    ##### If you are hosting any web proxy sites this is a quick way to block any malware/adult sites
    resolver 1.1.1.3;


    # Logging is very lame
    access_log off;
    error_log off;
    sendfile on;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/conf.d/blocklist.conf;

    ####################################
    #### Rate Limit/DDOS Protection ####
    ####################################

    limit_req_zone $binary_remote_addr zone=limitreq:20m rate=30r/s;
    limit_req zone=limitreq burst=500 nodelay;
    limit_req_status 444;
    limit_conn_zone $binary_remote_addr zone=limitconn:20m;
    limit_conn limitconn 10;

    # Optimize the amount of data that is being sent at once. Prevent Nginx from sending a partial frame. As a result it will increases the
    # throughput, since TCP frames will be filled up before being sent out.
    # You also need to activate the `sendfile` option.
    tcp_nopush on;

    # By default, the TCP stack implements a mechanism to delay sending the
    # data up to 200ms. To force a socket to send the data in its buffer
    # immediately we can turn this option on.
    tcp_nodelay on;

    reset_timedout_connection on;

    gzip on;

    # Gzip compression level (1-9).
    # 5 is a perfect compromise between size and CPU usage, offering about
    # 75% reduction for most ASCII files (almost identical to level 9).
    gzip_comp_level 5;

    # Don't compress a small file that is unlikely to shrink much. The small
    # file is also usually ended up in larger file sizes after gzipping.
    gzip_min_length 256;

    # Compress data even for a proxied connection.
    gzip_proxied any;

    # Cache both the regular and the gzipped versions of a resource whenever
    # client's Accept-Encoding capabilities header varies.
    gzip_vary on;

    # Compress all of the following mime-types, `text/html` is always
    # compressed.
    gzip_types
    application/atom+xml
    application/javascript
    application/json
    application/ld+json
    application/manifest+json
    application/rss+xml
    application/vnd.geo+json
    application/vnd.ms-fontobject
    application/x-font-ttf
    application/x-web-app-manifest+json
    application/xhtml+xml
    application/xml
    font/opentype
    image/bmp
    image/svg+xml
    image/x-icon
    text/cache-manifest
    text/css
    text/plain
    text/vcard
    text/vnd.rim.location.xloc
    text/vtt
    text/x-component
    text/x-cross-domain-policy;

    # Number of requests client can make over keep-alive -- for testing environments
    # keepalive_requests 100000;

    # Handle Websocket headers
    map $http_upgrade $connection_upgrade {
        default Upgrade;
        '' close;
    }

    ##### Extras = Use this for organized multi-site setups  #####
    #include /etc/nginx/sites-enabled/*.conf;
    #include /etc/nginx/conf.d/*.conf;
}
```

### Rate Limit Useragents Setup

```nginx
http {
    ##### Rate Limit Bots #####
    # Blacklist user agents
    # The following is a default list that simply blocks all bots. credit to https://stackoverflow.com/a/24820722
    map $http_user_agent $blacklist_useragent {
        default 0;
        ~*(google|bing|yandex|msnbot) 1;
        ~*(AltaVista|Googlebot|Slurp|BlackWidow|Bot|ChinaClaw|Custo|DISCo|Download|Demon|eCatch|EirGrabber|EmailSiphon|EmailWolf|SuperHTTP|Surfbot|WebWhacker) 1;
        ~*(Express|WebPictures|ExtractorPro|EyeNetIE|FlashGet|GetRight|GetWeb!|Go!Zilla|Go-Ahead-Got-It|GrabNet|Grafula|HMView|Go!Zilla|Go-Ahead-Got-It) 1;
        ~*(rafula|HMView|HTTrack|Stripper|Sucker|Indy|InterGET|Ninja|JetCar|Spider|larbin|LeechFTP|Downloader|tool|Navroad|NearSite|NetAnts|tAkeOut|WWWOFFLE) 1;
        ~*(GrabNet|NetSpider|Vampire|NetZIP|Octopus|Offline|PageGrabber|Foto|pavuk|pcBrowser|RealDownload|ReGet|SiteSnagger|SmartDownload|SuperBot|WebSpider) 1;
        ~*(Teleport|VoidEYE|Collector|WebAuto|WebCopier|WebFetch|WebGo|WebLeacher|WebReaper|WebSauger|eXtractor|Quester|WebStripper|WebZIP|Wget|Widow|Zeus) 1;
        ~*(Twengabot|htmlparser|libwww|Python|perl|urllib|scan|Curl|email|PycURL|Pyth|PyQ|WebCollector|WebCopy|webcraw) 1;
    }

    ##### Rate Limit Bots (Less aggressive for SEO) #####
    map $http_user_agent $limit_bots {
        default 0;
        ~*(yandex|msnbot) 1;
        #~*(google|bing|yandex|msnbot) 1;
        ~*(Surfbot|SuperHTTP|AltaVista|WebWhacker) 1;
        #~*(Googlebot|Surfbot|SuperHTTP|AltaVista|WebWhacker) 1;
        #~*(AltaVista|Googlebot|Slurp|BlackWidow|Bot|ChinaClaw|Custo|DISCo|Download|Demon|eCatch|EirGrabber|EmailSiphon|EmailWolf|SuperHTTP|Surfbot|WebWhacker) 1;
        ~*(Express|WebPictures|ExtractorPro|EyeNetIE|FlashGet|GetRight|GetWeb!|Go!Zilla|Go-Ahead-Got-It|GrabNet|Grafula|HMView|Go!Zilla|Go-Ahead-Got-It) 1;
        ~*(rafula|HMView|HTTrack|Stripper|Sucker|Indy|InterGET|Ninja|JetCar|Spider|larbin|LeechFTP|Downloader|tool|Navroad|NearSite|NetAnts|tAkeOut|WWWOFFLE) 1;
        ~*(GrabNet|NetSpider|Vampire|NetZIP|Octopus|Offline|PageGrabber|Foto|pavuk|pcBrowser|RealDownload|ReGet|SiteSnagger|SmartDownload|SuperBot|WebSpider) 1;
        ~*(Teleport|VoidEYE|Collector|WebAuto|WebCopier|WebFetch|WebGo|WebLeacher|WebReaper|WebSauger|eXtractor|Quester|WebStripper|WebZIP|Wget|Widow|Zeus) 1;
        ~*(Twengabot|htmlparser|libwww|Python|perl|urllib|scan|Curl|email|PycURL|Pyth|PyQ|WebCollector|WebCopy|webcraw) 1;
    }
}
```

### Load Balancing Setup

```nginx
upstream example {
    server 127.0.0.1:8078 weight=1;
}

upstream example2 {
    server 127.0.0.1:8080 weight=2;
}
```

### Advanced Reverse Proxy Configuration

```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}

#### HTTPS Server ####
server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    ### SSL Settings ###
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    ### Additional Fingerprinting Features ###
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA HIGH !RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS";
    ssl_prefer_server_ciphers on;
    ssl_dhparam /etc/nginx/ssl/dhparams.pem;

    ### Hide nginx version number from HTTP response headers ###
    server_tokens off;

    location / {
        ### You can directly put localhost:port here as well however it is better to use the upstream to utilize load balancing features
        proxy_pass https://example;
        ###
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        # fix "upstream sent too big header/body"
        proxy_buffer_size 16k;
        # proxy_buffer_size + 8k
        proxy_busy_buffers_size 24k;
        # numOfBuffers * bufferSize >= proxy_buffer_size
        proxy_buffers 4 16k;
        # client can only upload files less than 100M
        client_max_body_size 100M;
        proxy_read_timeout 120s;

        ## Headers for security and fingerprinting boosts; helps with SEO and site security
        # add_header X-Robots-Tag "googlebot: all";
        # add_header X-Robots-Tag "bingbot: all";

        # Prevent indexing by all bots
        add_header X-Robots-Tag "none" always;

        # Prevent MIME-type sniffing (protects against MIME-type confusion attacks)
        add_header X-Content-Type-Options "nosniff" always;

        # Strong Content Security Policy (CSP) - This limits resource loading and prevents inline scripts
        add_header Content-Security-Policy "default-src 'self'; connect-src 'self'; font-src 'self' https://fonts.googleapis.com; frame-src 'none'; img-src 'self' data:; media-src 'self'; object-src 'none'; script-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline';" always;

        # Enable HTTP Strict Transport Security (HSTS) for 1 year with subdomains and preload
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

        # Referrer Policy (minimizes information shared with third parties)
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        # Feature Policy (controls specific browser features)
        add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;


        # Fake Against Attacks
        if ($request_method !~ ^(GET|HEAD|POST)$) {
            return 444;
        }

        # Rate limit Webcrawers
        if ($limit_bots = 1) {
            return 401;
            break;
        }

        # Rate limit Referers
        # https://github.com/fail2ban/fail2ban

        # Cookie based authentication for preventing bots
        #set $proxied 0;

        #if ($http_cookie ~* 'access=yes') {
        #    set $proxied 1;
        #}
        #if ($proxied = 0) {
        #    return 404;
        #}
    }

    ### Error Pages ###
    error_page 500 502 503 504 521 =400 @proxy_down;
    location @proxy_down {
        add_header Content-Type text/html;
        default_type text/html;
        return 400 '';
    }

    error_page 401 403 @proxy_authbot;
    location @proxy_authbot {
        add_header Content-Type text/html;
        default_type text/html;
        return 400 '';
    }

    error_page 404 @proxy_pagenotfound;
    location @proxy_pagenotfound {
        add_header Content-Type text/html;
        default_type text/html;
        return 400 '';
    }

    ### Deny Access ###
    location ~ /\.ht {
        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        deny all;
    }

}
```

### Simple Reverse Proxy Configuration

```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass https://example;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        client_max_body_size 100M;
        proxy_read_timeout 120s;

        # Security Headers
        add_header X-Robots-Tag "none" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Content-Security-Policy "default-src 'self';" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    }

    # Error Handling
    error_page 500 502 503 504 =400 @proxy_down;
}
```

### Security Measures

- Rate limiting is applied to mitigate DDoS attacks.
- User agent blacklisting to limit web crawlers.
- Strong Content Security Policy (CSP) to enhance security.

For further customization or troubleshooting, please refer to the Nginx documentation.

Feel free to modify any sections to better fit your project's specific needs!
