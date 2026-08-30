export interface HaproxyOptionCatalogItem {
  scope: ('global' | 'listener' | 'backend')[]
  target?: 'section' | 'bind'
  directive: string
  label: string
  placeholder?: string
  help?: string
}

export const HAPROXY_OPTION_CATALOG: HaproxyOptionCatalogItem[] = [
  // Global performance / tuning
  { scope: ['global'], directive: 'maxconn', label: 'Global maxconn', placeholder: '100000', help: 'Maximum per-process connections.' },
  { scope: ['global'], directive: 'nbthread', label: 'Number of threads', placeholder: '4', help: 'Threads per process.' },
  { scope: ['global'], directive: 'nbproc', label: 'Number of processes', placeholder: '1', help: 'Processes to start.' },
  { scope: ['global'], directive: 'cpu-map', label: 'CPU mapping', placeholder: 'auto:1/1-4 0-3', help: 'Bind threads to CPUs.' },
  { scope: ['global'], directive: 'tune.bufsize', label: 'Buffer size', placeholder: '16384', help: 'Buffer size in bytes.' },
  { scope: ['global'], directive: 'tune.maxrewrite', label: 'Max rewrite', placeholder: '1024', help: 'Reserved bytes for header rewrite.' },
  { scope: ['global'], directive: 'tune.runqueue-depth', label: 'Runqueue depth', placeholder: '128', help: 'Runqueue depth.' },
  { scope: ['global'], directive: 'tune.ssl.cachesize', label: 'SSL cache size', placeholder: '1000000', help: 'SSL session cache entries.' },
  { scope: ['global'], directive: 'tune.ssl.lifetime', label: 'SSL session lifetime', placeholder: '300', help: 'SSL session lifetime in seconds.' },
  { scope: ['global'], directive: 'tune.ssl.maxrecord', label: 'SSL max record', placeholder: '0', help: 'SSL record size limit.' },
  { scope: ['global'], directive: 'spread-checks', label: 'Spread checks', placeholder: '5', help: 'Spread health checks by up to N ms.' },
  { scope: ['global'], directive: 'max-spread-checks', label: 'Max spread checks', placeholder: '50', help: 'Max check spreading.' },

  // Global timeouts
  { scope: ['global'], directive: 'timeout http-request', label: 'HTTP request timeout', placeholder: '10s', help: 'Max time to receive the full request.' },
  { scope: ['global'], directive: 'timeout queue', label: 'Queue timeout', placeholder: '5s', help: 'Max time in backend queue.' },
  { scope: ['global'], directive: 'timeout tunnel', label: 'Tunnel timeout', placeholder: '1h', help: 'Timeout for WebSocket/tunnel.' },
  { scope: ['global'], directive: 'timeout tarpit', label: 'Tarpit timeout', placeholder: '2s', help: 'Hold time for tarpitted requests.' },
  { scope: ['global'], directive: 'timeout client-fin', label: 'Client FIN timeout', placeholder: '1s', help: 'Timeout for client half-close.' },
  { scope: ['global'], directive: 'timeout server-fin', label: 'Server FIN timeout', placeholder: '1s', help: 'Timeout for server half-close.' },
  { scope: ['global'], directive: 'timeout check', label: 'Check timeout', placeholder: '5s', help: 'Timeout for health checks.' },

  // Global logging
  { scope: ['global'], directive: 'option httplog', label: 'HTTP log', placeholder: '', help: 'Enable HTTP logging format.' },
  { scope: ['global'], directive: 'option tcplog', label: 'TCP log', placeholder: '', help: 'Enable TCP logging format.' },
  { scope: ['global'], directive: 'option logasap', label: 'Log ASAP', placeholder: '', help: 'Log as soon as request is received.' },
  { scope: ['global'], directive: 'option log-health-checks', label: 'Log health checks', placeholder: '', help: 'Log health-check state changes.' },
  { scope: ['global'], directive: 'option dontlognull', label: 'Do not log null', placeholder: '', help: 'Do not log null connections.' },

  // Listener bind performance
  { scope: ['listener'], target: 'bind', directive: 'maxconn', label: 'Bind maxconn', placeholder: '10000', help: 'Max connections for this listener.' },
  { scope: ['listener'], target: 'bind', directive: 'backlog', label: 'Backlog', placeholder: '1024', help: 'TCP SYN backlog.' },
  { scope: ['listener'], target: 'bind', directive: 'tcp-fast-open', label: 'TCP fast open', placeholder: '10', help: 'Enable TFO with queue depth.' },

  // Listener section
  { scope: ['listener'], directive: 'maxconn', label: 'Frontend maxconn', placeholder: '10000', help: 'Max connections per listener.' },
  { scope: ['listener'], directive: 'timeout client', label: 'Client timeout', placeholder: '50s', help: 'Max client idle time.' },
  { scope: ['listener'], directive: 'timeout http-request', label: 'HTTP request timeout', placeholder: '10s', help: 'Max time for full request.' },
  { scope: ['listener'], directive: 'timeout http-keep-alive', label: 'Keep-alive timeout', placeholder: '10s', help: 'Idle keep-alive timeout.' },
  { scope: ['listener'], directive: 'option http-keep-alive', label: 'HTTP keep-alive', placeholder: '', help: 'Enable keep-alive.' },
  { scope: ['listener'], directive: 'option http-server-close', label: 'HTTP server close', placeholder: '', help: 'Close server side after response.' },
  { scope: ['listener'], directive: 'option tcp-smart-accept', label: 'TCP smart accept', placeholder: '', help: 'Delay ACK on accept.' },
  { scope: ['listener'], directive: 'option tcp-smart-connect', label: 'TCP smart connect', placeholder: '', help: 'Delay ACK on connect.' },
  { scope: ['listener'], directive: 'option http-ignore-probes', label: 'HTTP ignore probes', placeholder: '', help: 'Ignore pre-connect probes.' },
  { scope: ['listener'], directive: 'option clitcpka', label: 'Client TCP keepalive', placeholder: '', help: 'Enable client TCP keepalive.' },
  { scope: ['listener'], directive: 'option contstats', label: 'Continuous stats', placeholder: '', help: 'Continuously update stats.' },
  { scope: ['listener'], directive: 'option abortonclose', label: 'Abort on close', placeholder: '', help: 'Abort request if client closes.' },

  // Backend performance
  { scope: ['backend'], directive: 'timeout server', label: 'Server timeout', placeholder: '50s', help: 'Max server idle time.' },
  { scope: ['backend'], directive: 'timeout connect', label: 'Connect timeout', placeholder: '5s', help: 'Max connection setup time.' },
  { scope: ['backend'], directive: 'timeout queue', label: 'Queue timeout', placeholder: '5s', help: 'Max time in backend queue.' },
  { scope: ['backend'], directive: 'timeout tunnel', label: 'Tunnel timeout', placeholder: '1h', help: 'Tunnel/Websocket timeout.' },
  { scope: ['backend'], directive: 'timeout check', label: 'Check timeout', placeholder: '5s', help: 'Health check timeout.' },
  { scope: ['backend'], directive: 'retries', label: 'Retries', placeholder: '3', help: 'Connection retries after failure.' },
  { scope: ['backend'], directive: 'option redispatch', label: 'Redispatch', placeholder: '1', help: 'Retry on another server.' },
  { scope: ['backend'], directive: 'option abortonclose', label: 'Abort on close', placeholder: '', help: 'Abort request if client closes.' },
  { scope: ['backend'], directive: 'option srvtcpka', label: 'Server TCP keepalive', placeholder: '', help: 'Enable server TCP keepalive.' },
  { scope: ['backend'], directive: 'option allbackups', label: 'All backups', placeholder: '', help: 'Use all backups when main servers fail.' },
  { scope: ['backend'], directive: 'option persist', label: 'Persist', placeholder: '', help: 'Persist on proxy-aware server fail.' },
  { scope: ['backend'], directive: 'hash-type', label: 'Hash type', placeholder: 'consistent', help: 'Hash type for source/uri balance.' },

  // Backend stick tables and persistence
  { scope: ['backend'], directive: 'stick-table', label: 'Stick table', placeholder: 'type ip size 1m expire 30m', help: 'Define a stick table.' },
  { scope: ['backend'], directive: 'stick on', label: 'Stick on', placeholder: 'src', help: 'Stick on key.' },
  { scope: ['backend'], directive: 'stick match', label: 'Stick match', placeholder: 'src table mytable', help: 'Match stickiness.' },

  // Backend health checks
  { scope: ['backend'], directive: 'option httpchk', label: 'HTTP check', placeholder: 'GET /health', help: 'HTTP health check method.' },
  { scope: ['backend'], directive: 'http-check expect', label: 'HTTP check expect', placeholder: 'status 200', help: 'Expected response.' },
  { scope: ['backend'], directive: 'http-check send', label: 'HTTP check send', placeholder: 'hdr Host example.com', help: 'Send headers/body.' },
  { scope: ['backend'], directive: 'http-check disable-on-404', label: 'Disable on 404', placeholder: '', help: 'Disable server on 404.' },
  { scope: ['backend'], directive: 'option tcp-check', label: 'TCP check', placeholder: '', help: 'Enable TCP health check.' },
  { scope: ['backend'], directive: 'tcp-check connect', label: 'TCP check connect', placeholder: 'port 80', help: 'TCP check connect parameters.' },
  { scope: ['backend'], directive: 'tcp-check send', label: 'TCP check send', placeholder: 'PING\\r\\n', help: 'TCP check payload.' },
  { scope: ['backend'], directive: 'tcp-check expect', label: 'TCP check expect', placeholder: 'string +OK', help: 'TCP check expected response.' },
  { scope: ['backend'], directive: 'default-server', label: 'Default server', placeholder: 'inter 5s fall 3 rise 2 maxconn 1000', help: 'Default server parameters.' },

  // Header manipulation
  { scope: ['backend'], directive: 'http-request set-header', label: 'Set HTTP Header', placeholder: 'Host example.com', help: 'Add or replace an HTTP header before sending to the backend server.' },

  // Connection and protocol checks
  { scope: ['backend'], directive: 'option smtpchk', label: 'SMTP check', placeholder: 'HELO myhost.example.com', help: 'SMTP health check.' },
  { scope: ['backend'], directive: 'option pgsql-check', label: 'PostgreSQL check', placeholder: 'user haproxy', help: 'PostgreSQL health check.' },
  { scope: ['backend'], directive: 'option mysql-check', label: 'MySQL check', placeholder: 'user haproxy post-41', help: 'MySQL health check.' },
  { scope: ['backend'], directive: 'option redis-check', label: 'Redis check', placeholder: '', help: 'Redis PING health check.' },
  { scope: ['backend'], directive: 'option ldap-check', label: 'LDAP check', placeholder: '', help: 'LDAP health check.' },
  { scope: ['backend'], directive: 'option external-check', label: 'External check', placeholder: 'command /usr/bin/check', help: 'External health check command.' },

  // Connection reuse / pool
  { scope: ['backend'], directive: 'http-reuse', label: 'HTTP reuse', placeholder: 'aggressive', help: 'HTTP connection reuse strategy.' },
  { scope: ['backend'], directive: 'fullconn', label: 'Full connections', placeholder: '1000', help: 'Connection pool full threshold.' },
  { scope: ['backend'], directive: 'pool-purge-delay', label: 'Pool purge delay', placeholder: '1000', help: 'Delay before closing idle connections.' },

  // DNS service discovery
  { scope: ['backend'], directive: 'resolvers', label: 'Resolvers', placeholder: 'myresolver', help: 'Resolver section name for server DNS resolution.' },

  // Source / header based balancing helpers
  { scope: ['backend'], directive: 'hash-type', label: 'Hash type', placeholder: 'consistent', help: 'Hash type for source/uri balance.' },
  { scope: ['backend'], directive: 'source', label: 'Source address', placeholder: 'usesrc clientip', help: 'Source address for server connections.' },

  // Client / server keepalive
  { scope: ['listener'], directive: 'option http-pretend-keepalive', label: 'Pretend keepalive', placeholder: '', help: 'Close connection after response but keep-alive headers.' },
  { scope: ['listener'], directive: 'option tcp-keepalive', label: 'TCP keepalive', placeholder: 'intvl 5s', help: 'TCP keepalive parameters.' },
  { scope: ['backend'], directive: 'option tcp-keepalive', label: 'TCP keepalive', placeholder: 'intvl 5s', help: 'TCP keepalive to backend servers.' },
]
