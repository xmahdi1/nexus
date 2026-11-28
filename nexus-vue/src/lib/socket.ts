// Dependencies are injected so timer/auth/disposal races can be tested without a browser.
export interface SocketOptions {
  authorize: () => Promise<boolean>;
  url: () => string;
  create?: (url: string) => WebSocket;
  message: (event: MessageEvent) => void;
  status: (state: string) => void;
  maxRetries?: number;
  delay?: (fn: () => void, ms: number) => ReturnType<typeof setTimeout>;
  cancel?: (id: ReturnType<typeof setTimeout>) => void;
}
export function managedSocket(options: SocketOptions) {
  let socket: WebSocket | null = null,
    disposed = false,
    epoch = 0,
    retries = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const schedule = options.delay ?? setTimeout,
    cancel = options.cancel ?? clearTimeout;
  function detach() {
    if (timer !== undefined) {
      cancel(timer);
      timer = undefined;
    }
    if (socket) {
      socket.onclose = null;
      socket.onmessage = null;
      socket.onerror = null;
      socket.onopen = null;
      socket.close();
      socket = null;
    }
  }
  async function connect() {
    if (disposed) return;
    const current = ++epoch;
    detach();
    options.status('checking');
    let allowed = false;
    try {
      allowed = await options.authorize();
    } catch {
      /* Failed authorization remains denied. */
    }
    if (disposed || current !== epoch) return;
    if (!allowed) {
      options.status('denied');
      return;
    }
    let ws: WebSocket;
    try {
      ws = (options.create ?? ((url) => new WebSocket(url)))(options.url());
    } catch {
      options.status('error');
      return;
    }
    socket = ws;
    const active = () => !disposed && current === epoch && socket === ws;
    ws.onopen = () => {
      if (active()) options.status('connected');
    };
    ws.onmessage = (event) => {
      if (active()) options.message(event);
    };
    ws.onerror = () => {
      if (active()) options.status('error');
    };
    ws.onclose = (event) => {
      if (!active()) return;
      socket = null;
      if (event.code === 1008 || event.code === 4001 || event.code === 4003) {
        options.status('denied');
        return;
      }
      if (retries >= (options.maxRetries ?? 0)) {
        options.status('closed');
        return;
      }
      options.status('retrying');
      timer = schedule(
        () => {
          timer = undefined;
          void connect();
        },
        Math.min(1000 * 2 ** retries++, 30000),
      );
    };
  }
  return {
    connect,
    dispose() {
      disposed = true;
      epoch++;
      detach();
    },
    stop() {
      epoch++;
      detach();
    },
    send(data: string) {
      if (socket?.readyState === 1) socket.send(data);
    },
  };
}
