import { createServer, type Server } from "node:http";
import { connect, type AddressInfo, type Socket } from "node:net";

export type ConnectProxy = Readonly<{
  url: string;
  /** The `host:port` of every CONNECT request, in order. */
  tunnels: string[];
  /** The Proxy-Authorization header of every CONNECT request. */
  authorizations: (string | undefined)[];
  close: () => Promise<void>;
}>;

/**
 * A minimal HTTP proxy that only opens CONNECT tunnels, as a corporate
 * proxy does for HTTPS. It sees the target host and nothing inside TLS.
 */
export async function startConnectProxy(): Promise<ConnectProxy> {
  const tunnels: string[] = [];
  const authorizations: (string | undefined)[] = [];
  const sockets = new Set<Socket>();
  const server: Server = createServer((_request, response) => {
    response.writeHead(405);
    response.end();
  });
  server.on("connect", (request, client: Socket, head: Buffer) => {
    tunnels.push(request.url ?? "");
    authorizations.push(request.headers["proxy-authorization"]);
    sockets.add(client);
    const [host, port] = splitAuthority(request.url ?? "");
    const upstream = connect(port, host, () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    sockets.add(upstream);
    const end = () => { upstream.destroy(); client.destroy(); };
    upstream.on("error", () => {
      if (!client.destroyed) client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      end();
    });
    client.on("error", end);
    client.on("close", () => { sockets.delete(client); upstream.destroy(); });
    upstream.on("close", () => { sockets.delete(upstream); client.destroy(); });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return Object.freeze({
    url: `http://127.0.0.1:${port}`,
    tunnels,
    authorizations,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  });
}

function splitAuthority(authority: string): [string, number] {
  const match = /^\[?([^\]]+?)\]?:(\d+)$/u.exec(authority);
  return [match?.[1] ?? authority, Number(match?.[2] ?? 443)];
}
