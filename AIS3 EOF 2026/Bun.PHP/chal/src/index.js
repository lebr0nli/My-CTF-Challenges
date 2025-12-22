import { $ } from "bun";
import { resolve } from "node:path";

const server = Bun.serve({
    host: "0.0.0.0",
    port: 1337,
    routes: {
        "/": async req => {
            return new Response(null, {
                status: 302,
                headers: { "Location": "/cgi-bin/index.php" },
            });
        },

        "/cgi-bin/:filename": async req => {
            const filename = req.params.filename;
            if (!filename.endsWith(".php")) {
                return new Response(`404\n`, {
                    status: 404,
                    headers: { "Content-Type": "text/plain" },
                });
            }

            const scriptPath = resolve("cgi-bin/" + filename);
            const body = await req.blob();
            const shell = $`${scriptPath} < ${body}`
                .env({
                    REQUEST_METHOD: req.method,
                    QUERY_STRING: new URL(req.url).searchParams.toString(),
                    CONTENT_TYPE: req.headers.get("content-type") ?? "",
                    CONTENT_LENGTH: body ? String(body.size) : "0",
                    SCRIPT_FILENAME: scriptPath,
                    GATEWAY_INTERFACE: "CGI/1.1",
                    SERVER_PROTOCOL: "HTTP/1.1",
                    SERVER_SOFTWARE: "bun-php-server/0.1",
                    REDIRECT_STATUS: "200",
                })
                .nothrow();

            // PHP-CGI outputs headers + body separated by \r\n\r\n
            const output = await shell.text();
            const [rawHeaders, ...rest] = output.split("\r\n\r\n");
            const headers = new Headers();
            for (const line of rawHeaders.split("\r\n")) {
                const [k, v] = line.split(/:\s*/, 2);
                if (k && v) headers.set(k, v);
            }

            const responseBody = rest.join("\r\n\r\n");
            return new Response(responseBody, { headers });
        },
    }
});

console.log(`listening on http://localhost:${server.port}`);
