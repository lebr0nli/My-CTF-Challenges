# Ultra Fast File Sharing

* Category: Web, Pwn
* Score: 500/500
* Solves: 1/82

## Description

A simple ASGI application for sharing files quickly over the network!

Powered by FastAPI and Uvicorn with uvloop for high performance.

## Overview

This application is very simple; it only has two features:

- `GET /{filename:path}`: lets you download a file with the given `filename`
- `PUT /{filename:path}`: lets you upload a file with the given `filename`

We need to exploit vulnerabilities in these features to get a shell and read the flag.

## Solution

### Path Traversal

There's a check for `..` to prevent path traversal before reading or writing a file with given `filename`:
```python
if ".." in filename:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid filename",
    )
file_path = UPLOAD_DIR / filename
```

But apparently, this check is insufficient.

If `filename` is an absolute path, `UPLOAD_DIR / filename` will ignore `UPLOAD_DIR` and use `filename` directly to resolve the path.

This means if we `curl localhost:1337//etc/passwd`, the server will happily return the content of `/etc/passwd` for us.

If we `curl -T evil_template localhost:1337//app/templates/index.html`, the server will overwrite `/app/templates/index.html` with the content of `evil_template`, and we could easily achieve RCE... Oh, you wish :p

Unfortunately, in `docker-compose.yml`, there's a line:
```yaml
    read_only: true
```

So `/app/templates/index.html` is read-only, we cannot overwrite it.

### RCE via uvloop

Well, even though `read_only` is `true`, `/proc` is still writable. Even better, we can execute arbitrary code by writing to it.

[uvloop](https://github.com/MagicStack/uvloop), the library used in this challenge, is a fast implementation of the built-in asyncio event loop based on [libuv](https://github.com/libuv/libuv). There is excellent research on using the features of `libuv` to achieve RCE, which you can check out [here](https://www.sonarsource.com/blog/why-code-security-matters-even-in-hardened-environments/).

The core idea is to abuse the following logic in `libuv`:
```c
  do {
    r = read(loop->signal_pipefd[0], buf + bytes, sizeof(buf) - bytes);

    // omitted
    
    for (i = 0; i < end; i += sizeof(uv__signal_msg_t)) {
      msg = (uv__signal_msg_t*) (buf + i);
      handle = msg->handle;

      if (msg->signum == handle->signum) {
        assert(!(handle->flags & UV_HANDLE_CLOSING));
        handle->signal_cb(handle, handle->signum);
      }
```
> https://github.com/libuv/libuv/blob/b33162dd0b6767fbc3c833ecbe3c2f2607ba0dca/src/unix/signal.c#L448-L482

`libuv` reads `uv__signal_msg_t` structures from a pipe. If `msg->signum` matches `msg->handle->signum`, it will call `msg->handle->signal_cb(msg->handle, msg->handle->signum)`.

This means if we can make `msg->handle->signal_cb` point to the `system` function, place the command we want to execute at `msg->handle`, and ensure `msg->signum` matches `msg->handle->signum`, we can achieve RCE.

To verify we can control `rip` with this, we can `cat /dev/urandom > /proc/7/fd/<fd>` to all the fds in the process one by one, and you should notice that when writing to `/proc/7/fd/7`, the process will crash with a SIGSEGV!

But how can we fill in the correct addresses into these fields?

This part is easy thanks again to procfs. By reading `/proc/self/maps`, we can obtain the base addresses of libc and the heap, which allows us to calculate the address of `system` and the heap address of the fake struct we spray with HTTP requests.

The steps to exploit are as follows:
- Read `/proc/self/maps` to get the base addresses of libc and heap
- Spray our crafted `uv_signal_t` struct onto the heap via the HTTP request body
- Write to `/proc/self/fd/7` with the crafted `uv__signal_msg_t` struct to trigger the RCE

The full exploit code can be found in [solve.py](<./exploit/solve.py>).
