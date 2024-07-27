import os
import pathlib
import secrets
import shutil
import subprocess
import tempfile

from fastapi import BackgroundTasks
from fastapi import FastAPI
from fastapi import UploadFile
from fastapi import status
from fastapi.exceptions import HTTPException
from fastapi.responses import FileResponse
from fastapi.responses import HTMLResponse
from magika import Magika

app = FastAPI()


@app.get("/", include_in_schema=False, response_class=HTMLResponse)
async def home():
    return HTMLResponse(
        """<html>
    <body>
        <p>It's not 2016 anymore, the good old days are gone and I can't help you to get the flag.</p>
        <p>But don't worry, I can still help you to convert your image to a PNG file!</p>
        <a href="/docs">Check out the API documentation</a>
    </body>
</html>"""
    )


@app.post("/convert", response_class=FileResponse)
async def convert(file: UploadFile, background_tasks: BackgroundTasks):
    """
    Share any image file and it will be converted to a PNG file if it's a valid image file.
    """
    # No path traversal pls
    if os.path.pardir in file.filename or os.path.sep in file.filename:
        raise HTTPException(status_code=400, detail="Invalid file name")

    temp_dir = pathlib.Path(tempfile.mkdtemp())
    output_dir = temp_dir / secrets.token_hex(16)
    output_dir.mkdir()

    with open(output_dir / file.filename, "wb") as f:
        f.write(await file.read())

    m = Magika()
    output = m.identify_path(output_dir / file.filename).output
    if output.group != "image" or output.score != 1.0:
        print("Suspicious file detected")
        shutil.rmtree(temp_dir)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    subprocess.run(["magick", file.filename, "out.png"], cwd=output_dir)

    if not (output_dir / "out.png").is_file():
        print("Conversion failed")
        shutil.rmtree(temp_dir)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    background_tasks.add_task(shutil.rmtree, temp_dir)

    return FileResponse(output_dir / "out.png", media_type="image/png", filename="out.png")
