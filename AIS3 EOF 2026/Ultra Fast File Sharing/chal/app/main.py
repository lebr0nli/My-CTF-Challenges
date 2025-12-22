from pathlib import Path

from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import status
from fastapi.requests import Request
from fastapi.responses import FileResponse
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates


UPLOAD_DIR = Path(__file__).parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = FastAPI()

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@app.get("/")
async def list_files(request: Request) -> Response:
    """
    Render index page.

    The page lists all uploaded files and provides a drag-and-drop area
    for uploading new files.
    """
    files: list[str] = sorted([p.name for p in UPLOAD_DIR.iterdir() if p.is_file()])
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "files": files,
        },
    )


@app.get("/{filename:path}")
async def read_file(filename: str) -> FileResponse:
    """
    Return file contents for a given file name.

    This endpoint is equivalent to transfer.sh's download behavior:
    GET /{filename} will return the raw file content.
    """
    if ".." in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename",
        )
    file_path = UPLOAD_DIR / filename

    if not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File {filename} not found",
        )

    return Response(content=file_path.read_bytes(), media_type="application/octet-stream")


@app.put("/{filename:path}")
async def write_file(filename: str, request: Request) -> Response:
    """
    Store request body as a file with the given file name.

    Intended to be used with curl like:
        curl -T localfile http://host:port/remote_name
    """
    if ".." in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename",
        )
    file_path = UPLOAD_DIR / filename

    with file_path.open("wb") as destination:
        async for chunk in request.stream():
            if not chunk:
                continue
            destination.write(chunk)

    return Response(status_code=status.HTTP_201_CREATED)
