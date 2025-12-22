import html

from django.http import HttpResponse
from django.template import engines


def index(request):
    engine = engines["django"]
    name = html.escape(request.GET.get("name", "World"))
    if len(name) > 210:
        name = "Your name is too long!"
    template = engine.from_string(
        f"""<html>
<head>
    <meta http-equiv="Content-Security-Policy" content="script-src 'none';">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/simpledotcss/2.3.7/simple.min.css" integrity="sha512-taVA0VISClRMNshgWnlrG4lcEYSjwpgpI8vaoT0zGoPf9c74DA95SXMngcgjaWTrEsUbKmfKqmQ7toiXNc2l+A==" crossorigin="anonymous" referrerpolicy="no-referrer" />
</head>
<body>
    <section>
        <h1>Welcome to the Django!</h1>
        <form>
            <textarea name="name" placeholder="Type something" rows="4" cols="50"></textarea>
            <br/>
            <input type="submit" value="Submit">
        </form>
        <pre>Hello, {name}!</pre>
    </section>
</body>
</html>
""".strip()
    )
    return HttpResponse(template.render({}, request))
