# from django.shortcuts import render
from django.views.generic.base import TemplateView
from django.shortcuts import redirect


class IndexView(TemplateView):
    template_name = "upload.html"

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return super(TemplateView, self).dispatch(request, *args, **kwargs)
        else:
            return redirect('/login/')
